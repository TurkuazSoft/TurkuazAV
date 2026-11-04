// Dosya Yolu: REPO_ROOT/tests/service_update_transaction.rs
// Amac: Servis update orkestrasyonunda stage/health/rollback/state regresyonu
// Modul - FileType: Tests - Rust
// Version: 0.3.1
// Aciklama: Gercek RSA imzasi, kotu adaptor, concurrency, tamper ve rollback
// Bagimli Oldugu Katman: Service | Tool | Config

use anyhow::{bail, ensure, Result};
use rsa::{
    pkcs8::EncodePublicKey,
    pss::SigningKey,
    rand_core::OsRng,
    signature::{RandomizedSigner, SignatureEncoding},
    RsaPrivateKey,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
use turkuazav::{
    apply_verified_service_update,
    update::{
        parse_service_update_manifest, service_update_signature_payload, SERVICE_UPDATE_SCHEMA,
    },
    update_transaction::ServiceActivation,
    verify_service_update, TrustedKeyring, VerifiedServiceUpdate,
};

struct Fixture {
    temp: tempfile::TempDir,
    old: PathBuf,
    state: PathBuf,
    verified: VerifiedServiceUpdate,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let old = temp.path().join("previous-service");
        let state = temp.path().join("service-update-state");
        fs::write(&old, b"previous binary").unwrap();
        let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pem = key
            .to_public_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        let ring = TrustedKeyring::from_pinned_pem(vec![("update-publisher".into(), pem)]).unwrap();
        let binary = temp.path().join("update-source");
        let manifest = temp.path().join("manifest.json");
        let signature = temp.path().join("signature");
        fs::write(&binary, b"trusted update bytes").unwrap();
        let json = serde_json::json!({
            "schema": SERVICE_UPDATE_SCHEMA,
            "sequence": 7,
            "keyId": "update-publisher",
            "version": "0.3.1",
            "targetOs": if cfg!(windows) { "windows" } else { "linux" },
            "targetArch": "x86_64",
            "binarySize": 20,
            "binarySha256": hex::encode(Sha256::digest(b"trusted update bytes")),
        })
        .to_string();
        let parsed = parse_service_update_manifest(json.as_bytes()).unwrap();
        let signed = SigningKey::<Sha256>::new(key)
            .sign_with_rng(&mut OsRng, &service_update_signature_payload(&parsed))
            .to_vec();
        fs::write(&manifest, json).unwrap();
        fs::write(&signature, signed).unwrap();
        let verified =
            verify_service_update(&binary, &manifest, &signature, &ring, &state).unwrap();
        // Mutate the untrusted source after verification; the orchestrator
        // must only stage the signed in-memory snapshot.
        fs::write(binary, b"replaced untrusted source").unwrap();
        Self {
            temp,
            old,
            state,
            verified,
        }
    }

    fn run(&self, adapter: &mut FakeAdapter) -> Result<turkuazav::CommittedServiceUpdate> {
        apply_verified_service_update(self.temp.path(), &self.state, &self.verified, adapter)
    }
}

#[derive(Default)]
struct FakeAdapter {
    original: PathBuf,
    active: PathBuf,
    fail_activate: bool,
    fail_health: bool,
    fail_restore: bool,
    conflict_state: Option<PathBuf>,
    activated: usize,
    restored: usize,
}

impl FakeAdapter {
    fn new(original: &Path) -> Self {
        Self {
            original: original.to_owned(),
            active: original.to_owned(),
            ..Self::default()
        }
    }
}

impl ServiceActivation for FakeAdapter {
    fn current_binary(&mut self) -> Result<PathBuf> {
        Ok(self.active.clone())
    }

    fn activate(&mut self, staged: &Path) -> Result<()> {
        self.activated += 1;
        self.active = staged.to_owned();
        if self.fail_activate {
            bail!("Simulated activation failure");
        }
        Ok(())
    }

    fn check_health(&mut self, staged: &Path) -> Result<()> {
        ensure!(self.active == staged, "Unexpected staged executable");
        ensure!(
            fs::read(staged)? == b"trusted update bytes",
            "Staged bytes changed"
        );
        if let Some(path) = &self.conflict_state {
            // Competing updater: higher accepted sequence means that blindly
            // rolling back could violate a newly committed trust boundary.
            turkuazav::accept_version(path, 8, &[0x77; 32])?;
        }
        if self.fail_health {
            bail!("Simulated health failure");
        }
        Ok(())
    }

    fn restore(&mut self, previous: &Path) -> Result<()> {
        self.restored += 1;
        if self.fail_restore {
            bail!("Simulated restore failure");
        }
        ensure!(previous == self.original, "Rollback target changed");
        self.active = previous.to_owned();
        Ok(())
    }
}

#[test]
fn healthy_staged_snapshot_is_committed_only_after_acceptance() {
    let f = Fixture::new();
    let mut adapter = FakeAdapter::new(&f.old);
    let result = f.run(&mut adapter).unwrap();
    assert_eq!(result.sequence, 7);
    assert_eq!(result.version, "0.3.1");
    assert_eq!(
        fs::read(&result.installed_binary).unwrap(),
        b"trusted update bytes"
    );
    assert_eq!(adapter.active, result.installed_binary);
    assert_eq!(adapter.activated, 1);
    assert_eq!(adapter.restored, 0);
    assert!(!f.temp.path().join(".turkuazav-service-update.pending").exists());
    let saved = fs::read(&f.state).unwrap();
    assert_eq!(saved.len(), 40);
    assert_eq!(i64::from_le_bytes(saved[..8].try_into().unwrap()), 7);
    assert!(f.run(&mut adapter).is_err(), "Replay must not reactivate");
    assert_eq!(adapter.activated, 1);
}

#[test]
fn failed_activation_restores_old_binary_and_preserves_state() {
    let f = Fixture::new();
    let mut adapter = FakeAdapter::new(&f.old);
    adapter.fail_activate = true;
    assert!(f.run(&mut adapter).is_err());
    assert_eq!(adapter.active, f.old);
    assert_eq!(adapter.restored, 1);
    assert!(!f.state.exists());
    assert!(!f.temp.path().join(".turkuazav-service-update.pending").exists());
    assert_eq!(
        fs::read_dir(f.temp.path())
            .unwrap()
            .filter_map(|v| v.ok())
            .filter(|v| v
                .file_name()
                .to_string_lossy()
                .starts_with("turkuazav-service-seq-"))
            .count(),
        0
    );
}

#[test]
fn failed_health_restores_old_binary_and_preserves_state() {
    let f = Fixture::new();
    let mut adapter = FakeAdapter::new(&f.old);
    adapter.fail_health = true;
    assert!(f.run(&mut adapter).is_err());
    assert_eq!(adapter.active, f.old);
    assert_eq!(adapter.restored, 1);
    assert!(!f.state.exists());
}

#[test]
fn failed_restore_keeps_candidate_for_manual_recovery() {
    let f = Fixture::new();
    let mut adapter = FakeAdapter::new(&f.old);
    adapter.fail_health = true;
    adapter.fail_restore = true;
    let err = f.run(&mut adapter).unwrap_err();
    assert!(err.to_string().contains("manual recovery"));
    assert!(!f.state.exists());
    assert!(
        adapter.active.exists(),
        "Unrecovered candidate must remain available"
    );
    assert!(f.temp.path().join(".turkuazav-service-update.pending").exists());
}

#[test]
fn version_commit_conflict_does_not_trigger_unsafe_downgrade() {
    let f = Fixture::new();
    let mut adapter = FakeAdapter::new(&f.old);
    adapter.conflict_state = Some(f.state.clone());
    let err = f.run(&mut adapter).unwrap_err();
    assert!(err.to_string().contains("manual recovery"));
    assert_eq!(adapter.restored, 0);
    assert_ne!(adapter.active, f.old);
    assert!(f.temp.path().join(".turkuazav-service-update.pending").exists());
    let saved = fs::read(&f.state).unwrap();
    assert_eq!(i64::from_le_bytes(saved[..8].try_into().unwrap()), 8);
}

#[test]
fn redirected_root_and_invalid_state_location_are_rejected() {
    let f = Fixture::new();
    let mut adapter = FakeAdapter::new(&f.old);
    let outside = tempfile::tempdir().unwrap();
    assert!(apply_verified_service_update(
        f.temp.path(),
        &outside.path().join("state"),
        &f.verified,
        &mut adapter
    )
    .is_err());
    assert_eq!(adapter.activated, 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let link = outside.path().join("linked");
        symlink(f.temp.path(), &link).unwrap();
        assert!(apply_verified_service_update(
            &link,
            &link.join("state"),
            &f.verified,
            &mut adapter
        )
        .is_err());
        assert_eq!(adapter.activated, 0);
    }
}

#[test]
fn existing_staging_collision_fails_closed() {
    let f = Fixture::new();
    let mut adapter = FakeAdapter::new(&f.old);
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    let collision = f
        .temp
        .path()
        .join(format!("turkuazav-service-seq-7{suffix}"));
    fs::write(&collision, b"another candidate").unwrap();
    assert!(f.run(&mut adapter).is_err());
    assert_eq!(fs::read(&collision).unwrap(), b"another candidate");
    assert_eq!(adapter.activated, 0);
    assert!(!f.state.exists());
}

#[test]
fn unresolved_pending_marker_blocks_reentry_without_touching_service() {
    let f = Fixture::new();
    let pending = f.temp.path().join(".turkuazav-service-update.pending");
    fs::write(&pending, b"interrupted prior attempt").unwrap();
    let mut adapter = FakeAdapter::new(&f.old);
    let err = f.run(&mut adapter).unwrap_err();
    assert!(err.to_string().contains("manual recovery"));
    assert_eq!(adapter.activated, 0);
    assert_eq!(adapter.restored, 0);
    assert_eq!(adapter.active, f.old);
    assert_eq!(fs::read(&pending).unwrap(), b"interrupted prior attempt");
    assert!(!f.state.exists());
}

#[test]
fn failure_to_activate_clears_pending_marker_only_after_restore() {
    let f = Fixture::new();
    let mut adapter = FakeAdapter::new(&f.old);
    adapter.fail_health = true;
    assert!(f.run(&mut adapter).is_err());
    assert_eq!(adapter.active, f.old);
    assert!(!f.temp.path().join(".turkuazav-service-update.pending").exists());
    assert!(!f.state.exists());
}
