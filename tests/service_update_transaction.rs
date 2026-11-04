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
    assert!(!f
        .temp
        .path()
        .join(".turkuazav-service-update.pending")
        .exists());
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
    assert!(!f
        .temp
        .path()
        .join(".turkuazav-service-update.pending")
        .exists());
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
    assert!(f
        .temp
        .path()
        .join(".turkuazav-service-update.pending")
        .exists());
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
    assert!(f
        .temp
        .path()
        .join(".turkuazav-service-update.pending")
        .exists());
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
    assert!(!f
        .temp
        .path()
        .join(".turkuazav-service-update.pending")
        .exists());
    assert!(!f.state.exists());
}

#[test]
fn pending_inspection_is_read_only_and_rejects_unresolved_reentry() {
    let f = Fixture::new();
    assert_eq!(
        turkuazav::inspect_pending_service_update(f.temp.path(), &f.state).unwrap(),
        turkuazav::PendingUpdateInspection::NoPending
    );
    let mut adapter = FakeAdapter::new(&f.old);
    adapter.fail_health = true;
    adapter.fail_restore = true;
    assert!(f.run(&mut adapter).is_err());
    let marker = f.temp.path().join(".turkuazav-service-update.pending");
    let before = fs::read(&marker).unwrap();

    assert_eq!(
        turkuazav::inspect_pending_service_update(f.temp.path(), &f.state).unwrap(),
        turkuazav::PendingUpdateInspection::NeedsManualReview {
            sequence: 7,
            version_record_matches_marker: false,
            candidate_integrity: turkuazav::PendingCandidateInspection::MatchesRecordedDigest,
        }
    );
    assert_eq!(fs::read(&marker).unwrap(), before);
    assert!(!f.state.exists());
    assert!(f.run(&mut adapter).is_err());
    assert_eq!(adapter.activated, 1);
}

#[test]
fn accepted_record_match_still_requires_manual_reconciliation() {
    let f = Fixture::new();
    let mut adapter = FakeAdapter::new(&f.old);
    adapter.fail_restore = true;
    adapter.fail_health = true;
    assert!(f.run(&mut adapter).is_err());
    turkuazav::accept_version(
        &f.state,
        f.verified.sequence(),
        f.verified.manifest_fingerprint(),
    )
    .unwrap();
    let saved = fs::read(&f.state).unwrap();
    assert_eq!(
        turkuazav::inspect_pending_service_update(f.temp.path(), &f.state).unwrap(),
        turkuazav::PendingUpdateInspection::NeedsManualReview {
            sequence: 7,
            version_record_matches_marker: true,
            candidate_integrity: turkuazav::PendingCandidateInspection::MatchesRecordedDigest,
        }
    );
    assert!(f.run(&mut adapter).is_err());
    assert_eq!(adapter.activated, 1);
    assert_eq!(fs::read(&f.state).unwrap(), saved);
}

#[test]
fn pending_inspection_rejects_invalid_schema_paths_and_links() {
    let f = Fixture::new();
    let marker = f.temp.path().join(".turkuazav-service-update.pending");
    fs::write(&marker, b"invalid json").unwrap();
    assert!(turkuazav::inspect_pending_service_update(f.temp.path(), &f.state).is_err());
    let valid = serde_json::json!({
        "schema": "turkuazav.service-update-pending.v1",
        "sequence": 7,
        "manifestSha256": hex::encode(f.verified.manifest_fingerprint()),
        "previousBinary": f.old.to_string_lossy(),
        "candidateBinary": f.temp.path().join(if cfg!(windows) { "turkuazav-service-seq-7.exe" } else { "turkuazav-service-seq-7" }).to_string_lossy(),
    });
    let mut bad_path = valid.clone();
    bad_path["candidateBinary"] = serde_json::json!("../relative");
    fs::write(&marker, bad_path.to_string()).unwrap();
    assert!(turkuazav::inspect_pending_service_update(f.temp.path(), &f.state).is_err());
    let mut bad_schema = valid.clone();
    bad_schema["extraField"] = serde_json::json!(true);
    fs::write(&marker, bad_schema.to_string()).unwrap();
    assert!(turkuazav::inspect_pending_service_update(f.temp.path(), &f.state).is_err());
    fs::write(&marker, valid.to_string()).unwrap();
    assert!(matches!(
        turkuazav::inspect_pending_service_update(f.temp.path(), &f.state).unwrap(),
        turkuazav::PendingUpdateInspection::NeedsManualReview { .. }
    ));
    fs::write(&marker, vec![b'X'; 8193]).unwrap();
    assert!(turkuazav::inspect_pending_service_update(f.temp.path(), &f.state).is_err());

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        fs::remove_file(&marker).unwrap();
        symlink(&f.old, &marker).unwrap();
        assert!(turkuazav::inspect_pending_service_update(f.temp.path(), &f.state).is_err());
    }
}

#[test]
fn reserved_update_state_paths_fail_before_activation() {
    let f = Fixture::new();
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    let disallowed = [
        ".turkuazav-service-update.pending".to_string(),
        ".turkuazav-service-update.txn.lock".to_string(),
        ".turkuazav-service-update.txn".to_string(),
        ".turkuazav-update-remainder".to_string(),
        format!("turkuazav-service-seq-7{suffix}"),
        format!("turkuazav-service-seq-8{suffix}"),
    ];
    for name in disallowed {
        let mut adapter = FakeAdapter::new(&f.old);
        let forbidden = f.temp.path().join(name);
        assert!(
            apply_verified_service_update(f.temp.path(), &forbidden, &f.verified, &mut adapter,)
                .is_err(),
            "Reserved or colliding state path must be rejected"
        );
        assert_eq!(adapter.activated, 0);
        assert_eq!(adapter.restored, 0);
        assert_eq!(adapter.active, f.old);
        assert!(!f
            .temp
            .path()
            .join(format!("turkuazav-service-seq-7{suffix}"))
            .exists());
    }
    assert!(!f.state.exists());
}

#[test]
fn traversal_state_paths_fail_without_service_switch() {
    let f = Fixture::new();
    let mut adapter = FakeAdapter::new(&f.old);
    let traversing = f
        .temp
        .path()
        .join("subdir")
        .join("..")
        .join("version-state");
    assert!(
        apply_verified_service_update(f.temp.path(), &traversing, &f.verified, &mut adapter,)
            .is_err()
    );
    assert_eq!(adapter.activated, 0);
    assert_eq!(adapter.restored, 0);
    assert!(!f.state.exists());
}

#[test]
fn interrupted_v2_candidate_integrity_detects_tampering_and_missing_files() {
    let f = Fixture::new();
    let mut adapter = FakeAdapter::new(&f.old);
    adapter.fail_health = true;
    adapter.fail_restore = true;
    assert!(f.run(&mut adapter).is_err());
    let inspect = || turkuazav::inspect_pending_service_update(f.temp.path(), &f.state);
    assert_eq!(
        inspect().unwrap(),
        turkuazav::PendingUpdateInspection::NeedsManualReview {
            sequence: 7,
            version_record_matches_marker: false,
            candidate_integrity: turkuazav::PendingCandidateInspection::MatchesRecordedDigest,
        }
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&adapter.active, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(&adapter.active, b"modified candidate bytes").unwrap();
    assert_eq!(
        inspect().unwrap(),
        turkuazav::PendingUpdateInspection::NeedsManualReview {
            sequence: 7,
            version_record_matches_marker: false,
            candidate_integrity: turkuazav::PendingCandidateInspection::DiffersFromRecordedDigest,
        }
    );
    fs::remove_file(&adapter.active).unwrap();
    assert_eq!(
        inspect().unwrap(),
        turkuazav::PendingUpdateInspection::NeedsManualReview {
            sequence: 7,
            version_record_matches_marker: false,
            candidate_integrity: turkuazav::PendingCandidateInspection::Missing,
        }
    );
    assert!(f.run(&mut adapter).is_err(), "Pending latch stays set");
    assert_eq!(adapter.activated, 1);
    assert!(!f.state.exists());
}

#[test]
fn legacy_v1_pending_record_reports_no_candidate_digest() {
    let f = Fixture::new();
    let marker = f.temp.path().join(".turkuazav-service-update.pending");
    let candidate = f.temp.path().join(if cfg!(windows) {
        "turkuazav-service-seq-7.exe"
    } else {
        "turkuazav-service-seq-7"
    });
    let record = serde_json::json!({
        "schema": "turkuazav.service-update-pending.v1",
        "sequence": 7,
        "manifestSha256": hex::encode(f.verified.manifest_fingerprint()),
        "previousBinary": f.old.to_string_lossy(),
        "candidateBinary": candidate.to_string_lossy(),
    });
    fs::write(&marker, record.to_string()).unwrap();
    assert_eq!(
        turkuazav::inspect_pending_service_update(f.temp.path(), &f.state).unwrap(),
        turkuazav::PendingUpdateInspection::NeedsManualReview {
            sequence: 7,
            version_record_matches_marker: false,
            candidate_integrity: turkuazav::PendingCandidateInspection::LegacyRecordWithoutDigest,
        }
    );
    assert_eq!(
        fs::read(&marker).unwrap(),
        record.to_string().as_bytes()
    );
}

#[test]
fn pending_v2_requires_digest_size_and_rejects_linked_candidate() {
    let f = Fixture::new();
    let marker = f.temp.path().join(".turkuazav-service-update.pending");
    let candidate = f.temp.path().join(if cfg!(windows) {
        "turkuazav-service-seq-7.exe"
    } else {
        "turkuazav-service-seq-7"
    });
    let mut record = serde_json::json!({
        "schema": "turkuazav.service-update-pending.v2",
        "sequence": 7,
        "manifestSha256": hex::encode(f.verified.manifest_fingerprint()),
        "previousBinary": f.old.to_string_lossy(),
        "candidateBinary": candidate.to_string_lossy(),
        "candidateSize": 20,
        "candidateSha256": hex::encode(Sha256::digest(b"trusted update bytes")),
    });
    record.as_object_mut().unwrap().remove("candidateSha256");
    fs::write(&marker, record.to_string()).unwrap();
    assert!(turkuazav::inspect_pending_service_update(f.temp.path(), &f.state).is_err());
    record["candidateSha256"] =
        serde_json::json!(hex::encode(Sha256::digest(b"trusted update bytes")));
    record["candidateSize"] = serde_json::json!(0);
    fs::write(&marker, record.to_string()).unwrap();
    assert!(turkuazav::inspect_pending_service_update(f.temp.path(), &f.state).is_err());

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        record["candidateSize"] = serde_json::json!(20);
        fs::write(&marker, record.to_string()).unwrap();
        symlink(&f.old, &candidate).unwrap();
        assert!(turkuazav::inspect_pending_service_update(f.temp.path(), &f.state).is_err());
    }
}

#[test]
fn current_service_binary_cannot_be_used_as_version_state() {
    let f = Fixture::new();
    turkuazav::accept_version(&f.state, 1, &[0x11; 32]).unwrap();
    let before = fs::read(&f.state).unwrap();
    let mut adapter = FakeAdapter::new(&f.state);
    let error = f.run(&mut adapter).unwrap_err();
    assert!(error.to_string().contains("existing service executable"));
    assert_eq!(adapter.activated, 0);
    assert_eq!(adapter.restored, 0);
    assert_eq!(fs::read(&f.state).unwrap(), before);
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    assert!(!f
        .temp
        .path()
        .join(format!("turkuazav-service-seq-7{suffix}"))
        .exists());
}
