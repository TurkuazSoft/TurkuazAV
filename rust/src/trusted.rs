// Dosya Yolu: REPO_ROOT/rust/src/trusted.rs
// Amac: Trusted manifest imza/publisher kontrolu ve anti-rollback
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: CSharp 0.2.4 imza payload ve 40-byte state formatini korur
// Bagimli Oldugu Katman: Service | Repo | Tool | Config

use crate::{
    config,
    rules::{self, RuleScanResult},
    scan::read_bounded,
};
use anyhow::{bail, Context, Result};
use fs2::FileExt;
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};
use subtle::ConstantTimeEq;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRuleManifest {
    pub schema: String,
    pub sequence: i64,
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "rulesSha256")]
    pub rules_sha256: String,
}

pub struct TrustedKeyring {
    keys: HashMap<String, String>,
}
impl TrustedKeyring {
    /// Keys MUST come from a separately trusted application bootstrap.
    pub fn from_pinned_pem(keys: impl IntoIterator<Item = (String, String)>) -> Result<Self> {
        let mut pinned = HashMap::new();
        for (id, pem) in keys {
            if !valid_key_id(&id) || pinned.contains_key(&id) {
                bail!("Invalid or duplicate publisher id");
            }
            let key = RsaPublicKey::from_public_key_pem(&pem).context("Bad publisher PEM")?;
            if key.n().bits() < 2048 {
                bail!("Publisher RSA key too weak");
            }
            pinned.insert(id, pem);
        }
        Ok(Self { keys: pinned })
    }
    fn key(&self, id: &str) -> Result<&str> {
        self.keys
            .get(id)
            .map(String::as_str)
            .context("Untrusted publisher")
    }
}

#[derive(Debug)]
pub struct VerifiedRulePackage {
    pub sequence: i64,
    pub publisher_key_id: String,
    pub verified_rules: Vec<u8>,
    pub manifest_fingerprint: [u8; 32],
}

fn valid_key_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_' || c == b'.'
        })
}
pub fn parse_manifest(json: &[u8]) -> Result<TrustedRuleManifest> {
    if json.is_empty() || json.len() > config::MAX_MANIFEST_BYTES {
        bail!("Malformed rule manifest");
    }
    let m: TrustedRuleManifest = serde_json::from_slice(json).context("Malformed rule manifest")?;
    if m.schema != config::PACKAGE_SCHEMA
        || m.sequence <= 0
        || !valid_key_id(&m.key_id)
        || m.rules_sha256.len() != 64
        || !m
            .rules_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("Malformed rule manifest");
    }
    Ok(m)
}
pub fn signature_payload(m: &TrustedRuleManifest) -> Vec<u8> {
    format!(
        "{}\n{}\n{}\n{}\n",
        config::SIGNATURE_DOMAIN,
        m.sequence,
        m.key_id,
        m.rules_sha256
    )
    .into_bytes()
}

pub fn verify_package(
    rules: &Path,
    manifest: &Path,
    signature: &Path,
    ring: &TrustedKeyring,
) -> Result<VerifiedRulePackage> {
    let rule_bytes = read_bounded(rules, config::MAX_RULE_BYTES)?;
    let manifest_bytes = read_bounded(manifest, config::MAX_MANIFEST_BYTES)?;
    let signature_bytes = read_bounded(signature, config::MAX_SIGNATURE_BYTES)?;
    let parsed = parse_manifest(&manifest_bytes)?;
    let pem = ring.key(&parsed.key_id)?;
    let payload = signature_payload(&parsed);
    rules::verify_signature(&payload, &signature_bytes, pem)?;
    let expected = hex::decode(&parsed.rules_sha256)?;
    let computed = Sha256::digest(&rule_bytes);
    if computed.as_slice().ct_eq(&expected).unwrap_u8() != 1 {
        bail!("Signed rules digest mismatch");
    }
    let fingerprint = Sha256::digest(&payload);
    Ok(VerifiedRulePackage {
        sequence: parsed.sequence,
        publisher_key_id: parsed.key_id,
        verified_rules: rule_bytes,
        manifest_fingerprint: fingerprint.into(),
    })
}

/// File must live in an access-controlled local service directory.
/// A separate stable .lock file serializes cooperating writers even when the
/// 40-byte state inode is atomically replaced. It is NOT a privileged-rollback
/// or hardware-root-of-trust defense.
pub fn accept_version(state_file: &Path, sequence: i64, fingerprint: &[u8; 32]) -> Result<()> {
    if sequence <= 0 {
        bail!("Invalid rule version");
    }
    let parent = state_file.parent().filter(|p| p.is_dir()).context(
        "Version state parent directory must already exist",
    )?;
    let filename = state_file.file_name().context("Invalid version state filename")?;
    let mut lock_name = filename.to_os_string();
    lock_name.push(".lock");
    let lock_path = parent.join(lock_name);

    // A symlink/reparse lock could redirect the writer out of the protected root.
    match std::fs::symlink_metadata(&lock_path) {
        Ok(meta) if crate::scan::is_reparse_or_symlink(&meta) || !meta.is_file() => {
            bail!("Invalid version lock path");
        }
        Ok(_) => (),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error).context("Cannot inspect version lock"),
    }
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .context("Cannot open protected version lock")?;
    lock_file
        .lock_exclusive()
        .context("Cannot lock protected version state")?;
    let result = (|| -> Result<()> {
        let old = match std::fs::symlink_metadata(state_file) {
            Ok(meta) => {
                if crate::scan::is_reparse_or_symlink(&meta) || !meta.is_file() {
                    bail!("Version state link or invalid file denied");
                }
                // An existing empty state is corruption, not a first install.
                if meta.len() != 40 {
                    bail!("Corrupt or legacy rule version state");
                }
                let bytes = std::fs::read(state_file).context("Cannot read version state")?;
                if bytes.len() != 40 {
                    bail!("Corrupt or legacy rule version state");
                }
                Some(bytes)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error).context("Cannot inspect version state"),
        };

        if let Some(saved) = old {
            let previous = i64::from_le_bytes(saved[..8].try_into()?);
            if previous <= 0 {
                bail!("Corrupt rule version state");
            }
            if sequence < previous {
                bail!("Rule downgrade denied");
            }
            if sequence == previous {
                if saved[8..].ct_eq(fingerprint).unwrap_u8() != 1 {
                    bail!("Rule version fingerprint conflict");
                }
                return Ok(());
            }
        }

        let mut next = [0u8; 40];
        next[..8].copy_from_slice(&sequence.to_le_bytes());
        next[8..].copy_from_slice(fingerprint);

        // Staging within the SAME directory keeps rename on one filesystem.
        // An interrupted staging write leaves the last committed state intact.
        let mut staged = tempfile::Builder::new()
            .prefix(".turkuazav-version-")
            .tempfile_in(parent)
            .context("Cannot stage version state")?;
        staged.as_file_mut().write_all(&next)?;
        staged.as_file_mut().sync_all()?;
        staged
            .persist(state_file)
            .context("Cannot atomically replace version state")?;
        #[cfg(unix)]
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("Cannot sync version state directory")?;
        Ok(())
    })();
    let _ = FileExt::unlock(&lock_file);
    result
}

/// Grouping paths keeps the cancellable API small without breaking
/// the existing v0.3.1 non-cancellable library entry point.
pub struct TrustedScanPaths<'a> {
    pub target: &'a Path,
    pub rules_path: &'a Path,
    pub manifest: &'a Path,
    pub signature: &'a Path,
    pub engine: &'a Path,
    pub state_file: &'a Path,
}

pub fn scan_trusted_rules(
    target: &Path,
    rules_path: &Path,
    manifest: &Path,
    signature: &Path,
    engine: &Path,
    state_file: &Path,
    ring: &TrustedKeyring,
) -> Result<RuleScanResult> {
    scan_trusted_rules_with_cancel(
        TrustedScanPaths {
            target,
            rules_path,
            manifest,
            signature,
            engine,
            state_file,
        },
        ring,
        &AtomicBool::new(false),
    )
}

pub fn scan_trusted_rules_with_cancel(
    paths: TrustedScanPaths<'_>,
    ring: &TrustedKeyring,
    cancelled: &AtomicBool,
) -> Result<RuleScanResult> {
    if cancelled.load(Ordering::Relaxed) {
        bail!("YARA-X scan cancelled");
    }
    let verified = verify_package(paths.rules_path, paths.manifest, paths.signature, ring)?;
    let result = rules::scan_verified_rules_with_cancel(
        paths.target,
        &verified.verified_rules,
        paths.engine,
        cancelled,
    )?;
    // Incomplete or cancelled scans must never advance anti-rollback state.
    if cancelled.load(Ordering::Relaxed) {
        bail!("YARA-X scan cancelled");
    }
    accept_version(
        paths.state_file,
        verified.sequence,
        &verified.manifest_fingerprint,
    )?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{
        pkcs8::EncodePublicKey,
        pss::SigningKey,
        rand_core::OsRng,
        signature::{RandomizedSigner, SignatureEncoding},
        RsaPrivateKey,
    };

    #[test]
    fn cancelled_trusted_scan_must_not_create_version_state() {
        let temp = tempfile::tempdir().unwrap();
        let invalid = temp.path().join("missing");
        let state = temp.path().join("state");
        let ring = TrustedKeyring::from_pinned_pem(Vec::<(String, String)>::new()).unwrap();
        let cancelled = AtomicBool::new(true);
        let result = scan_trusted_rules_with_cancel(
            TrustedScanPaths {
                target: &invalid,
                rules_path: &invalid,
                manifest: &invalid,
                signature: &invalid,
                engine: &invalid,
                state_file: &state,
            },
            &ring,
            &cancelled,
        );
        assert!(result.unwrap_err().to_string().contains("cancelled"));
        assert!(!state.exists());
    }

    #[test]
    fn canonical_and_strict_manifest() {
        let ok = br#"{"schema":"turkuazav.rule-package.v1","sequence":7,"keyId":"key-a","rulesSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        let m = parse_manifest(ok).unwrap();
        assert_eq!(String::from_utf8(signature_payload(&m)).unwrap(),
            "TurkuazAV.rule-package.v1\n7\nkey-a\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
        assert!(parse_manifest(br#"{"schema":"turkuazav.rule-package.v1","sequence":2,"sequence":3,"keyId":"a","rulesSha256":"aaaa"}"#).is_err());
        assert!(parse_manifest(br#"{"schema":"turkuazav.rule-package.v1","sequence":2,"keyId":"a","rulesSha256":"aaaa","extra":42}"#).is_err());
    }

    #[test]
    fn version_state_downgrade_conflict_and_legacy_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        let a = [1u8; 32];
        let b = [2u8; 32];
        accept_version(&state, 5, &a).unwrap();
        accept_version(&state, 5, &a).unwrap();
        assert!(accept_version(&state, 4, &a).is_err());
        assert!(accept_version(&state, 5, &b).is_err());
        accept_version(&state, 6, &b).unwrap();
        assert_eq!(std::fs::read(&state).unwrap().len(), 40);
        let legacy = tmp.path().join("old");
        std::fs::write(&legacy, [0u8; 8]).unwrap();
        assert!(accept_version(&legacy, 2, &a).is_err());
    }

    #[test]
    fn empty_existing_state_is_corruption_not_first_boot() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        std::fs::write(&state, []).unwrap();
        assert!(accept_version(&state, 1, &[1; 32]).is_err());
        assert!(std::fs::read(&state).unwrap().is_empty());
    }

    #[test]
    fn concurrent_writers_keep_exact_40_byte_contract() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("version");
        let threads: Vec<_> = (0..12)
            .map(|_| {
                let path = state.clone();
                std::thread::spawn(move || accept_version(&path, 9, &[4u8; 32]))
            })
            .collect();
        for worker in threads {
            worker.join().unwrap().unwrap();
        }
        let saved = std::fs::read(&state).unwrap();
        assert_eq!(saved.len(), 40);
        assert_eq!(i64::from_le_bytes(saved[..8].try_into().unwrap()), 9);
        assert_eq!(&saved[8..], &[4u8; 32]);
        assert!(state.with_file_name("version.lock").is_file());
        assert!(accept_version(&state, 8, &[4u8; 32]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn version_state_and_lock_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        std::fs::write(&outside, [0xAA; 40]).unwrap();
        let state = tmp.path().join("state");
        symlink(&outside, &state).unwrap();
        assert!(accept_version(&state, 1, &[1; 32]).is_err());
        std::fs::remove_file(&state).unwrap();
        symlink(&outside, tmp.path().join("state.lock")).unwrap();
        assert!(accept_version(&state, 1, &[1; 32]).is_err());
        assert_eq!(std::fs::read(outside).unwrap(), [0xAA; 40]);
    }

    #[test]
    fn stray_incomplete_staging_file_cannot_replace_valid_state() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        accept_version(&state, 11, &[1; 32]).unwrap();
        std::fs::write(tmp.path().join(".turkuazav-version-abandoned"), [9u8; 3]).unwrap();
        assert!(accept_version(&state, 10, &[1; 32]).is_err());
        assert_eq!(i64::from_le_bytes(std::fs::read(&state).unwrap()[..8].try_into().unwrap()), 11);
        accept_version(&state, 12, &[2; 32]).unwrap();
        assert_eq!(i64::from_le_bytes(std::fs::read(&state).unwrap()[..8].try_into().unwrap()), 12);
    }

    #[test]
    fn signed_package_tamper_and_unknown_key_rejected() {
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pem = private
            .to_public_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        let ring = TrustedKeyring::from_pinned_pem(vec![("trusted".into(), pem)]).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let rules = tmp.path().join("rules");
        let manifest = tmp.path().join("manifest");
        let signature = tmp.path().join("signature");
        let content = b"rule demo { condition: true }";
        std::fs::write(&rules, content).unwrap();
        let json = format!(
            r#"{{"schema":"{}","sequence":1,"keyId":"trusted","rulesSha256":"{}"}}"#,
            config::PACKAGE_SCHEMA,
            hex::encode(Sha256::digest(content))
        );
        let m = parse_manifest(json.as_bytes()).unwrap();
        let sig =
            SigningKey::<Sha256>::new(private).sign_with_rng(&mut rng, &signature_payload(&m));
        std::fs::write(&manifest, &json).unwrap();
        std::fs::write(&signature, sig.to_vec()).unwrap();
        assert_eq!(
            verify_package(&rules, &manifest, &signature, &ring)
                .unwrap()
                .sequence,
            1
        );
        std::fs::write(&rules, b"tampered").unwrap();
        assert!(verify_package(&rules, &manifest, &signature, &ring).is_err());
        let unknown = TrustedKeyring::from_pinned_pem(Vec::<(String, String)>::new()).unwrap();
        assert!(verify_package(&rules, &manifest, &signature, &unknown).is_err());
    }
}
