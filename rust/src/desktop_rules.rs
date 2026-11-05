// Dosya Yolu: REPO_ROOT/rust/src/desktop_rules.rs
// Amac: Masaustu icin imzali YARA-X on denetimi ve guvenilir tarama
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: Sabit publisher kokleri, imza/motor dogrulamasi ve read-only state kontrolu
// Bagimli Oldugu Katman: Service | Tool | Config

use crate::{
    config, rules, scan, scan_with, trusted, ScannerReport, TrustedKeyring, TrustedYaraXScanner,
};
use anyhow::{bail, ensure, Context, Result};
use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};
use subtle::ConstantTimeEq;

/// Advisory validation only. No file path, signing material or unverified
/// user metadata is returned to the GUI. The real scan rechecks everything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopRulePreflight {
    pub publisher_key_id: String,
    pub sequence: i64,
}

/// @dev-id TAV-DESKTOP-TRUST-010
/// @purpose Keep trusted publisher roots separate from rule-package metadata.
/// @contract Only the application bootstrap may supply publisher PEM strings.
/// Rule files, the manifest, a CLI argument or an environment variable must
/// NEVER be interpreted as a trust root. A missing bootstrap is disabled.
pub struct DesktopTrustedRules {
    rules_path: PathBuf,
    manifest: PathBuf,
    signature: PathBuf,
    engine: PathBuf,
    state_file: PathBuf,
    keys: TrustedKeyring,
}

/// Advisory snapshot, not an authorization or a substitute for the locked
/// atomic anti-rollback check performed after a successful trusted scan.
fn inspect_version_snapshot(
    state_file: &Path,
    sequence: i64,
    expected_fingerprint: &[u8; 32],
) -> Result<()> {
    let metadata = match fs::symlink_metadata(state_file) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("Cannot inspect rule version state"),
    };
    ensure!(
        metadata.is_file() && !scan::is_reparse_or_symlink(&metadata) && metadata.len() == 40,
        "Invalid rule version state"
    );
    let bytes = fs::read(state_file).context("Cannot read rule version state")?;
    ensure!(bytes.len() == 40, "Invalid rule version state length");
    let previous = i64::from_le_bytes(bytes[..8].try_into()?);
    ensure!(previous > 0, "Invalid rule version sequence");
    ensure!(sequence >= previous, "Signed rule downgrade denied");
    if sequence == previous {
        ensure!(
            bytes[8..].ct_eq(expected_fingerprint).unwrap_u8() == 1,
            "Signed rule version fingerprint conflict"
        );
    }
    Ok(())
}

impl DesktopTrustedRules {
    /// Pin provenance is the caller's responsibility: supply only publisher
    /// roots independently provisioned as part of the trusted application.
    /// Empty roots are rejected rather than silently allowing user keys.
    pub fn from_trusted_bootstrap(
        pinned_publishers: &[(&str, &str)],
        rules_directory: &Path,
        engine: &Path,
        state_file: &Path,
    ) -> Result<Self> {
        if pinned_publishers.is_empty() {
            bail!("No trusted desktop publisher is provisioned");
        }
        ensure!(
            rules_directory.is_absolute() && engine.is_absolute() && state_file.is_absolute(),
            "Trusted rule configuration requires absolute paths"
        );
        let keys = TrustedKeyring::from_pinned_pem(
            pinned_publishers
                .iter()
                .map(|(id, pem)| ((*id).to_owned(), (*pem).to_owned())),
        )?;
        Ok(Self {
            rules_path: rules_directory.join("rules.yar"),
            manifest: rules_directory.join("manifest.json"),
            signature: rules_directory.join("rules.sig"),
            engine: engine.to_path_buf(),
            state_file: state_file.to_path_buf(),
            keys,
        })
    }

    /// @dev-id TAV-DESKTOP-TRUST-012
    /// @purpose Inspect a signed local rule bundle before enabling desktop UI.
    /// @contract No engine process, trusted state write, automatic download,
    /// untrusted root admission or malware verdict. Only a preflight hint:
    /// the trusted scan will recheck signatures, engine and rollback state.
    pub fn preflight(&self) -> Result<DesktopRulePreflight> {
        let root = self
            .rules_path
            .parent()
            .context("Missing trusted rules directory")?;
        let root_meta = fs::symlink_metadata(root).context("Trusted rules directory missing")?;
        ensure!(
            root_meta.is_dir() && !scan::is_reparse_or_symlink(&root_meta),
            "Trusted rules directory must be a normal directory"
        );
        let parent = self
            .state_file
            .parent()
            .context("Missing rule state parent")?;
        let state_parent_meta =
            fs::symlink_metadata(parent).context("Rule state parent directory missing")?;
        ensure!(
            state_parent_meta.is_dir() && !scan::is_reparse_or_symlink(&state_parent_meta),
            "Rule state parent must be a normal directory"
        );
        ensure!(
            self.state_file != self.rules_path
                && self.state_file != self.manifest
                && self.state_file != self.signature
                && self.state_file != self.engine,
            "Rule state must not overlap scan inputs"
        );
        let verified = trusted::verify_package(
            &self.rules_path,
            &self.manifest,
            &self.signature,
            &self.keys,
        )?;
        let engine_meta =
            fs::symlink_metadata(&self.engine).context("YARA-X engine metadata missing")?;
        ensure!(
            engine_meta.len() <= config::MAX_ENGINE_BYTES,
            "YARA-X engine size limit exceeded"
        );
        rules::verify_engine(&self.engine)?;
        inspect_version_snapshot(
            &self.state_file,
            verified.sequence,
            &verified.manifest_fingerprint,
        )?;
        Ok(DesktopRulePreflight {
            publisher_key_id: verified.publisher_key_id,
            sequence: verified.sequence,
        })
    }

    /// @dev-id TAV-DESKTOP-TRUST-011
    /// @purpose Reuse the existing signature/pinned-engine/anti-rollback chain.
    /// @contract No developer-only unsigned rule API, file deletion or blocking.
    /// Cancellation and any trust failure return an error instead of a verdict.
    pub fn scan(&self, target: &Path, cancelled: &AtomicBool) -> Result<ScannerReport> {
        ensure!(target.is_absolute(), "Rule scan target must be absolute");
        let scanner = TrustedYaraXScanner {
            rules_path: &self.rules_path,
            manifest: &self.manifest,
            signature: &self.signature,
            engine: &self.engine,
            state_file: &self.state_file,
            trusted_keys: &self.keys,
        };
        scan_with(&scanner, target, cancelled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_publisher_root_never_enables_desktop_rules() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let result = DesktopTrustedRules::from_trusted_bootstrap(
            &[],
            root,
            &root.join("yr"),
            &root.join("state"),
        );
        assert!(result.is_err());
        assert!(!root.join("state").exists());
    }

    #[test]
    fn invalid_publisher_is_not_a_bootstrap() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        assert!(DesktopTrustedRules::from_trusted_bootstrap(
            &[("publisher", "not-a-valid-rsa-public-key")],
            root,
            &root.join("yr"),
            &root.join("state"),
        )
        .is_err());
        assert!(!root.join("state").exists());
    }

    #[test]
    fn snapshot_denies_downgrade_conflict_and_corrupt_state_without_writing() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        let one = [1u8; 32];
        let two = [2u8; 32];
        inspect_version_snapshot(&state, 1, &one).unwrap();
        assert!(!state.exists());
        let mut bytes = [0u8; 40];
        bytes[..8].copy_from_slice(&5_i64.to_le_bytes());
        bytes[8..].copy_from_slice(&one);
        fs::write(&state, bytes).unwrap();
        let before = fs::read(&state).unwrap();
        inspect_version_snapshot(&state, 5, &one).unwrap();
        inspect_version_snapshot(&state, 6, &two).unwrap();
        assert!(inspect_version_snapshot(&state, 4, &one).is_err());
        assert!(inspect_version_snapshot(&state, 5, &two).is_err());
        assert_eq!(fs::read(&state).unwrap(), before);
        fs::write(&state, [0u8; 8]).unwrap();
        assert!(inspect_version_snapshot(&state, 8, &two).is_err());
        assert_eq!(fs::metadata(&state).unwrap().len(), 8);
    }

    #[cfg(unix)]
    #[test]
    fn linked_version_state_is_rejected() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        fs::write(&real, [1u8; 40]).unwrap();
        let link = temp.path().join("state");
        symlink(&real, &link).unwrap();
        assert!(inspect_version_snapshot(&link, 10, &[1u8; 32]).is_err());
        assert_eq!(fs::read(&real).unwrap(), [1u8; 40]);
    }
}
