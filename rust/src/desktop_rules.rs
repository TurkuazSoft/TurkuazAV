// Dosya Yolu: REPO_ROOT/rust/src/desktop_rules.rs
// Amac: Masaustu arayuzunde yalnizca guvenilir YARA-X paketlerini calistir
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: Sabit publisher guveni ile Scanner raporu arasindaki erisim kapisi
// Bagimli Oldugu Katman: Service | Tool | Config

use crate::{scan_with, ScannerReport, TrustedKeyring, TrustedYaraXScanner};
use anyhow::{bail, ensure, Result};
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

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
    fn caller_supplied_invalid_publisher_is_not_a_bootstrap() {
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
}
