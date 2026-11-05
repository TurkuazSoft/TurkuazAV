// Dosya Yolu: REPO_ROOT/rust/src/scanner.rs
// Amac: Motor bagimsiz TurkuazAV Scanner orkestrasyon arayuzu
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: SHA-256 ve guvenilir YARA-X adaptorlerini ortak rapora baglar
// Bagimli Oldugu Katman: Service | Tool

use crate::{
    scan,
    threat::ThreatAssessment,
    trusted::{self, TrustedKeyring, TrustedScanPaths},
};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

/// Scanner is the product-level abstraction; YARA-X remains a vendor engine name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerId {
    Sha256,
    YaraX,
}

impl ScannerId {
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::YaraX => "YARA-X",
        }
    }
}

/// This report has no path and cannot authorize blocking or quarantine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerReport {
    pub scanner: ScannerId,
    pub assessment: ThreatAssessment,
}

/// @dev-id TAV-SCANNER-CORE-001
/// @purpose Keep scanner engines behind one small, read-only API.
/// @reason UI and future policy consumers must not depend on vendor CLI details.
/// @contract Implementations return evidence, not automatic malware verdicts.
pub trait ScannerBackend {
    fn id(&self) -> ScannerId;
    fn scan(&self, target: &Path, cancelled: &AtomicBool) -> Result<ThreatAssessment>;
}

/// Existing bounded SHA-256 scanner; hashing alone provides no threat verdict.
#[derive(Debug, Default)]
pub struct Sha256Scanner;

impl ScannerBackend for Sha256Scanner {
    fn id(&self) -> ScannerId {
        ScannerId::Sha256
    }

    fn scan(&self, target: &Path, cancelled: &AtomicBool) -> Result<ThreatAssessment> {
        Ok(ThreatAssessment::from_hash_scan(&scan::scan_file(
            target, cancelled,
        )))
    }
}

/// Uses the existing signed-rule and pinned-engine trust chain, not scan-rules.
pub struct TrustedYaraXScanner<'a> {
    pub rules_path: &'a Path,
    pub manifest: &'a Path,
    pub signature: &'a Path,
    pub engine: &'a Path,
    pub state_file: &'a Path,
    pub trusted_keys: &'a TrustedKeyring,
}

impl ScannerBackend for TrustedYaraXScanner<'_> {
    fn id(&self) -> ScannerId {
        ScannerId::YaraX
    }

    fn scan(&self, target: &Path, cancelled: &AtomicBool) -> Result<ThreatAssessment> {
        let result = trusted::scan_trusted_rules_with_cancel(
            TrustedScanPaths {
                target,
                rules_path: self.rules_path,
                manifest: self.manifest,
                signature: self.signature,
                engine: self.engine,
                state_file: self.state_file,
            },
            self.trusted_keys,
            cancelled,
        )?;
        Ok(ThreatAssessment::from_rule_scan(&result))
    }
}

/// @dev-id TAV-SCANNER-CORE-002
/// @purpose Preserve scanner attribution and fail closed on cancellation.
/// @reason Partial reports must never reach UI or response policy as completed scans.
/// @contract Existing scanning and signed-rule entry points remain unchanged.
pub fn scan_with(
    scanner: &dyn ScannerBackend,
    target: &Path,
    cancelled: &AtomicBool,
) -> Result<ScannerReport> {
    if cancelled.load(Ordering::Relaxed) {
        bail!("Scan cancelled");
    }
    let assessment = scanner.scan(target, cancelled)?;
    if cancelled.load(Ordering::Relaxed) {
        bail!("Scan cancelled");
    }
    Ok(ScannerReport {
        scanner: scanner.id(),
        assessment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat::{AnalysisCoverage, ThreatCategory, ThreatVerdict};
    use std::fs;

    #[test]
    fn hash_scanner_preserves_digest_without_safety_verdict() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("benign-fixture.txt");
        fs::write(&target, b"abc").unwrap();
        let result = scan_with(&Sha256Scanner, &target, &AtomicBool::new(false)).unwrap();
        assert_eq!(result.scanner, ScannerId::Sha256);
        assert_eq!(result.scanner.display_name(), "SHA-256");
        assert_eq!(result.assessment.coverage, AnalysisCoverage::Completed);
        assert_eq!(result.assessment.verdict, ThreatVerdict::NotEvaluated);
        assert_eq!(result.assessment.category, ThreatCategory::Unknown);
        assert_eq!(
            result.assessment.sha256.as_deref(),
            Some("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")
        );
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"sha256\""));
        assert!(!json.contains("benign-fixture.txt"));
        assert_eq!(serde_json::from_str::<ScannerReport>(&json).unwrap(), result);
    }

    #[test]
    fn missing_file_is_failed_not_a_clean_verdict() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("missing");
        let result = scan_with(&Sha256Scanner, &target, &AtomicBool::new(false)).unwrap();
        assert_eq!(result.assessment.coverage, AnalysisCoverage::Failed);
        assert_eq!(result.assessment.verdict, ThreatVerdict::NotEvaluated);
        assert!(result.assessment.sha256.is_none());
    }

    #[test]
    fn cancelled_requests_return_no_report() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("fixture");
        fs::write(&target, b"abc").unwrap();
        let cancelled = AtomicBool::new(true);
        assert!(scan_with(&Sha256Scanner, &target, &cancelled).is_err());
    }

    #[test]
    fn yara_x_identity_kept_and_untrusted_rules_not_executed() {
        let temp = tempfile::tempdir().unwrap();
        let ring = TrustedKeyring::from_pinned_pem(Vec::<(String, String)>::new()).unwrap();
        let scanner = TrustedYaraXScanner {
            rules_path: &temp.path().join("missing-rules"),
            manifest: &temp.path().join("missing-manifest"),
            signature: &temp.path().join("missing-signature"),
            engine: &temp.path().join("missing-engine"),
            state_file: &temp.path().join("version-state"),
            trusted_keys: &ring,
        };
        let target = temp.path().join("not-executed");
        assert_eq!(scanner.id(), ScannerId::YaraX);
        assert_eq!(scanner.id().display_name(), "YARA-X");
        let failure = scan_with(&scanner, &target, &AtomicBool::new(false));
        assert!(failure.is_err());
        assert!(!temp.path().join("version-state").exists());
    }
}
