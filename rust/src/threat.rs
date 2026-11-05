// Dosya Yolu: REPO_ROOT/rust/src/threat.rs
// Amac: Hash ve YARA-X sonuclarini yanlis malware hukmu uretmeden raporla
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: Tehdit turu, inceleme durumu, kanit ve tarama kapsami sozlesmesi
// Bagimli Oldugu Katman: Service

use crate::{
    rules::RuleScanResult,
    scan::{FileScanResult, ScanStatus},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const MAX_RULE_EVIDENCE: usize = 32;

/// Kategori, tehdit ailesi veya dogrulanmis malware hukmu degildir.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCategory {
    Unknown,
    Virus,
    Trojan,
    Worm,
    Ransomware,
    Spyware,
    Rootkit,
    Backdoor,
    Adware,
    PotentiallyUnwanted,
}

/// Taramanin teknik sonucu ile tehdit hukmu birbirinden ayridir.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisCoverage {
    Completed,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatVerdict {
    /// Hash sonucu veya bos kural listesi malware temizligi kanitlamaz.
    NotEvaluated,
    /// YARA kural eslesmesi bagimsiz inceleme gerektirir, engelleme degildir.
    RequiresReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    YaraRule,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatEvidence {
    pub evidence_type: EvidenceType,
    pub identifier: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatAssessment {
    pub coverage: AnalysisCoverage,
    pub verdict: ThreatVerdict,
    pub category: ThreatCategory,
    pub sha256: Option<String>,
    pub evidence: Vec<ThreatEvidence>,
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|character| character.is_ascii_hexdigit())
}

impl ThreatAssessment {
    /// @dev-id TAV-THREAT-MODEL-001
    /// @purpose Disassociate successful SHA-256 hashing from malware detection.
    /// @reason A completed hash-only scan must never generate a clean verdict.
    /// @contract Skips/failures never expose a digest or evidence.
    pub fn from_hash_scan(scan: &FileScanResult) -> Self {
        let (coverage, sha256) = match (&scan.status, scan.sha256.as_deref()) {
            (ScanStatus::Hashed, Some(digest)) if is_sha256(digest) => {
                (AnalysisCoverage::Completed, Some(digest.to_owned()))
            }
            (ScanStatus::Hashed, _) => (AnalysisCoverage::Failed, None),
            (ScanStatus::Skipped, _) => (AnalysisCoverage::Skipped, None),
            (ScanStatus::Failed, _) => (AnalysisCoverage::Failed, None),
        };
        Self {
            coverage,
            verdict: ThreatVerdict::NotEvaluated,
            category: ThreatCategory::Unknown,
            sha256,
            evidence: Vec::new(),
        }
    }

    /// @dev-id TAV-THREAT-MODEL-002
    /// @purpose Turn YARA-X rule matches into bounded review evidence only.
    /// @reason Rule names are not proof of a malware family or authorization to block.
    /// @contract This adapter has no external network, filesystem or policy side effects.
    pub fn from_rule_scan(scan: &RuleScanResult) -> Self {
        let evidence: Vec<_> = scan
            .rule_identifiers
            .iter()
            .map(String::as_str)
            .filter(|identifier| !identifier.trim().is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(MAX_RULE_EVIDENCE)
            .map(|identifier| ThreatEvidence {
                evidence_type: EvidenceType::YaraRule,
                identifier: identifier.to_owned(),
            })
            .collect();

        let verdict = if evidence.is_empty() {
            ThreatVerdict::NotEvaluated
        } else {
            ThreatVerdict::RequiresReview
        };

        Self {
            coverage: AnalysisCoverage::Completed,
            verdict,
            category: ThreatCategory::Unknown,
            sha256: None,
            evidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn hash_scan(status: ScanStatus, digest: Option<&str>) -> FileScanResult {
        FileScanResult {
            path: PathBuf::from("local-test-file"),
            status,
            sha256: digest.map(str::to_owned),
            size_bytes: Some(3),
            details: None,
        }
    }

    #[test]
    fn hash_does_not_claim_a_clean_or_malicious_file() {
        let digest = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
        let assessment =
            ThreatAssessment::from_hash_scan(&hash_scan(ScanStatus::Hashed, Some(digest)));
        assert_eq!(assessment.coverage, AnalysisCoverage::Completed);
        assert_eq!(assessment.sha256.as_deref(), Some(digest));
        assert_eq!(assessment.verdict, ThreatVerdict::NotEvaluated);
        assert_eq!(assessment.category, ThreatCategory::Unknown);
        assert!(assessment.evidence.is_empty());
    }

    #[test]
    fn skipped_failed_or_malformed_hashes_fail_closed() {
        for (status, digest, coverage) in [
            (ScanStatus::Skipped, Some("bad"), AnalysisCoverage::Skipped),
            (ScanStatus::Failed, Some("bad"), AnalysisCoverage::Failed),
            (ScanStatus::Hashed, Some("bad"), AnalysisCoverage::Failed),
            (ScanStatus::Hashed, None, AnalysisCoverage::Failed),
        ] {
            let assessment = ThreatAssessment::from_hash_scan(&hash_scan(status, digest));
            assert_eq!(assessment.coverage, coverage);
            assert_eq!(assessment.verdict, ThreatVerdict::NotEvaluated);
            assert!(assessment.sha256.is_none());
            assert!(assessment.evidence.is_empty());
        }
    }

    #[test]
    fn yara_match_never_assigns_family_or_blocks() {
        let scan = RuleScanResult {
            file_path: PathBuf::from("local-test-file"),
            rule_identifiers: vec![
                "Rule_B".to_owned(),
                "Rule_A".to_owned(),
                "Rule_B".to_owned(),
                " ".to_owned(),
            ],
        };
        let assessment = ThreatAssessment::from_rule_scan(&scan);
        assert_eq!(assessment.verdict, ThreatVerdict::RequiresReview);
        assert_eq!(assessment.category, ThreatCategory::Unknown);
        assert_eq!(assessment.evidence.len(), 2);
        assert_eq!(assessment.evidence[0].identifier, "Rule_A");
        assert!(assessment.sha256.is_none());
    }

    #[test]
    fn empty_yara_matches_are_not_a_clean_verdict() {
        let scan = RuleScanResult {
            file_path: PathBuf::from("local-test-file"),
            rule_identifiers: Vec::new(),
        };
        let assessment = ThreatAssessment::from_rule_scan(&scan);
        assert_eq!(assessment.verdict, ThreatVerdict::NotEvaluated);
        assert!(assessment.evidence.is_empty());
    }

    #[test]
    fn evidence_is_bounded_and_serialization_omits_file_paths() {
        let scan = RuleScanResult {
            file_path: PathBuf::from("private-secret-path"),
            rule_identifiers: (0..200).map(|index| format!("Rule_{index:03}")).collect(),
        };
        let assessment = ThreatAssessment::from_rule_scan(&scan);
        assert_eq!(assessment.evidence.len(), MAX_RULE_EVIDENCE);

        let serialized = serde_json::to_string(&assessment).unwrap();
        assert!(serialized.contains("\"requires_review\""));
        assert!(serialized.contains("\"unknown\""));
        assert!(!serialized.contains("private-secret-path"));
        let parsed: ThreatAssessment = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed, assessment);
    }
}
