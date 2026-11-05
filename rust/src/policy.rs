// Dosya Yolu: REPO_ROOT/rust/src/policy.rs
// Amac: Scanner raporlarini salt-okunur kullanici yonlendirmesine donustur
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: Kanit varligi, kapsam ve motor tutarliligini yan etkisiz denetler
// Bagimli Oldugu Katman: Service

use crate::{
    scanner::{ScannerId, ScannerReport},
    threat::{AnalysisCoverage, ThreatCategory, ThreatVerdict},
};

/// Advice is never permission to delete, block, quarantine or trust a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvisoryAction {
    NoAutomaticAction,
    ManualReview,
    RetryAnalysis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvisoryReason {
    HashOnly,
    NoRuleMatch,
    RuleMatch,
    Incomplete,
    InconsistentReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvisoryDecision {
    pub action: AdvisoryAction,
    pub reason: AdvisoryReason,
}

impl AdvisoryDecision {
    const fn new(action: AdvisoryAction, reason: AdvisoryReason) -> Self {
        Self { action, reason }
    }
}

/// @dev-id TAV-SCANNER-POLICY-001
/// @purpose Separate detection evidence from user-facing recommendations.
/// @reason Engine reports may be incomplete or inconsistent; no match is not clean.
/// @contract Pure function; never authorizes automatic protection actions.
/// ScannerId is attribution only and does not independently prove publisher trust.
pub fn advise(report: &ScannerReport) -> AdvisoryDecision {
    let assessment = &report.assessment;
    if assessment.coverage != AnalysisCoverage::Completed {
        return AdvisoryDecision::new(AdvisoryAction::RetryAnalysis, AdvisoryReason::Incomplete);
    }

    if assessment.category != ThreatCategory::Unknown {
        return AdvisoryDecision::new(
            AdvisoryAction::RetryAnalysis,
            AdvisoryReason::InconsistentReport,
        );
    }

    match report.scanner {
        ScannerId::Sha256
            if assessment.sha256.is_some()
                && assessment.verdict == ThreatVerdict::NotEvaluated
                && assessment.evidence.is_empty() =>
        {
            AdvisoryDecision::new(AdvisoryAction::NoAutomaticAction, AdvisoryReason::HashOnly)
        }
        ScannerId::YaraX if assessment.sha256.is_none() => {
            match (assessment.verdict, assessment.evidence.is_empty()) {
                (ThreatVerdict::RequiresReview, false) => {
                    AdvisoryDecision::new(AdvisoryAction::ManualReview, AdvisoryReason::RuleMatch)
                }
                (ThreatVerdict::NotEvaluated, true) => {
                    AdvisoryDecision::new(AdvisoryAction::NoAutomaticAction, AdvisoryReason::NoRuleMatch)
                }
                _ => AdvisoryDecision::new(
                    AdvisoryAction::RetryAnalysis,
                    AdvisoryReason::InconsistentReport,
                ),
            }
        }
        _ => AdvisoryDecision::new(
            AdvisoryAction::RetryAnalysis,
            AdvisoryReason::InconsistentReport,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat::{EvidenceType, ThreatAssessment, ThreatEvidence};

    fn example(scanner: ScannerId, verdict: ThreatVerdict) -> ScannerReport {
        ScannerReport {
            scanner,
            assessment: ThreatAssessment {
                coverage: AnalysisCoverage::Completed,
                verdict,
                category: ThreatCategory::Unknown,
                sha256: None,
                evidence: Vec::new(),
            },
        }
    }

    #[test]
    fn hash_is_never_a_clean_verdict_or_blocking_action() {
        let mut report = example(ScannerId::Sha256, ThreatVerdict::NotEvaluated);
        report.assessment.sha256 = Some(
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
                .to_owned(),
        );
        assert_eq!(
            advise(&report),
            AdvisoryDecision::new(AdvisoryAction::NoAutomaticAction, AdvisoryReason::HashOnly)
        );
    }

    #[test]
    fn yara_match_requires_manual_review_but_empty_matches_are_not_clean() {
        let mut report = example(ScannerId::YaraX, ThreatVerdict::NotEvaluated);
        assert_eq!(
            advise(&report),
            AdvisoryDecision::new(AdvisoryAction::NoAutomaticAction, AdvisoryReason::NoRuleMatch)
        );
        report.assessment.verdict = ThreatVerdict::RequiresReview;
        report.assessment.evidence.push(ThreatEvidence {
            evidence_type: EvidenceType::YaraRule,
            identifier: "FixtureRule".to_owned(),
        });
        assert_eq!(
            advise(&report),
            AdvisoryDecision::new(AdvisoryAction::ManualReview, AdvisoryReason::RuleMatch)
        );
    }

    #[test]
    fn incomplete_scan_is_never_reviewed_as_a_complete_match() {
        let mut report = example(ScannerId::YaraX, ThreatVerdict::RequiresReview);
        report.assessment.evidence.push(ThreatEvidence {
            evidence_type: EvidenceType::YaraRule,
            identifier: "FixtureRule".to_owned(),
        });
        for coverage in [AnalysisCoverage::Skipped, AnalysisCoverage::Failed] {
            report.assessment.coverage = coverage;
            assert_eq!(
                advise(&report),
                AdvisoryDecision::new(AdvisoryAction::RetryAnalysis, AdvisoryReason::Incomplete)
            );
        }
    }

    #[test]
    fn inconsistent_scanner_reports_require_retry_instead_of_a_verdict() {
        let mut yara = example(ScannerId::YaraX, ThreatVerdict::RequiresReview);
        assert_eq!(advise(&yara).reason, AdvisoryReason::InconsistentReport);

        yara.assessment.verdict = ThreatVerdict::NotEvaluated;
        yara.assessment.evidence.push(ThreatEvidence {
            evidence_type: EvidenceType::YaraRule,
            identifier: "FixtureRule".to_owned(),
        });
        assert_eq!(advise(&yara).action, AdvisoryAction::RetryAnalysis);

        yara.assessment.evidence.clear();
        yara.assessment.sha256 = Some("digest".to_owned());
        assert_eq!(advise(&yara).reason, AdvisoryReason::InconsistentReport);

        let mut hash = example(ScannerId::Sha256, ThreatVerdict::NotEvaluated);
        assert_eq!(advise(&hash).action, AdvisoryAction::RetryAnalysis);
        hash.assessment.category = ThreatCategory::Trojan;
        assert_eq!(advise(&hash).reason, AdvisoryReason::InconsistentReport);
    }
}
