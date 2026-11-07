// Dosya Yolu: REPO_ROOT/rust/src/lib.rs
// Amac: Rust TurkuazAV modullerinin kamusal API'si
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: Salt okunur hash, imzali kural ve paket akislari
// Bagimli Oldugu Katman: Service | Repo | Tool | Config

pub mod config;
pub mod desktop_rules;
pub mod monitor;
pub mod native_events;
pub mod policy;
pub mod publisher_bootstrap;
pub mod rule_publication;
pub mod rule_staging;
pub mod rules;
pub mod scan;
pub mod scanner;
pub mod service;
pub mod source_evidence;
pub mod threat;
pub mod trusted;
pub mod update;
pub mod update_transaction;
pub mod virustotal;
pub mod worker;

pub use desktop_rules::{DesktopRulePreflight, DesktopTrustedRules};
pub use monitor::{ChangeKind, DirectoryObserver, ObservedChange};
pub use native_events::{NativeChangeWakeup, WakeReason};
pub use policy::{advise, AdvisoryAction, AdvisoryDecision, AdvisoryReason};
pub use publisher_bootstrap::PublisherDigestPin;
pub use rule_publication::{
    publish_verified_rule_candidate, CandidatePublicationPaths, PublishedRuleCandidate,
};
pub use rule_staging::{stage_signed_rule_candidate, RuleCandidatePaths, StagedRuleCandidate};
pub use rules::{
    parse_yarax_output, scan_rules, scan_rules_with_cancel, verify_engine, RuleScanResult,
};
pub use scan::{scan_file, scan_path, scan_path_each, FileScanResult, ScanStatus};
pub use scanner::{
    scan_with, ScannerBackend, ScannerId, ScannerReport, Sha256Scanner, TrustedYaraXScanner,
};
pub use service::{ReconcileSignal, ScanCoordinator};
pub use source_evidence::{
    collect_source_evidence, collect_source_evidence_with_approval, EvidenceSource,
    ExternalLookupApproval, SourceEvidenceReport, SourceLocation, SourceObservation, SourceSignal,
};
pub use threat::{
    AnalysisCoverage, EvidenceType, ThreatAssessment, ThreatCategory, ThreatEvidence, ThreatVerdict,
};
pub use trusted::{
    accept_version, scan_trusted_rules, scan_trusted_rules_with_cancel, verify_package,
    TrustedKeyring, TrustedScanPaths, VerifiedRulePackage,
};
pub use update::{verify_service_update, VerifiedServiceUpdate};
pub use update_transaction::{
    apply_verified_service_update, inspect_pending_service_update, CommittedServiceUpdate,
    PendingCandidateInspection, PendingUpdateInspection, ServiceActivation,
};
pub use virustotal::{HttpsGetRequest, HttpsGetResponse, HttpsGetTransport, VirusTotalHashSource};
pub use worker::{SupervisedScanWorker, WorkerFault, WorkerHealth, WorkerPhase};
