// Dosya Yolu: REPO_ROOT/rust/src/lib.rs
// Amac: Rust TurkuazAV modullerinin kamusal API'si
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: Salt okunur hash, imzali kural ve paket akislari
// Bagimli Oldugu Katman: Service | Repo | Tool | Config

pub mod config;
pub mod monitor;
pub mod native_events;
pub mod rules;
pub mod scan;
pub mod service;
pub mod trusted;
pub mod worker;

pub use monitor::{ChangeKind, DirectoryObserver, ObservedChange};
pub use native_events::{NativeChangeWakeup, WakeReason};
pub use rules::{
    parse_yarax_output, scan_rules, scan_rules_with_cancel, verify_engine, RuleScanResult,
};
pub use scan::{scan_file, scan_path, scan_path_each, FileScanResult, ScanStatus};
pub use service::{ReconcileSignal, ScanCoordinator};
pub use worker::{SupervisedScanWorker, WorkerFault, WorkerHealth, WorkerPhase};
pub use trusted::{
    accept_version, scan_trusted_rules, scan_trusted_rules_with_cancel, verify_package,
    TrustedKeyring, TrustedScanPaths, VerifiedRulePackage,
};
