// Dosya Yolu: REPO_ROOT/rust/src/lib.rs
// Amac: Rust TurkuazAV modullerinin kamusal API'si
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: Salt okunur hash, imzali kural ve paket akislari
// Bagimli Oldugu Katman: Service | Repo | Tool | Config

pub mod config;
pub mod scan;
pub mod rules;
pub mod trusted;

pub use scan::{scan_file, scan_path, FileScanResult, ScanStatus};
pub use rules::{scan_rules, verify_engine, parse_yarax_output, RuleScanResult};
pub use trusted::{scan_trusted_rules, verify_package, accept_version, TrustedKeyring, VerifiedRulePackage};
