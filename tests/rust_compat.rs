// Dosya Yolu: REPO_ROOT/tests/rust_compat.rs
// Amac: Eski 0.3.1 davranis kontrati Rust ile sabit tutulur
// Modul - FileType: Tests - Rust
// Version: 0.3.1
// Aciklama: Hash ve fail-closed regression
// Bagimli Oldugu Katman: Service | Tool | View

use std::{fs, sync::atomic::AtomicBool};
use turkuazav::{accept_version, parse_yarax_output, scan_path, ScanStatus};

#[test]
fn folder_scan_reports_success_without_malware_verdict() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("example.txt"), b"hello").unwrap();
    let results = scan_path(dir.path(), &AtomicBool::new(false)).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, ScanStatus::Hashed);
    assert!(results[0].details.is_none());
    assert!(results[0].sha256.as_ref().is_some_and(|s| s.len() == 64));
}

#[test]
fn malicious_engine_output_path_does_not_masquerade_as_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let expected = dir.path().join("expected");
    fs::write(&expected, b"data").unwrap();
    let other = dir.path().join("other");
    fs::write(&other, b"data").unwrap();
    let payload =
        serde_json::json!({"path":other.to_string_lossy(), "rules":[{"identifier":"fake"}]})
            .to_string();
    assert!(parse_yarax_output(&payload, &expected).is_err());
}

#[test]
fn existing_dotnet_40_byte_state_is_accepted_without_format_migration() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("legacy-state.bin");
    let fingerprint = [0xABu8; 32];
    let mut record = [0u8; 40];
    record[..8].copy_from_slice(&17i64.to_le_bytes());
    record[8..].copy_from_slice(&fingerprint);
    fs::write(&state, record).unwrap();

    // The original .NET little-endian record can be read by Rust unchanged.
    accept_version(&state, 17, &fingerprint).unwrap();
    assert_eq!(fs::read(&state).unwrap(), record);
    assert!(accept_version(&state, 16, &fingerprint).is_err());
    assert!(accept_version(&state, 17, &[0xCDu8; 32]).is_err());

    accept_version(&state, 18, &[0xCDu8; 32]).unwrap();
    let next = fs::read(&state).unwrap();
    assert_eq!(next.len(), 40);
    assert_eq!(i64::from_le_bytes(next[..8].try_into().unwrap()), 18);
    assert_eq!(&next[8..], &[0xCDu8; 32]);
}
