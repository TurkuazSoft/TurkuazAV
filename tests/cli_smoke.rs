// Dosya Yolu: REPO_ROOT/tests/cli_smoke.rs
// Amac: Derlenen Rust CLI'yi alt surecte 0.3.1 kontratiyla test et
// Modul - FileType: Tests - Rust
// Version: 0.3.1
// Aciklama: Gercek stdout, exit code ve hash raporu regressions
// Bagimli Oldugu Katman: Controller | Service | View

use std::{fs, process::Command};

#[test]
fn scan_outputs_exact_digest_and_no_antivirus_verdict() {
    let folder = tempfile::tempdir().unwrap();
    let input = folder.path().join("hello.txt");
    fs::write(&input, b"abc").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_turkuazav"))
        .args(["scan", input.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "CLI stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"));
    assert!(stdout.contains("Summary: hashed=1, skipped=0, failed=0"));
    assert!(!stdout.to_lowercase().contains("clean"));
    assert!(!stdout.to_lowercase().contains("temiz"));
}

#[test]
fn usage_is_nonzero_and_invalid_input_fails_closed() {
    let help = Command::new(env!("CARGO_BIN_EXE_turkuazav"))
        .output()
        .unwrap();
    assert_eq!(help.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage:"));

    let nonexistent = tempfile::tempdir().unwrap().path().join("missing-input");
    let error = Command::new(env!("CARGO_BIN_EXE_turkuazav"))
        .args(["scan", nonexistent.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!error.status.success());
    assert!(String::from_utf8_lossy(&error.stderr).contains("Scan error:"));
}

#[test]
fn unicode_directory_scan_from_unrelated_working_directory_streams_results() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("Deneme Türkçe klasör");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("giriş.txt"), b"first").unwrap();
    fs::write(input.join("ikinci.txt"), b"second").unwrap();
    let big = fs::File::create(input.join("big.bin")).unwrap();
    big.set_len(turkuazav::config::MAX_FILE_SIZE + 1).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_turkuazav"))
        .arg("scan")
        .arg(&input)
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("giriş.txt"));
    assert!(stdout.contains("ikinci.txt"));
    assert!(stdout.contains("SKIP |"));
    assert!(stdout.contains("Summary: hashed=2, skipped=1, failed=0"));
}
