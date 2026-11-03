// Dosya Yolu: REPO_ROOT/tests/service_host_smoke.rs
// Amac: Gercek servis ikilisinin kurulum olmadan canli surec testleri
// Modul - FileType: Tests - Rust
// Version: 0.3.1
// Aciklama: Unicode relocasyon, exit code ve Linux SIGTERM kapatma
// Bagimli Oldugu Katman: Tool | Service

use std::{fs, process::Command};

#[test]
fn service_once_process_completes_from_unrelated_unicode_directory() {
    let dir = tempfile::tempdir().unwrap();
    let watched = dir.path().join("Hizmet Çalışma");
    fs::create_dir_all(&watched).unwrap();
    fs::write(watched.join("test.txt"), b"hello").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_turkuazav-service"))
        .arg("--once")
        .arg(&watched)
        .arg("1")
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("SERVICE_ONCE=PASS version=0.3.1"));
    assert!(!text.contains("test.txt"));
}

#[test]
fn service_refuses_invalid_or_unprivileged_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let executable = env!("CARGO_BIN_EXE_turkuazav-service");
    let missing = Command::new(executable)
        .args(["--once", "relative", "1"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
    let missing_directory = Command::new(executable)
        .arg("--once")
        .arg(dir.path().join("missing"))
        .arg("1")
        .output()
        .unwrap();
    assert!(!missing_directory.status.success());
    let excessive = Command::new(executable)
        .arg("--once")
        .arg(dir.path())
        .arg("100")
        .output()
        .unwrap();
    assert!(!excessive.status.success());
}

#[cfg(target_os = "linux")]
#[test]
fn linux_sigterm_gracefully_stops_foreground_service_process() {
    use std::{
        io::{BufRead, BufReader},
        os::raw::c_int,
        process::Stdio,
        time::{Duration, Instant},
    };

    unsafe extern "C" {
        fn kill(pid: c_int, signal: c_int) -> c_int;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_turkuazav-service"))
        .arg("--foreground")
        .arg(dir.path())
        .arg("1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line).unwrap();
    assert!(line.starts_with("SERVICE_HOST=READY"), "{line}");
    // SAFETY: child.id() identifies the dedicated subprocess created here.
    assert_eq!(unsafe { kill(child.id() as c_int, 15) }, 0);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "Service SIGTERM exit: {status}");
            break;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("Service failed to stop after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}
