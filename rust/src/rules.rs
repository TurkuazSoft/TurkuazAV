// Dosya Yolu: REPO_ROOT/rust/src/rules.rs
// Amac: RSA-PSS-SHA256 imzali kurallari sabit YARA-X motoruyla tara
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: Engine pin, timeout, output cap, snapshot ve NDJSON kontrolu
// Bagimli Oldugu Katman: Service | Tool | Config

use crate::{
    config,
    scan::{ensure_regular, is_reparse_or_symlink, read_bounded},
};
use anyhow::{bail, Context, Result};
use rsa::{
    pkcs1::DecodeRsaPublicKey,
    pkcs8::DecodePublicKey,
    pss::{Signature, VerifyingKey},
    signature::Verifier,
    traits::PublicKeyParts,
    RsaPublicKey,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone)]
pub struct RuleScanResult {
    pub file_path: PathBuf,
    pub rule_identifiers: Vec<String>,
}

pub fn verify_signature(data: &[u8], signature: &[u8], public_pem: &str) -> Result<()> {
    let key = RsaPublicKey::from_public_key_pem(public_pem)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(public_pem))
        .context("Unsupported public key")?;
    if key.n().bits() < 2048 {
        bail!("Weak RSA key");
    }
    let sig = Signature::try_from(signature).context("Malformed RSA signature")?;
    VerifyingKey::<Sha256>::new(key)
        .verify(data, &sig)
        .context("Invalid RSA-PSS-SHA256 signature")
}

pub fn verify_engine(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("YARA-X executable path must be absolute");
    }
    let meta = fs::symlink_metadata(path).context("YARA-X engine missing")?;
    if is_reparse_or_symlink(&meta) || !meta.is_file() {
        bail!("YARA-X engine path is not a regular file");
    }
    let expected = hex::decode(config::engine_digest()?)?;
    let mut file = File::open(path).context("Cannot read YARA-X executable")?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; config::BUFFER_SIZE];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let actual = hasher.finalize();
    if actual.as_slice().ct_eq(&expected).unwrap_u8() != 1 {
        bail!("YARA-X engine digest mismatch");
    }
    Ok(())
}

pub fn parse_yarax_output(ndjson: &str, expected: &Path) -> Result<Vec<String>> {
    let target = fs::canonicalize(expected).context("Missing target snapshot")?;
    let mut identifiers = BTreeSet::new();
    for line in ndjson.lines().filter(|line| !line.trim().is_empty()) {
        let v: Value = serde_json::from_str(line).context("Malformed YARA-X output")?;
        let found = v
            .get("path")
            .and_then(Value::as_str)
            .context("YARA-X output path absent")?;
        let actual = fs::canonicalize(found).context("YARA-X output path invalid")?;
        #[cfg(windows)]
        let is_same =
            actual.to_string_lossy().to_lowercase() == target.to_string_lossy().to_lowercase();
        #[cfg(not(windows))]
        let is_same = actual == target;
        if !is_same {
            bail!("YARA-X output path mismatch");
        }
        let rules = v
            .get("rules")
            .and_then(Value::as_array)
            .context("YARA-X output rules missing")?;
        for r in rules {
            let id = r
                .get("identifier")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .context("Invalid rule identifier")?;
            identifiers.insert(id.to_owned());
        }
    }
    Ok(identifiers.into_iter().collect())
}

fn read_pipe(mut input: impl Read) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    input
        .by_ref()
        .take((config::MAX_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut output)?;
    if output.len() > config::MAX_OUTPUT_BYTES {
        bail!("YARA-X output limit exceeded");
    }
    Ok(output)
}

/// Makes the bytes to be executed independent of a mutable engine path.
/// The private copy is checked *after* copying; a hash of the original path
/// would leave a verify/execute race.
fn stage_engine(engine: &Path, private_dir: &Path) -> Result<PathBuf> {
    if !engine.is_absolute() {
        bail!("YARA-X executable path must be absolute");
    }
    let meta = fs::symlink_metadata(engine).context("YARA-X engine missing")?;
    if is_reparse_or_symlink(&meta) || !meta.is_file() {
        bail!("YARA-X engine path is not a regular file");
    }
    if meta.len() > config::MAX_ENGINE_BYTES {
        bail!("YARA-X executable size limit exceeded");
    }
    let staged = private_dir.join(if cfg!(windows) { "yr.exe" } else { "yr" });
    let copied = fs::copy(engine, &staged).context("Cannot copy YARA-X engine")?;
    if copied > config::MAX_ENGINE_BYTES {
        bail!("YARA-X executable size limit exceeded");
    }
    // The staged executable, not the untrusted source path, is what gets run.
    verify_engine(&staged)?;
    Ok(staged)
}

/// Poll pipe readers in short intervals so cancellation is also honored
/// after the immediate YARA-X process has exited. Detached readers must not
/// be joined without a deadline when a descendant holds an inherited pipe.
fn receive_pipe(
    receiver: &mpsc::Receiver<Result<Vec<u8>>>,
    started: Instant,
    deadline: Duration,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>> {
    loop {
        if cancelled.load(Ordering::Relaxed) {
            bail!("YARA-X scan cancelled");
        }
        let remaining = deadline.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            bail!("YARA-X output read timed out");
        }
        let interval = remaining.min(Duration::from_millis(25));
        match receiver.recv_timeout(interval) {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("YARA-X pipe reader disconnected");
            }
        }
    }
}

pub fn run_engine(engine: &Path, rules: &Path, target: &Path) -> Result<Vec<String>> {
    run_engine_with_cancel(engine, rules, target, &AtomicBool::new(false))
}

pub fn run_engine_with_cancel(
    engine: &Path,
    rules: &Path,
    target: &Path,
    cancelled: &AtomicBool,
) -> Result<Vec<String>> {
    if cancelled.load(Ordering::Relaxed) {
        bail!("YARA-X scan cancelled");
    }
    let private_dir = tempfile::Builder::new()
        .prefix("TurkuazAV-Engine-")
        .tempdir()?;
    let staged = stage_engine(engine, private_dir.path())?;
    let mut child = Command::new(&staged)
        .arg("scan")
        .arg("--output-format=ndjson")
        .arg(rules)
        .arg(target)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Unable to start YARA-X")?;
    let stdout = child.stdout.take().context("stdout unavailable")?;
    let stderr = child.stderr.take().context("stderr unavailable")?;
    // Reader threads communicate through bounded messages. Never join a pipe
    // reader indefinitely: an orphaned grandchild can retain an inherited pipe.
    let (out_sender, out_receiver) = mpsc::channel();
    let (err_sender, err_receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = out_sender.send(read_pipe(stdout));
    });
    thread::spawn(move || {
        let _ = err_sender.send(read_pipe(stderr));
    });
    let started = Instant::now();
    let timeout = Duration::from_secs(config::ENGINE_TIMEOUT_SECONDS);
    let exit = loop {
        if cancelled.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("YARA-X scan cancelled");
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => (),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("YARA-X process wait failed");
            }
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!("YARA-X scan timed out");
        }
        thread::sleep(Duration::from_millis(25));
    };
    let stdout = receive_pipe(&out_receiver, started, timeout, cancelled)?;
    let stderr = receive_pipe(&err_receiver, started, timeout, cancelled)?;
    if cancelled.load(Ordering::Relaxed) {
        bail!("YARA-X scan cancelled");
    }
    if !exit.success() {
        let text = String::from_utf8_lossy(&stderr);
        bail!("YARA-X engine failed: {}", text);
    }
    parse_yarax_output(
        std::str::from_utf8(&stdout).context("Invalid YARA-X output encoding")?,
        target,
    )
}

pub fn snapshot(target: &Path, snapshot: &Path) -> Result<()> {
    snapshot_with_cancel(target, snapshot, &AtomicBool::new(false))
}

pub fn snapshot_with_cancel(target: &Path, snapshot: &Path, cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Relaxed) {
        bail!("YARA-X scan cancelled");
    }
    ensure_regular(target, config::MAX_FILE_SIZE)?;
    let mut input = File::open(target).context("Target open failed")?;
    let mut output = File::create_new(snapshot).context("Snapshot creation failed")?;
    let mut copied = 0u64;
    let mut buffer = [0u8; 4096];
    loop {
        if cancelled.load(Ordering::Relaxed) {
            bail!("YARA-X scan cancelled");
        }
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        copied = copied.checked_add(count as u64).context("Size overflow")?;
        if copied > config::MAX_FILE_SIZE {
            bail!("Target snapshot size limit exceeded");
        }
        output.write_all(&buffer[..count])?;
    }
    output.flush()?;
    if cancelled.load(Ordering::Relaxed) {
        bail!("YARA-X scan cancelled");
    }
    Ok(())
}

pub fn scan_verified_rules(target: &Path, rules: &[u8], engine: &Path) -> Result<RuleScanResult> {
    scan_verified_rules_with_cancel(target, rules, engine, &AtomicBool::new(false))
}

pub fn scan_verified_rules_with_cancel(
    target: &Path,
    rules: &[u8],
    engine: &Path,
    cancelled: &AtomicBool,
) -> Result<RuleScanResult> {
    if cancelled.load(Ordering::Relaxed) {
        bail!("YARA-X scan cancelled");
    }
    ensure_regular(target, config::MAX_FILE_SIZE)?;
    let temp = tempfile::Builder::new()
        .prefix("TurkuazAV-Rules-")
        .tempdir()?;
    let rule_path = temp.path().join("verified.yar");
    let snapshot_path = temp.path().join("target.snapshot");
    fs::write(&rule_path, rules)?;
    snapshot_with_cancel(target, &snapshot_path, cancelled)?;
    let matches = run_engine_with_cancel(engine, &rule_path, &snapshot_path, cancelled)?;
    Ok(RuleScanResult {
        file_path: target.to_path_buf(),
        rule_identifiers: matches,
    })
}

/// Developer-only key path. This is NOT a trusted publisher bootstrap.
pub fn scan_rules(
    target: &Path,
    rules: &Path,
    signature: &Path,
    public_key: &Path,
    engine: &Path,
) -> Result<RuleScanResult> {
    scan_rules_with_cancel(
        target,
        rules,
        signature,
        public_key,
        engine,
        &AtomicBool::new(false),
    )
}

pub fn scan_rules_with_cancel(
    target: &Path,
    rules: &Path,
    signature: &Path,
    public_key: &Path,
    engine: &Path,
    cancelled: &AtomicBool,
) -> Result<RuleScanResult> {
    if cancelled.load(Ordering::Relaxed) {
        bail!("YARA-X scan cancelled");
    }
    ensure_regular(target, config::MAX_FILE_SIZE)?;
    let rules_bytes = read_bounded(rules, config::MAX_RULE_BYTES)?;
    let signature_bytes = read_bounded(signature, config::MAX_SIGNATURE_BYTES)?;
    let public_bytes = read_bounded(public_key, config::MAX_PUBLIC_KEY_BYTES)?;
    let pem = std::str::from_utf8(&public_bytes).context("Invalid PEM encoding")?;
    verify_signature(&rules_bytes, &signature_bytes, pem)?;
    if cancelled.load(Ordering::Relaxed) {
        bail!("YARA-X scan cancelled");
    }
    scan_verified_rules_with_cancel(target, &rules_bytes, engine, cancelled)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ndjson_path_and_identifier_enforced() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("target");
        fs::write(&f, b"hello").unwrap();
        let good = format!(
            r#"{{"path":{},"rules":[{{"identifier":"demo"}}]}}"#,
            serde_json::to_string(&f.to_string_lossy()).unwrap()
        );
        assert_eq!(parse_yarax_output(&good, &f).unwrap(), vec!["demo"]);
        assert!(parse_yarax_output(
            r#"{"path":"/untrusted","rules":[{"identifier":"demo"}]}"#,
            &f
        )
        .is_err());
        assert!(parse_yarax_output(
            &format!(
                r#"{{"path":{},"rules":[{{"identifier":""}}]}}"#,
                serde_json::to_string(&f.to_string_lossy()).unwrap()
            ),
            &f
        )
        .is_err());
    }
    #[test]
    fn cancellation_fails_before_untrusted_rule_io() {
        let cancelled = AtomicBool::new(true);
        let invalid = Path::new("this-path-must-not-be-opened");
        let result =
            scan_rules_with_cancel(invalid, invalid, invalid, invalid, invalid, &cancelled);
        assert!(result.unwrap_err().to_string().contains("cancelled"));
    }
    #[test]
    fn snapshot_cancellation_never_leaves_complete_success() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let dest = temp.path().join("snapshot");
        fs::write(&source, b"example").unwrap();
        let cancelled = AtomicBool::new(true);
        assert!(snapshot_with_cancel(&source, &dest, &cancelled).is_err());
        assert!(!dest.exists());
    }
    #[test]
    fn staged_engine_fails_closed_for_untrusted_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("fake-yr");
        let folder = temp.path().join("private");
        fs::create_dir_all(&folder).unwrap();
        fs::write(&source, b"not the pinned YARA-X release").unwrap();
        assert!(stage_engine(&source, &folder).is_err());
        let staged = folder.join(if cfg!(windows) { "yr.exe" } else { "yr" });
        assert!(staged.exists());
        assert_eq!(fs::read(staged).unwrap(), b"not the pinned YARA-X release");
    }
    #[test]
    fn oversized_engine_rejected_before_staging() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("huge-yr");
        let folder = temp.path().join("private");
        fs::create_dir_all(&folder).unwrap();
        File::create(&source)
            .unwrap()
            .set_len(config::MAX_ENGINE_BYTES + 1)
            .unwrap();
        assert!(stage_engine(&source, &folder).is_err());
    }
    #[test]
    fn pipe_reader_cancellation_is_not_delayed_by_inherited_handles() {
        let (_sender, receiver) = mpsc::channel();
        let cancelled = AtomicBool::new(true);
        let start = Instant::now();
        assert!(receive_pipe(&receiver, start, Duration::from_secs(30), &cancelled,).is_err());
    }
    #[test]
    fn engine_output_limit_fails_closed() {
        let oversized = vec![b'A'; config::MAX_OUTPUT_BYTES + 1];
        assert!(read_pipe(std::io::Cursor::new(oversized)).is_err());
    }
    #[test]
    fn wrong_engine_rejected() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("fake-yr");
        fs::write(&f, b"this is not an engine").unwrap();
        assert!(verify_engine(&f).is_err());
    }
}
