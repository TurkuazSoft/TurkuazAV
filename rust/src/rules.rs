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

pub fn run_engine(engine: &Path, rules: &Path, target: &Path) -> Result<Vec<String>> {
    verify_engine(engine)?;
    let mut child = Command::new(engine)
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
    let out_reader = thread::spawn(move || read_pipe(stdout));
    let err_reader = thread::spawn(move || read_pipe(stderr));
    let started = Instant::now();
    let mut exit = None;
    loop {
        if let Some(status) = child.try_wait()? {
            exit = Some(status);
            break;
        }
        if started.elapsed() >= Duration::from_secs(config::ENGINE_TIMEOUT_SECONDS) {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    if exit.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let stdout = out_reader
        .join()
        .map_err(|_| anyhow::anyhow!("YARA-X stdout thread panicked"))??;
    let stderr = err_reader
        .join()
        .map_err(|_| anyhow::anyhow!("YARA-X stderr thread panicked"))??;
    if exit.is_none() {
        bail!("YARA-X scan timed out");
    }
    if !exit.expect("Checked above").success() {
        let text = String::from_utf8_lossy(&stderr);
        bail!("YARA-X engine failed: {}", text);
    }
    parse_yarax_output(
        std::str::from_utf8(&stdout).context("Invalid YARA-X output encoding")?,
        target,
    )
}

pub fn snapshot(target: &Path, snapshot: &Path) -> Result<()> {
    ensure_regular(target, config::MAX_FILE_SIZE)?;
    let mut input = File::open(target).context("Target open failed")?;
    let mut output = File::create_new(snapshot).context("Snapshot creation failed")?;
    let mut copied = 0u64;
    let mut buffer = [0u8; 4096];
    loop {
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
    Ok(())
}

pub fn scan_verified_rules(target: &Path, rules: &[u8], engine: &Path) -> Result<RuleScanResult> {
    ensure_regular(target, config::MAX_FILE_SIZE)?;
    let temp = tempfile::Builder::new()
        .prefix("TurkuazAV-Rules-")
        .tempdir()?;
    let rule_path = temp.path().join("verified.yar");
    let snapshot_path = temp.path().join("target.snapshot");
    fs::write(&rule_path, rules)?;
    snapshot(target, &snapshot_path)?;
    let matches = run_engine(engine, &rule_path, &snapshot_path)?;
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
    ensure_regular(target, config::MAX_FILE_SIZE)?;
    let rules_bytes = read_bounded(rules, config::MAX_RULE_BYTES)?;
    let signature_bytes = read_bounded(signature, config::MAX_SIGNATURE_BYTES)?;
    let public_bytes = read_bounded(public_key, config::MAX_PUBLIC_KEY_BYTES)?;
    let pem = std::str::from_utf8(&public_bytes).context("Invalid PEM encoding")?;
    verify_signature(&rules_bytes, &signature_bytes, pem)?;
    scan_verified_rules(target, &rules_bytes, engine)
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
    fn wrong_engine_rejected() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("fake-yr");
        fs::write(&f, b"this is not an engine").unwrap();
        assert!(verify_engine(&f).is_err());
    }
}
