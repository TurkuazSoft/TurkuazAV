// Dosya Yolu: REPO_ROOT/rust/src/scan.rs
// Amac: Dosyalari degistirmeden bounded SHA256 hesapla
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: Symlink/reparse engeli, iptal ve sonuc sozlesmesi
// Bagimli Oldugu Katman: Service | Repo | Tool | Config

use crate::config::{BUFFER_SIZE, MAX_FILE_SIZE};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::{fs::{self, File, Metadata}, io::Read, path::{Path, PathBuf}, sync::atomic::{AtomicBool, Ordering}};
use walkdir::WalkDir;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStatus { Hashed, Skipped, Failed }

#[derive(Debug, Clone)]
pub struct FileScanResult {
    pub path: PathBuf,
    pub status: ScanStatus,
    pub sha256: Option<String>,
    pub size_bytes: Option<u64>,
    pub details: Option<String>,
}

pub fn is_reparse_or_symlink(meta: &Metadata) -> bool {
    if meta.file_type().is_symlink() { return true; }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 { return true; }
    }
    false
}

pub fn ensure_regular(path: &Path, limit: u64) -> Result<Metadata> {
    let meta = fs::symlink_metadata(path).context("File metadata unavailable")?;
    if is_reparse_or_symlink(&meta) || !meta.is_file() {
        bail!("Invalid path or symbolic link");
    }
    if meta.len() > limit { bail!("File too large"); }
    Ok(meta)
}

pub fn sha256_bounded(path: &Path, limit: u64, cancelled: &AtomicBool) -> Result<(String, u64)> {
    ensure_regular(path, limit)?;
    let mut input = File::open(path).context("File open failed")?;
    let mut sha = Sha256::new();
    let mut buf = [0u8; BUFFER_SIZE];
    let mut count = 0u64;
    loop {
        if cancelled.load(Ordering::Relaxed) { bail!("Scan cancelled"); }
        let bytes = input.read(&mut buf)?;
        if bytes == 0 { break; }
        count = count.checked_add(bytes as u64).context("Size overflow")?;
        if count > limit { bail!("File too large"); }
        sha.update(&buf[..bytes]);
    }
    if cancelled.load(Ordering::Relaxed) { bail!("Scan cancelled"); }
    Ok((hex::encode_upper(sha.finalize()), count))
}

pub fn scan_file(path: &Path, cancelled: &AtomicBool) -> FileScanResult {
    let path = path.to_path_buf();
    match fs::symlink_metadata(&path) {
        Ok(meta) if is_reparse_or_symlink(&meta) => FileScanResult {
            path, status: ScanStatus::Skipped, sha256: None, size_bytes: None,
            details: Some("Symbolic link skipped".into()),
        },
        Ok(meta) if meta.is_file() && meta.len() > MAX_FILE_SIZE => FileScanResult {
            path, status: ScanStatus::Skipped, sha256: None, size_bytes: Some(meta.len()),
            details: Some("File too large".into()),
        },
        Ok(meta) if !meta.is_file() => FileScanResult {
            path, status: ScanStatus::Failed, sha256: None, size_bytes: None,
            details: Some("Not a regular file".into()),
        },
        Ok(_) => match sha256_bounded(&path, MAX_FILE_SIZE, cancelled) {
            Ok((hash, size)) => FileScanResult { path, status: ScanStatus::Hashed,
                sha256: Some(hash), size_bytes: Some(size), details: None },
            Err(error) => FileScanResult { path, status: ScanStatus::Failed,
                sha256: None, size_bytes: None, details: Some(error.to_string()) },
        },
        Err(error) => FileScanResult { path, status: ScanStatus::Failed,
            sha256: None, size_bytes: None, details: Some(error.to_string()) },
    }
}

pub fn scan_path(path: &Path, cancelled: &AtomicBool) -> Result<Vec<FileScanResult>> {
    let meta = fs::symlink_metadata(path).context("Scan root does not exist")?;
    if is_reparse_or_symlink(&meta) { bail!("Root symbolic link denied"); }
    if meta.is_file() { return Ok(vec![scan_file(path, cancelled)]); }
    if !meta.is_dir() { bail!("Invalid scan root"); }
    let mut results = Vec::new();
    for item in WalkDir::new(path).follow_links(false).sort_by_file_name() {
        if cancelled.load(Ordering::Relaxed) { bail!("Scan cancelled"); }
        match item {
            Ok(entry) if entry.file_type().is_dir() => (),
            Ok(entry) => {
                // Do not recurse into reparse directories on Windows.
                results.push(scan_file(entry.path(), cancelled));
            },
            Err(error) => results.push(FileScanResult {
                path: error.path().unwrap_or(path).to_path_buf(),
                status: ScanStatus::Failed, sha256: None, size_bytes: None,
                details: Some(error.to_string()),
            }),
        }
    }
    Ok(results)
}

pub fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    ensure_regular(path, limit as u64)?;
    let mut input = File::open(path).context("Input open failed")?;
    let mut result = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let got = input.read(&mut buffer)?;
        if got == 0 { break; }
        if got > limit.saturating_sub(result.len()) { bail!("Input size limit exceeded"); }
        result.extend_from_slice(&buffer[..got]);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hash_matches_reference_and_no_verdict() {
        let temp = tempfile::tempdir().unwrap();
        let f = temp.path().join("sample");
        fs::write(&f, b"abc").unwrap();
        let result = scan_file(&f, &AtomicBool::new(false));
        assert_eq!(result.status, ScanStatus::Hashed);
        assert_eq!(result.sha256.as_deref(), Some("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"));
        assert_eq!(result.size_bytes, Some(3));
    }
    #[test]
    fn large_file_skipped_and_previous_hash_cleared() {
        let temp = tempfile::tempdir().unwrap();
        let f = temp.path().join("big");
        let file = File::create(&f).unwrap();
        file.set_len(MAX_FILE_SIZE + 1).unwrap();
        let result = scan_file(&f, &AtomicBool::new(false));
        assert_eq!(result.status, ScanStatus::Skipped);
        assert!(result.sha256.is_none());
    }
    #[test]
    fn cancellation_never_returns_hash() {
        let temp = tempfile::tempdir().unwrap();
        let f = temp.path().join("cancel");
        fs::write(&f, b"hello").unwrap();
        let result = scan_file(&f, &AtomicBool::new(true));
        assert_eq!(result.status, ScanStatus::Failed);
        assert!(result.sha256.is_none());
    }
    #[cfg(unix)]
    #[test]
    fn symlink_not_followed() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("target");
        let link = temp.path().join("link");
        fs::write(&original, b"secret").unwrap();
        symlink(&original, &link).unwrap();
        assert_eq!(scan_file(&link, &AtomicBool::new(false)).status, ScanStatus::Skipped);
        assert!(scan_path(&link, &AtomicBool::new(false)).is_err());
    }
}
