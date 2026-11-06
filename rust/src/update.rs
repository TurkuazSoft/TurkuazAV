// Dosya Yolu: REPO_ROOT/rust/src/update.rs
// Amac: Servis guncellemesi icin imza ve downgrade kontrol kapisi
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: Salt-okunur dogrulama; kurulum veya anti-rollback commit'i yapmaz
// Bagimli Oldugu Katman: Service | Config | Tool

use crate::{
    config,
    scan::{is_reparse_or_symlink, read_bounded},
    trusted::TrustedKeyring,
};
use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use subtle::ConstantTimeEq;

pub const SERVICE_UPDATE_SCHEMA: &str = "turkuazav.service-update.v1";
pub const SERVICE_UPDATE_DOMAIN: &str = "TurkuazAV.service-update.v1";
pub const MAX_SERVICE_BINARY_BYTES: usize = 67_108_864;

/// Exact signed fields only; paths, URLs, execution flags and shell commands
/// must never be supplied by an update manifest.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceUpdateManifest {
    pub schema: String,
    pub sequence: i64,
    #[serde(rename = "keyId")]
    pub key_id: String,
    pub version: String,
    #[serde(rename = "targetOs")]
    pub target_os: String,
    #[serde(rename = "targetArch")]
    pub target_arch: String,
    #[serde(rename = "binarySize")]
    pub binary_size: u64,
    #[serde(rename = "binarySha256")]
    pub binary_sha256: String,
}

/// Snapshot of *verified bytes*. No manifest-provided path is used, and the
/// caller must re-verify its own staged executable before running it.
/// No installation or state-file mutation occurs in this module.
#[derive(Debug)]
pub struct VerifiedServiceUpdate {
    sequence: i64,
    publisher_key_id: String,
    version: String,
    verified_binary: Vec<u8>,
    manifest_fingerprint: [u8; 32],
}

impl VerifiedServiceUpdate {
    pub fn sequence(&self) -> i64 {
        self.sequence
    }
    pub fn publisher_key_id(&self) -> &str {
        &self.publisher_key_id
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn verified_binary(&self) -> &[u8] {
        &self.verified_binary
    }
    pub fn manifest_fingerprint(&self) -> &[u8; 32] {
        &self.manifest_fingerprint
    }
}

fn valid_version(version: &str) -> bool {
    let mut parts = version.split('.');
    let component = |text: &str| {
        !text.is_empty()
            && text.len() <= 10
            && (text == "0" || !text.starts_with('0'))
            && text.bytes().all(|b| b.is_ascii_digit())
            && text.parse::<u32>().is_ok()
    };
    let valid = parts.by_ref().take(3).collect::<Vec<_>>();
    valid.len() == 3 && parts.next().is_none() && valid.iter().all(|part| component(part))
}

fn target_platform() -> Result<(&'static str, &'static str)> {
    if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        Ok(("windows", "x86_64"))
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Ok(("linux", "x86_64"))
    } else {
        bail!("Service update verification unsupported on this platform")
    }
}

pub fn parse_service_update_manifest(json: &[u8]) -> Result<ServiceUpdateManifest> {
    ensure!(
        !json.is_empty() && json.len() <= config::MAX_MANIFEST_BYTES,
        "Invalid service update manifest length"
    );
    let value: ServiceUpdateManifest =
        serde_json::from_slice(json).context("Invalid service update manifest")?;
    let (os, arch) = target_platform()?;
    ensure!(
        value.schema == SERVICE_UPDATE_SCHEMA
            && value.sequence > 0
            && crate::trusted::valid_key_id(&value.key_id)
            && valid_version(&value.version)
            && value.target_os == os
            && value.target_arch == arch
            && value.binary_size > 0
            && value.binary_size <= MAX_SERVICE_BINARY_BYTES as u64
            && value.binary_sha256.len() == 64
            && value
                .binary_sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "Invalid, unsupported or unbounded service update manifest"
    );
    Ok(value)
}

/// Signed payload is deliberately domain-separated from signed YARA rule
/// packages. Every authenticated field has a fixed position.
pub fn service_update_signature_payload(value: &ServiceUpdateManifest) -> Vec<u8> {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        SERVICE_UPDATE_DOMAIN,
        value.sequence,
        value.key_id,
        value.version,
        value.target_os,
        value.target_arch,
        value.binary_size,
        value.binary_sha256
    )
    .into_bytes()
}

/// Read-only optimistic check. Final installation must re-check under an
/// exclusive protected state lock and commit state only after successful
/// durable switch-over. Never commit state merely because verification passed.
fn check_accepted_state(state_file: &Path, sequence: i64, fingerprint: &[u8; 32]) -> Result<()> {
    ensure!(
        state_file.parent().is_some_and(Path::is_dir),
        "Protected update state parent must already exist"
    );
    match fs::symlink_metadata(state_file) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("Cannot inspect service update state"),
        Ok(meta) => {
            ensure!(
                meta.is_file() && !is_reparse_or_symlink(&meta) && meta.len() == 40,
                "Corrupt or redirected service update state"
            );
            let saved = fs::read(state_file).context("Cannot read service update state")?;
            ensure!(saved.len() == 40, "Corrupt service update state");
            let last = i64::from_le_bytes(saved[..8].try_into()?);
            ensure!(last > 0, "Corrupt service update sequence");
            ensure!(sequence >= last, "Service update downgrade denied");
            if sequence == last {
                ensure!(
                    saved[8..].ct_eq(fingerprint).unwrap_u8() == 1,
                    "Service update sequence fingerprint conflict"
                );
            }
            Ok(())
        }
    }
}

/// @dev-id TAV-UPDATE-VERIFY-010
/// @purpose Authenticate a bounded, platform-specific service binary snapshot.
/// @reason SHA-256 alone does not establish an authorized publisher identity.
/// @contract Caller provides an independently trusted publisher keyring and a
/// separate protected service-update state path, never rule-version state.
/// This function changes neither installed binaries nor anti-rollback state.
pub fn verify_service_update(
    binary: &Path,
    manifest: &Path,
    signature: &Path,
    ring: &TrustedKeyring,
    state_file: &Path,
) -> Result<VerifiedServiceUpdate> {
    let manifest_bytes = read_bounded(manifest, config::MAX_MANIFEST_BYTES)?;
    let signature_bytes = read_bounded(signature, config::MAX_SIGNATURE_BYTES)?;
    let parsed = parse_service_update_manifest(&manifest_bytes)?;
    let payload = service_update_signature_payload(&parsed);

    // No unsigned bytes are returned. The pinned keyring is independent
    // from the attacker-controlled manifest and signature.
    ring.verify_signed_payload(&parsed.key_id, &payload, &signature_bytes)?;
    let bytes = read_bounded(binary, MAX_SERVICE_BINARY_BYTES)?;
    ensure!(
        parsed.binary_size == bytes.len() as u64,
        "Signed service binary size mismatch"
    );
    let expected = hex::decode(&parsed.binary_sha256)?;
    let actual = Sha256::digest(&bytes);
    ensure!(
        actual.as_slice().ct_eq(&expected).unwrap_u8() == 1,
        "Signed service binary SHA256 mismatch"
    );
    let fingerprint: [u8; 32] = Sha256::digest(&payload).into();
    check_accepted_state(state_file, parsed.sequence, &fingerprint)?;
    Ok(VerifiedServiceUpdate {
        sequence: parsed.sequence,
        publisher_key_id: parsed.key_id,
        version: parsed.version,
        verified_binary: bytes,
        manifest_fingerprint: fingerprint,
    })
}
