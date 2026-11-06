// Dosya Yolu: REPO_ROOT/rust/src/update_transaction.rs
// Amac: Imzali servis ikilisini hazirlayan kontrollu update islem cekirdegi
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: Guvenli staging, servisi kontrol etme ve best-effort rollback
// Bagimli Oldugu Katman: Service | Tool | Config

use crate::{
    scan::{is_reparse_or_symlink, read_bounded},
    trusted::accept_version,
    update::{VerifiedServiceUpdate, MAX_SERVICE_BINARY_BYTES},
};
use anyhow::{bail, ensure, Context, Result};
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;

const TRANSACTION_LOCK: &str = ".turkuazav-service-update.txn.lock";
const PENDING_MARKER: &str = ".turkuazav-service-update.pending";
const MAX_PENDING_RECORD_BYTES: usize = 8192;

/// The platform-specific adapter MUST independently authorize the service
/// name, identity, executable path and actual process/health state. This is
/// an interface, not an enabled SCM/systemd installer or a trusted adapter.
pub trait ServiceActivation {
    fn current_binary(&mut self) -> Result<PathBuf>;
    fn activate(&mut self, verified_candidate: &Path) -> Result<()>;
    fn check_health(&mut self, verified_candidate: &Path) -> Result<()>;
    fn restore(&mut self, previous_binary: &Path) -> Result<()>;
}

#[derive(Debug)]
pub struct CommittedServiceUpdate {
    pub sequence: i64,
    pub version: String,
    pub installed_binary: PathBuf,
}

fn regular_file(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "Expected an absolute service executable"
    );
    let meta = fs::symlink_metadata(path).context("Cannot inspect service executable")?;
    ensure!(
        meta.is_file() && !is_reparse_or_symlink(&meta),
        "Refusing a linked or non-regular executable"
    );
    Ok(())
}

fn lock_transaction(install_root: &Path) -> Result<fs::File> {
    ensure!(install_root.is_absolute(), "Install root must be absolute");
    let root = fs::symlink_metadata(install_root).context("Missing install root")?;
    ensure!(
        root.is_dir() && !is_reparse_or_symlink(&root),
        "Invalid or redirected install root"
    );
    let lock_path = install_root.join(TRANSACTION_LOCK);
    match fs::symlink_metadata(&lock_path) {
        Ok(meta) => ensure!(
            meta.is_file() && !is_reparse_or_symlink(&meta),
            "Untrusted transaction lock"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error).context("Cannot inspect transaction lock"),
    }
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .context("Cannot open protected transaction lock")?;
    lock_file
        .try_lock_exclusive()
        .context("Another service-update transaction is in progress")?;
    Ok(lock_file)
}

fn check_state_path(install_root: &Path, state_file: &Path) -> Result<()> {
    ensure!(
        safe_report_path(install_root) && safe_report_path(state_file),
        "Update paths must be absolute and free of traversal components"
    );
    let state_name = state_file
        .file_name()
        .and_then(|name| name.to_str())
        .context("Invalid service update state filename")?;

    // @dev-id TAV-UPDATE-PATH-010
    // @purpose Reject state names that collide with the transaction lock,
    // pending marker, its lock sidecar, or the private staging namespace.
    // @reason Such collisions can make activation succeed but state commit
    // fail, leaving the running service and version record inconsistent.
    ensure!(
        state_name != PENDING_MARKER
            && state_name != TRANSACTION_LOCK
            && state_name != ".turkuazav-service-update.txn"
            && !state_name.starts_with(".turkuazav-update-")
            && !state_name.starts_with("turkuazav-service-seq-"),
        "Reserved service update state path"
    );
    let state_parent = state_file
        .parent()
        .context("Invalid service update state path")?
        .canonicalize()
        .context("Cannot resolve service update state parent")?;
    ensure!(
        install_root.canonicalize()? == state_parent,
        "Update state must be under the controlled install root"
    );
    Ok(())
}

fn require_new_sequence(state_file: &Path, sequence: i64) -> Result<()> {
    match fs::symlink_metadata(state_file) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("Cannot inspect update sequence"),
        Ok(meta) => {
            ensure!(
                meta.is_file() && !is_reparse_or_symlink(&meta) && meta.len() == 40,
                "Corrupt or redirected update sequence"
            );
            let saved = fs::read(state_file).context("Cannot read update sequence")?;
            ensure!(saved.len() == 40, "Corrupt update sequence");
            let old_sequence = i64::from_le_bytes(saved[..8].try_into()?);
            ensure!(
                old_sequence > 0 && sequence > old_sequence,
                "Service update must advance accepted sequence"
            );
            Ok(())
        }
    }
}

fn candidate_path(install_root: &Path, sequence: i64) -> PathBuf {
    let filename = if cfg!(windows) {
        format!("turkuazav-service-seq-{sequence}.exe")
    } else {
        format!("turkuazav-service-seq-{sequence}")
    };
    install_root.join(filename)
}

fn stage_verified(install_root: &Path, verified: &VerifiedServiceUpdate) -> Result<PathBuf> {
    let target = candidate_path(install_root, verified.sequence());
    // A crash residue or concurrent installation must not be overwritten.
    ensure!(
        !target.exists()
            && fs::symlink_metadata(&target)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "Staged version path already exists or is inaccessible"
    );
    let mut file = tempfile::Builder::new()
        .prefix(".turkuazav-update-")
        .tempfile_in(install_root)
        .context("Cannot create private staged executable")?;
    file.as_file_mut().write_all(verified.verified_binary())?;
    file.as_file_mut().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o500))?;
    }
    file.persist_noclobber(&target)
        .context("Cannot install staged executable without overwrite")?;
    #[cfg(unix)]
    fs::File::open(install_root)
        .and_then(|dir| dir.sync_all())
        .context("Cannot sync staging directory")?;
    let staged = read_bounded(&target, MAX_SERVICE_BINARY_BYTES)?;
    let expected = Sha256::digest(verified.verified_binary());
    let actual = Sha256::digest(&staged);
    ensure!(
        actual.as_slice().ct_eq(expected.as_slice()).unwrap_u8() == 1,
        "Staged executable differs from signed snapshot"
    );
    Ok(target)
}

/// An unresolved marker is a fail-closed latch, NOT a recovery instruction.
/// Never auto-restore a binary by interpreting untrusted on-disk path strings.
fn refuse_unresolved_update(install_root: &Path) -> Result<()> {
    match fs::symlink_metadata(install_root.join(PENDING_MARKER)) {
        Ok(_) => bail!("Unresolved service-update transaction; manual recovery required"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("Cannot inspect pending service-update marker"),
    }
}

/// @dev-id TAV-UPDATE-PENDING-010
/// @purpose Persist intent before an adapter can change the OS service.
/// @reason A process crash must not silently allow a second transaction.
/// @contract Creates a new, synchronized operator-only record; it is never
/// used as authority to activate, restore, or accept a service binary.
fn record_pending_update(
    install_root: &Path,
    previous: &Path,
    candidate: &Path,
    verified: &VerifiedServiceUpdate,
) -> Result<()> {
    let previous = previous
        .to_str()
        .context("Non-UTF8 previous service path not supported by pending record")?;
    let candidate = candidate
        .to_str()
        .context("Non-UTF8 candidate path not supported by pending record")?;
    let record = serde_json::json!({
        "schema": "turkuazav.service-update-pending.v2",
        "sequence": verified.sequence(),
        "manifestSha256": hex::encode(verified.manifest_fingerprint()),
        "previousBinary": previous,
        "candidateBinary": candidate,
        "candidateSize": verified.verified_binary().len() as u64,
        "candidateSha256": hex::encode(Sha256::digest(verified.verified_binary())),
    })
    .to_string();
    ensure!(
        record.len() <= MAX_PENDING_RECORD_BYTES,
        "Service-update pending record too large"
    );

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(install_root.join(PENDING_MARKER))
        .context("Cannot create protected pending update record")?;
    file.write_all(record.as_bytes())?;
    file.sync_all()?;
    #[cfg(unix)]
    fs::File::open(install_root)
        .and_then(|dir| dir.sync_all())
        .context("Cannot synchronize pending update directory")?;
    Ok(())
}

/// Only clear the latch after a known-good restoration or committed update.
/// A cleanup/sync error is ambiguous, so the caller must stop for reconciliation.
fn clear_pending_update(install_root: &Path) -> Result<()> {
    fs::remove_file(install_root.join(PENDING_MARKER))
        .context("Cannot clear pending service-update record")?;
    #[cfg(unix)]
    fs::File::open(install_root)
        .and_then(|dir| dir.sync_all())
        .context("Cannot synchronize cleared pending update directory")?;
    Ok(())
}

/// Compares staged bytes with a locally recorded digest, not with a trusted
/// publisher signature. Never treat a matching digest as authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingCandidateInspection {
    LegacyRecordWithoutDigest,
    Missing,
    MatchesRecordedDigest,
    DiffersFromRecordedDigest,
}

/// Diagnostic report only. Even a matching 40-byte record is NOT proof that
/// the service is running, healthy, or safe to restore; the pending latch must
/// never be cleared automatically from this result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingUpdateInspection {
    NoPending,
    NeedsManualReview {
        sequence: i64,
        version_record_matches_marker: bool,
        candidate_integrity: PendingCandidateInspection,
    },
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingUpdateRecord {
    schema: String,
    sequence: i64,
    #[serde(rename = "manifestSha256")]
    manifest_sha256: String,
    #[serde(rename = "previousBinary")]
    previous_binary: String,
    #[serde(rename = "candidateBinary")]
    candidate_binary: String,
    #[serde(rename = "candidateSize")]
    candidate_size: Option<u64>,
    #[serde(rename = "candidateSha256")]
    candidate_sha256: Option<String>,
}

fn safe_report_path(path: &Path) -> bool {
    path.is_absolute()
        && !path.components().any(|part| {
            matches!(
                part,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
}

/// @dev-id TAV-UPDATE-PENDING-020
/// @purpose Inspect an unresolved update without following journal paths.
/// @reason A broken or interrupted transaction needs safe operator diagnosis.
/// @contract Bounded strict-schema inspection; no service activation, path
/// execution, pending-marker deletion, or 40-byte state mutation. This is an
/// observation that may race a concurrent updater and is NOT a recovery grant.
pub fn inspect_pending_service_update(
    install_root: &Path,
    state_file: &Path,
) -> Result<PendingUpdateInspection> {
    let root_meta =
        fs::symlink_metadata(install_root).context("Cannot inspect update installation root")?;
    ensure!(
        safe_report_path(install_root) && root_meta.is_dir() && !is_reparse_or_symlink(&root_meta),
        "Unsafe update installation root"
    );
    check_state_path(install_root, state_file)?;
    let pending_path = install_root.join(PENDING_MARKER);
    match fs::symlink_metadata(&pending_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PendingUpdateInspection::NoPending);
        }
        Err(error) => return Err(error).context("Cannot inspect pending update record"),
        Ok(meta) => ensure!(
            meta.is_file()
                && !is_reparse_or_symlink(&meta)
                && meta.len() > 0
                && meta.len() <= MAX_PENDING_RECORD_BYTES as u64,
            "Invalid or redirected pending update record"
        ),
    }

    let bytes = read_bounded(&pending_path, MAX_PENDING_RECORD_BYTES)?;
    let record: PendingUpdateRecord =
        serde_json::from_slice(&bytes).context("Corrupt pending update record")?;
    let previous = Path::new(&record.previous_binary);
    let candidate = Path::new(&record.candidate_binary);
    ensure!(
        record.sequence > 0
            && record.manifest_sha256.len() == 64
            && record
                .manifest_sha256
                .bytes()
                .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
            && safe_report_path(previous)
            && safe_report_path(candidate)
            && previous != candidate
            && candidate == candidate_path(install_root, record.sequence),
        "Invalid pending update record fields"
    );
    let fingerprint = hex::decode(&record.manifest_sha256)?;

    // @dev-id TAV-UPDATE-PENDING-030
    // @purpose Versioned on-disk digest evidence for interrupted staging.
    // @reason Existing v1 markers must remain readable but cannot claim to
    // prove candidate integrity; newly written v2 records bind size and hash.
    let expected_candidate = match record.schema.as_str() {
        "turkuazav.service-update-pending.v1" => {
            ensure!(
                record.candidate_size.is_none() && record.candidate_sha256.is_none(),
                "Unexpected legacy pending digest fields"
            );
            None
        }
        "turkuazav.service-update-pending.v2" => {
            let size = record
                .candidate_size
                .context("Missing pending candidate size")?;
            let digest = record
                .candidate_sha256
                .as_deref()
                .context("Missing pending candidate digest")?;
            ensure!(
                size > 0
                    && size <= MAX_SERVICE_BINARY_BYTES as u64
                    && digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "Invalid pending candidate digest or size"
            );
            Some((size, hex::decode(digest)?))
        }
        _ => bail!("Unsupported pending update record schema"),
    };

    // These are diagnostic comparisons only; journal contents are not signed.
    // The exact versioned path is derived above, never used for execution.
    let candidate_integrity = match expected_candidate {
        None => PendingCandidateInspection::LegacyRecordWithoutDigest,
        Some((expected_size, digest)) => match fs::symlink_metadata(candidate) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                PendingCandidateInspection::Missing
            }
            Err(error) => return Err(error).context("Cannot inspect pending candidate"),
            Ok(meta) => {
                ensure!(
                    meta.is_file()
                        && !is_reparse_or_symlink(&meta)
                        && meta.len() <= MAX_SERVICE_BINARY_BYTES as u64,
                    "Unsafe pending candidate"
                );
                if meta.len() != expected_size {
                    PendingCandidateInspection::DiffersFromRecordedDigest
                } else {
                    let bytes = read_bounded(candidate, MAX_SERVICE_BINARY_BYTES)?;
                    let actual = Sha256::digest(&bytes);
                    if bytes.len() as u64 == expected_size
                        && actual.as_slice().ct_eq(&digest).unwrap_u8() == 1
                    {
                        PendingCandidateInspection::MatchesRecordedDigest
                    } else {
                        PendingCandidateInspection::DiffersFromRecordedDigest
                    }
                }
            }
        },
    };

    // Compare only the persisted 40-byte record; the marker's claimed paths
    // are never opened or used as service activation / rollback authority.
    let matches_record = match fs::symlink_metadata(state_file) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error).context("Cannot inspect version state"),
        Ok(meta) => {
            ensure!(
                meta.is_file() && !is_reparse_or_symlink(&meta) && meta.len() == 40,
                "Invalid or redirected version state"
            );
            let bytes = fs::read(state_file).context("Cannot read version state")?;
            ensure!(bytes.len() == 40, "Corrupt version state");
            let saved_sequence = i64::from_le_bytes(bytes[..8].try_into()?);
            ensure!(saved_sequence > 0, "Corrupt version sequence");
            saved_sequence == record.sequence && bytes[8..].ct_eq(&fingerprint).unwrap_u8() == 1
        }
    };
    Ok(PendingUpdateInspection::NeedsManualReview {
        sequence: record.sequence,
        version_record_matches_marker: matches_record,
        candidate_integrity,
    })
}

/// @dev-id TAV-UPDATE-TRANSACTION-010
/// @purpose Stage signed bytes, run an adapter health gate, then advance state.
/// @reason Downgrade protection may only be committed after service acceptance.
/// @contract In-process failures before commit attempt restore the previous
/// executable. Failed restore leaves the candidate for operator recovery.
/// Errors while committing the state have UNCERTAIN durability, so automatic
/// downgrade/rollback is forbidden at that point. An unresolved persistent
/// marker blocks subsequent updates after interruption but CANNOT restore a
/// service. This preview has NO complete durable
/// crash journal or real SCM/systemd adapter, and must not be used as a
/// production installer. Protected directory/account trust is caller-provided.
pub fn apply_verified_service_update(
    install_root: &Path,
    state_file: &Path,
    verified: &VerifiedServiceUpdate,
    service: &mut impl ServiceActivation,
) -> Result<CommittedServiceUpdate> {
    let _transaction_lock = lock_transaction(install_root)?;
    check_state_path(install_root, state_file)?;
    ensure!(
        state_file != candidate_path(install_root, verified.sequence()),
        "Update state path collides with service candidate"
    );
    refuse_unresolved_update(install_root)?;
    require_new_sequence(state_file, verified.sequence())?;
    let previous = service
        .current_binary()
        .context("Cannot identify prior service")?;
    regular_file(&previous)?;
    ensure!(
        state_file != previous,
        "Update state path collides with existing service executable"
    );
    let candidate = stage_verified(install_root, verified)?;
    // Record the pending switch before calling any platform activation hook.
    // If journal creation fails, no service activation has been attempted.
    record_pending_update(install_root, &previous, &candidate, verified)?;
    // The active path may be mutated by the OS/service process; the adapter
    // must verify an actual running process and is never allowed to claim a
    // malware verdict from this operation.
    let activation = service
        .activate(&candidate)
        .and_then(|()| service.check_health(&candidate));
    if let Err(error) = activation {
        if let Err(restore_error) = service.restore(&previous) {
            // Do not delete candidate when recovery failed: a live process may
            // still be executing it. Preserve evidence for operator repair.
            bail!(
                "Service activation failed ({error:#}); restore failed ({restore_error:#}); manual recovery required"
            );
        }
        fs::remove_file(&candidate).context("Restore succeeded but candidate cleanup failed")?;
        clear_pending_update(install_root)
            .context("Restored service but pending record cleanup needs reconciliation")?;
        return Err(error).context("Service activation rejected; previous service restored");
    }
    // No rollback after this point: accept_version can return an error AFTER
    // an atomic state replacement (e.g. failure syncing the parent directory).
    // The operator must reconcile service state and durable record manually.
    accept_version(
        state_file,
        verified.sequence(),
        verified.manifest_fingerprint(),
    )
    .context("Service accepted but version commit is uncertain; manual recovery required")?;
    clear_pending_update(install_root).context(
        "Service version accepted but pending record cleanup failed; manual recovery required",
    )?;
    Ok(CommittedServiceUpdate {
        sequence: verified.sequence(),
        version: verified.version().to_owned(),
        installed_binary: candidate,
    })
}
