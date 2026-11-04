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
    ensure!(path.is_absolute(), "Expected an absolute service executable");
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
    ensure!(state_file.is_absolute(), "Update state path must be absolute");
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

fn stage_verified(install_root: &Path, verified: &VerifiedServiceUpdate) -> Result<PathBuf> {
    let filename = if cfg!(windows) {
        format!("turkuazav-service-seq-{}.exe", verified.sequence())
    } else {
        format!("turkuazav-service-seq-{}", verified.sequence())
    };
    let target = install_root.join(filename);
    // A crash residue or concurrent installation must not be overwritten.
    ensure!(
        !target.exists() && fs::symlink_metadata(&target).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
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

/// @dev-id TAV-UPDATE-TRANSACTION-010
/// @purpose Stage signed bytes, run an adapter health gate, then advance state.
/// @reason Downgrade protection may only be committed after service acceptance.
/// @contract In-process failures before commit attempt restore the previous
/// executable. Failed restore leaves the candidate for operator recovery.
/// Errors while committing the state have UNCERTAIN durability, so automatic
/// downgrade/rollback is forbidden at that point. This preview has NO durable
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
    require_new_sequence(state_file, verified.sequence())?;
    let previous = service.current_binary().context("Cannot identify prior service")?;
    regular_file(&previous)?;
    let candidate = stage_verified(install_root, verified)?;
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
    Ok(CommittedServiceUpdate {
        sequence: verified.sequence(),
        version: verified.version().to_owned(),
        installed_binary: candidate,
    })
}
