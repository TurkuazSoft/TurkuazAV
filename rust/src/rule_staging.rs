// Dosya Yolu: REPO_ROOT/rust/src/rule_staging.rs
// Amac: Imzali YARA-X kural adaylarini etkin pakete dokunmadan hazirla
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: Gecici snapshot, imza/motor kontrolu ve yazilmayan rollback denetimi
// Bagimli Oldugu Katman: Service | Tool | Config

use crate::{
    config, desktop_rules::inspect_version_snapshot, rules, scan, trusted, TrustedKeyring,
};
use anyhow::{ensure, Context, Result};
#[cfg(unix)]
use std::fs::File;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path},
};
use tempfile::{Builder, TempDir};

/// Inputs must originate from an independently authorized publisher keyring.
/// Staging is intentionally separate from active-rule installation or selection.
pub struct RuleCandidatePaths<'a> {
    pub rules: &'a Path,
    pub manifest: &'a Path,
    pub signature: &'a Path,
    pub engine: &'a Path,
    pub version_state: &'a Path,
}

/// An uncommitted temporary snapshot. Drop removes the staging directory on
/// an ordinary shutdown. Process crashes may leave stale temp directories;
/// neither this type nor its paths authorize production activation.
pub struct StagedRuleCandidate {
    directory: TempDir,
    pub sequence: i64,
    pub publisher_key_id: String,
}

impl StagedRuleCandidate {
    pub fn rules(&self) -> std::path::PathBuf {
        self.directory.path().join("rules.yar")
    }

    pub fn manifest(&self) -> std::path::PathBuf {
        self.directory.path().join("manifest.json")
    }

    pub fn signature(&self) -> std::path::PathBuf {
        self.directory.path().join("rules.sig")
    }

    pub fn directory(&self) -> &Path {
        self.directory.path()
    }
}

fn write_new_snapshot(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("Cannot create staged rule component")?;
    file.write_all(bytes)
        .context("Cannot write staged rule component")?;
    file.sync_all()
        .context("Cannot sync staged rule component")?;
    Ok(())
}

/// @dev-id TAV-RULE-STAGING-001
/// @purpose Stage verified rule bytes without overwriting active rules.
/// @contract Signed manifest/rules, pinned engine and advisory rollback
/// snapshot must validate; no engine execution, update activation, version
/// state write, unsigned key import, deletion or permanent install.
/// This is NOT a production updater. Only a separately privileged, audited
/// transaction with locking/ACLs and crash recovery may activate a candidate.
pub fn stage_signed_rule_candidate(
    inputs: RuleCandidatePaths<'_>,
    trusted_keys: &TrustedKeyring,
    staging_parent: &Path,
) -> Result<StagedRuleCandidate> {
    for path in [
        inputs.rules,
        inputs.manifest,
        inputs.signature,
        inputs.engine,
        inputs.version_state,
        staging_parent,
    ] {
        ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
            "Rule candidate paths must be absolute without traversal"
        );
    }
    let meta = fs::symlink_metadata(staging_parent).context("Staging root must exist")?;
    ensure!(
        meta.is_dir() && !scan::is_reparse_or_symlink(&meta),
        "Staging root must be a normal directory"
    );
    let engine_meta = fs::symlink_metadata(inputs.engine).context("Missing YARA-X engine")?;
    ensure!(
        engine_meta.is_file()
            && !scan::is_reparse_or_symlink(&engine_meta)
            && engine_meta.len() <= config::MAX_ENGINE_BYTES,
        "Invalid YARA-X engine"
    );
    // Checking the engine does not run it or grant trust to a package.
    rules::verify_engine(inputs.engine)?;
    // Bounded reads reject symlinks/reparse paths. The *staged* copies are
    // verified after writing: source file mutation cannot alter a returned
    // candidate, and mixed mutable-source snapshots fail signature checks.
    let rules_bytes = scan::read_bounded(inputs.rules, config::MAX_RULE_BYTES)?;
    let manifest_bytes = scan::read_bounded(inputs.manifest, config::MAX_MANIFEST_BYTES)?;
    let signature_bytes = scan::read_bounded(inputs.signature, config::MAX_SIGNATURE_BYTES)?;

    let stage = Builder::new()
        .prefix(".tav-rule-candidate-")
        .tempdir_in(staging_parent)
        .context("Cannot create isolated rule candidate directory")?;
    write_new_snapshot(&stage.path().join("rules.yar"), &rules_bytes)?;
    write_new_snapshot(&stage.path().join("manifest.json"), &manifest_bytes)?;
    write_new_snapshot(&stage.path().join("rules.sig"), &signature_bytes)?;
    #[cfg(unix)]
    File::open(stage.path())
        .and_then(|directory| directory.sync_all())
        .context("Cannot sync candidate directory")?;
    let verified = trusted::verify_package(
        &stage.path().join("rules.yar"),
        &stage.path().join("manifest.json"),
        &stage.path().join("rules.sig"),
        trusted_keys,
    )?;
    // An advisory snapshot cannot replace the locked 40-byte accept_version
    // check and could race another writer. It must never create state.
    inspect_version_snapshot(
        inputs.version_state,
        verified.sequence,
        &verified.manifest_fingerprint,
    )?;
    Ok(StagedRuleCandidate {
        directory: stage,
        sequence: verified.sequence,
        publisher_key_id: verified.publisher_key_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_inputs_do_not_touch_existing_active_or_state_files() {
        let temp = tempfile::tempdir().unwrap();
        let staging = temp.path().join("staging");
        fs::create_dir(&staging).unwrap();
        let rules = temp.path().join("rules.yar");
        let manifest = temp.path().join("manifest.json");
        let signature = temp.path().join("rules.sig");
        let engine = temp.path().join("yr");
        let state = temp.path().join("state.bin");
        fs::write(&rules, b"active original rules").unwrap();
        fs::write(&manifest, b"invalid manifest").unwrap();
        fs::write(&signature, b"invalid signature").unwrap();
        fs::write(&engine, b"not an official YARA-X engine").unwrap();
        fs::write(&state, b"preserve-me").unwrap();
        let keyring = TrustedKeyring::from_pinned_pem(Vec::new()).unwrap();
        let inputs = RuleCandidatePaths {
            rules: &rules,
            manifest: &manifest,
            signature: &signature,
            engine: &engine,
            version_state: &state,
        };
        assert!(stage_signed_rule_candidate(inputs, &keyring, &staging).is_err());
        assert_eq!(fs::read(&rules).unwrap(), b"active original rules");
        assert_eq!(fs::read(&state).unwrap(), b"preserve-me");
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_staging_root_is_rejected() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("real");
        fs::create_dir(&root).unwrap();
        let linked = temp.path().join("linked");
        symlink(&root, &linked).unwrap();
        let empty_ring = TrustedKeyring::from_pinned_pem(Vec::new()).unwrap();
        let path = temp.path().join("absent");
        let input = RuleCandidatePaths {
            rules: &path,
            manifest: &path,
            signature: &path,
            engine: &path,
            version_state: &path,
        };
        assert!(stage_signed_rule_candidate(input, &empty_ring, &linked).is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    }
}
