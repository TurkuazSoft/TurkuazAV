// Dosya Yolu: REPO_ROOT/rust/src/rule_publication.rs
// Amac: Dogrulanmis kural adayini etkin kurallari ezmeden surumlu alana yaz
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: No-clobber candidate reservation, reverify, read-only state ve READY isareti
// Bagimli Oldugu Katman: Service | Repository | Tool

use crate::{
    config, desktop_rules::inspect_version_snapshot, rule_staging::StagedRuleCandidate, rules,
    scan, trusted, TrustedKeyring,
};
use anyhow::{ensure, Context, Result};
#[cfg(unix)]
use std::fs::File;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};

const READY_MARKER: &str = "CANDIDATE_READY";
const READY_CONTENT: &[u8] = b"uncommitted-candidate-only\n";

/// Location is caller-selected and MUST be access-controlled by a future
/// privileged installer. The API does not select active rules or alter state.
pub struct CandidatePublicationPaths<'a> {
    pub repository_root: &'a Path,
    pub engine: &'a Path,
    pub version_state: &'a Path,
}

/// A persisted candidate is not an authorized active version. Re-validate
/// signed bytes and the protected 40-byte state before any future activation.
pub struct PublishedRuleCandidate {
    directory: PathBuf,
    pub sequence: i64,
    pub publisher_key_id: String,
}

impl PublishedRuleCandidate {
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn rules(&self) -> PathBuf {
        self.directory.join("rules.yar")
    }

    pub fn manifest(&self) -> PathBuf {
        self.directory.join("manifest.json")
    }

    pub fn signature(&self) -> PathBuf {
        self.directory.join("rules.sig")
    }
}

fn validate_regular_directory(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir)),
        "Candidate publication requires an absolute path without traversal"
    );
    let meta = fs::symlink_metadata(path).context("Candidate publication directory is missing")?;
    ensure!(
        meta.is_dir() && !scan::is_reparse_or_symlink(&meta),
        "Candidate publication directory must not be redirected"
    );
    Ok(())
}

fn write_new_component(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("Cannot reserve new candidate file")?;
    file.write_all(bytes)
        .context("Cannot write candidate file")?;
    file.sync_all()
        .context("Cannot synchronize candidate file")?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .context("Cannot synchronize candidate directory")
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    // Windows file data is synced; durable directory metadata still requires
    // an OS-specific publish transaction before claiming crash safety.
    Ok(())
}

/// @dev-id TAV-RULE-PUBLICATION-001
/// @purpose Reserve a NEW versioned candidate without replacing active rules.
/// @contract The directory is reserved using create_dir (never rename-overwrite).
/// The signed staged bytes, publisher identity, pinned engine and advisory
/// version state are checked again. READY is written LAST and is only a hint.
/// No activation, anti-rollback commit, service restart, unattended cleanup,
/// or release signing is performed. A failed write may leave an incomplete
/// directory without READY; a future attempt must refuse to overwrite it.
pub fn publish_verified_rule_candidate(
    staged: &StagedRuleCandidate,
    trusted_keys: &TrustedKeyring,
    paths: CandidatePublicationPaths<'_>,
) -> Result<PublishedRuleCandidate> {
    validate_regular_directory(paths.repository_root)?;
    validate_regular_directory(staged.directory())?;
    ensure!(
        !paths.repository_root.starts_with(staged.directory())
            && !staged.directory().starts_with(paths.repository_root),
        "Candidate publication and staging roots must be disjoint"
    );
    for path in [paths.engine, paths.version_state] {
        ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
                && !path.starts_with(paths.repository_root),
            "Engine and version state must be outside candidate publication"
        );
    }
    let engine_meta = fs::symlink_metadata(paths.engine).context("Pinned engine missing")?;
    ensure!(
        engine_meta.is_file()
            && !scan::is_reparse_or_symlink(&engine_meta)
            && engine_meta.len() <= config::MAX_ENGINE_BYTES,
        "Invalid pinned YARA-X engine"
    );
    rules::verify_engine(paths.engine)?;
    let source = trusted::verify_package(
        &staged.rules(),
        &staged.manifest(),
        &staged.signature(),
        trusted_keys,
    )?;
    ensure!(
        source.sequence == staged.sequence && source.publisher_key_id == staged.publisher_key_id,
        "Staged candidate identity changed"
    );
    inspect_version_snapshot(
        paths.version_state,
        source.sequence,
        &source.manifest_fingerprint,
    )?;

    let name = format!(
        "candidate-v{}-{}",
        source.sequence,
        hex::encode(source.manifest_fingerprint)
    );
    let destination = paths.repository_root.join(name);
    // create_dir fails if the name already exists (file, directory or link).
    // Do NOT use rename: Unix rename may overwrite an existing empty directory.
    fs::create_dir(&destination)
        .context("Candidate version already exists or cannot be reserved")?;

    // After reserving, copy exactly the bounded inputs and re-verify the
    // published snapshot before creating a completion hint. Never reuse
    // verification of mutable staging paths as final publication authority.
    let rules_bytes = scan::read_bounded(&staged.rules(), config::MAX_RULE_BYTES)?;
    let manifest_bytes = scan::read_bounded(&staged.manifest(), config::MAX_MANIFEST_BYTES)?;
    let signature_bytes = scan::read_bounded(&staged.signature(), config::MAX_SIGNATURE_BYTES)?;
    write_new_component(&destination.join("rules.yar"), &rules_bytes)?;
    write_new_component(&destination.join("manifest.json"), &manifest_bytes)?;
    write_new_component(&destination.join("rules.sig"), &signature_bytes)?;
    sync_directory(&destination)?;

    let published = trusted::verify_package(
        &destination.join("rules.yar"),
        &destination.join("manifest.json"),
        &destination.join("rules.sig"),
        trusted_keys,
    )?;
    ensure!(
        published.sequence == source.sequence
            && published.publisher_key_id == source.publisher_key_id
            && published.manifest_fingerprint == source.manifest_fingerprint,
        "Published candidate differs from verified staging snapshot"
    );
    // This snapshot is advisory: activation must take the protected state
    // lock, re-check and only then make an atomic durable state transition.
    inspect_version_snapshot(
        paths.version_state,
        published.sequence,
        &published.manifest_fingerprint,
    )?;
    write_new_component(&destination.join(READY_MARKER), READY_CONTENT)?;
    sync_directory(&destination)?;
    sync_directory(paths.repository_root)?;
    Ok(PublishedRuleCandidate {
        directory: destination,
        sequence: published.sequence,
        publisher_key_id: published.publisher_key_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_root_must_be_existing_normal_directory() {
        let t = tempfile::tempdir().unwrap();
        let absent = t.path().join("absent");
        assert!(validate_regular_directory(&absent).is_err());
        validate_regular_directory(t.path()).unwrap();
        let regular = t.path().join("ordinary-file");
        fs::write(&regular, b"keep").unwrap();
        assert!(validate_regular_directory(&regular).is_err());
        assert_eq!(fs::read(&regular).unwrap(), b"keep");
    }

    #[cfg(unix)]
    #[test]
    fn linked_publication_root_is_rejected() {
        use std::os::unix::fs::symlink;
        let t = tempfile::tempdir().unwrap();
        let linked = t.path().join("linked");
        symlink(t.path(), &linked).unwrap();
        assert!(validate_regular_directory(&linked).is_err());
    }
}
