// Dosya Yolu: REPO_ROOT/rust/src/monitor.rs
// Amac: Salt-okunur, sinirli klasor degisim gozlemi
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: Polling tabanli snapshot farki; engelleme, karantina ve daemon yok
// Bagimli Oldugu Katman: Service | Repo | Config

use crate::{
    config::{MAX_MONITORED_FILES, MAX_FILE_SIZE},
    scan::{is_reparse_or_symlink, scan_path_each, ScanStatus},
};
use anyhow::{bail, Context, Result};
use std::{
    collections::BTreeMap,
    fs,
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Modified,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedChange {
    pub path: PathBuf,
    pub kind: ChangeKind,
    pub sha256: Option<String>,
}

/// In-memory, explicitly started polling only. This is not a filesystem
/// event source, virus verdict, background service or blocking security hook.
pub struct DirectoryObserver {
    root: PathBuf,
    baseline: BTreeMap<PathBuf, String>,
}

fn inventory(
    root: &Path,
    cancelled: &AtomicBool,
    max_files: usize,
) -> Result<BTreeMap<PathBuf, String>> {
    let mut files = BTreeMap::new();
    scan_path_each(root, cancelled, |item| {
        match item.status {
            ScanStatus::Hashed => {
                if files.len() >= max_files {
                    bail!("Observer file count limit exceeded");
                }
                let hash = item.sha256.context("Missing SHA-256 from successful scan")?;
                files.insert(item.path, hash);
            }
            // Skipped files are not covered; if a previously tracked file
            // becomes skipped, poll() will reject the incomplete snapshot.
            ScanStatus::Skipped => (),
            ScanStatus::Failed => bail!("Observer scan is incomplete"),
        }
        Ok(())
    })?;
    if cancelled.load(Ordering::Relaxed) {
        bail!("Observer cancelled");
    }
    Ok(files)
}

impl DirectoryObserver {
    pub fn new(root: &Path, cancelled: &AtomicBool) -> Result<Self> {
        let metadata = fs::symlink_metadata(root).context("Observer root unavailable")?;
        if is_reparse_or_symlink(&metadata) || !metadata.is_dir() {
            bail!("Observer requires a real directory root");
        }
        let root = fs::canonicalize(root).context("Cannot resolve observer root")?;
        let baseline = inventory(&root, cancelled, MAX_MONITORED_FILES)?;
        Ok(Self { root, baseline })
    }

    pub fn tracked_files(&self) -> usize {
        self.baseline.len()
    }

    /// Failed, cancelled, oversized or inaccessible polls do NOT mutate the
    /// accepted baseline. A lost previously tracked file that still exists
    /// cannot be misreported as a legitimate deletion.
    pub fn poll(&mut self, cancelled: &AtomicBool) -> Result<Vec<ObservedChange>> {
        let current = inventory(&self.root, cancelled, MAX_MONITORED_FILES)?;
        let mut changes = Vec::new();

        for (path, digest) in &current {
            let kind = match self.baseline.get(path) {
                None => Some(ChangeKind::Added),
                Some(previous) if previous != digest => Some(ChangeKind::Modified),
                Some(_) => None,
            };
            if let Some(kind) = kind {
                changes.push(ObservedChange {
                    path: path.clone(),
                    kind,
                    sha256: Some(digest.clone()),
                });
            }
        }
        for path in self.baseline.keys() {
            if current.contains_key(path) {
                continue;
            }
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    changes.push(ObservedChange {
                        path: path.clone(),
                        kind: ChangeKind::Removed,
                        sha256: None,
                    });
                }
                // Previously tracked regular files might now be skipped,
                // oversized, inaccessible or behind a reparse directory.
                // Never turn lost visibility into a misleading deletion.
                Ok(_) => bail!("Previously monitored file is no longer scannable"),
                Err(error) => return Err(error).context("Cannot verify removed file"),
            }
        }
        if cancelled.load(Ordering::Relaxed) {
            bail!("Observer cancelled");
        }
        changes.sort_by(|a, b| a.path.cmp(&b.path));
        self.baseline = current;
        Ok(changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_change_detection_and_no_initial_events() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("ilk.txt");
        fs::write(&first, b"first").unwrap();
        let cancelled = AtomicBool::new(false);
        let mut observer = DirectoryObserver::new(temp.path(), &cancelled).unwrap();
        assert_eq!(observer.tracked_files(), 1);
        assert!(observer.poll(&cancelled).unwrap().is_empty());

        fs::write(&first, b"updated").unwrap();
        let changed = observer.poll(&cancelled).unwrap();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].kind, ChangeKind::Modified);
        assert_eq!(changed[0].path, first);
        assert!(changed[0].sha256.is_some());

        let second = temp.path().join("ikinci.txt");
        fs::write(&second, b"second").unwrap();
        let added = observer.poll(&cancelled).unwrap();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].kind, ChangeKind::Added);
        assert_eq!(added[0].path, second);

        fs::remove_file(&second).unwrap();
        let removed = observer.poll(&cancelled).unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].kind, ChangeKind::Removed);
        assert_eq!(removed[0].path, second);
        assert!(removed[0].sha256.is_none());
        assert!(observer.poll(&cancelled).unwrap().is_empty());
    }

    #[test]
    fn failure_and_cancel_preserve_previous_baseline() {
        let temp = tempfile::tempdir().unwrap();
        let tracked = temp.path().join("file");
        fs::write(&tracked, b"original").unwrap();
        let cancelled = AtomicBool::new(false);
        let mut observer = DirectoryObserver::new(temp.path(), &cancelled).unwrap();

        FileSize::make_oversized(&tracked);
        assert!(observer.poll(&cancelled).is_err());
        assert_eq!(observer.tracked_files(), 1);
        fs::write(&tracked, b"new contents").unwrap();

        let stopped = AtomicBool::new(true);
        assert!(observer.poll(&stopped).is_err());
        let changes = observer.poll(&cancelled).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ChangeKind::Modified);
    }

    struct FileSize;
    impl FileSize {
        fn make_oversized(path: &Path) {
            fs::OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap()
                .set_len(MAX_FILE_SIZE + 1)
                .unwrap();
        }
    }

    #[test]
    fn file_inventory_limit_aborts_instead_of_truncating() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("a"), b"1").unwrap();
        fs::write(temp.path().join("b"), b"2").unwrap();
        assert!(inventory(temp.path(), &AtomicBool::new(false), 1).is_err());
    }

    #[test]
    fn deleted_monitor_root_must_not_emit_fake_removals() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("example"), b"abc").unwrap();
        let cancelled = AtomicBool::new(false);
        let mut observer = DirectoryObserver::new(&root, &cancelled).unwrap();
        fs::remove_dir_all(&root).unwrap();
        assert!(observer.poll(&cancelled).is_err());
        assert_eq!(observer.tracked_files(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn new_symlink_outside_root_is_never_hashed() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("inside");
        let outside = temp.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret"), b"private").unwrap();
        let cancelled = AtomicBool::new(false);
        let mut observer = DirectoryObserver::new(&root, &cancelled).unwrap();
        symlink(&outside, root.join("link")).unwrap();
        assert!(observer.poll(&cancelled).unwrap().is_empty());
        assert_eq!(observer.tracked_files(), 0);
    }
}
