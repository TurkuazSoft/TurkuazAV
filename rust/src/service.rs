// Dosya Yolu: REPO_ROOT/rust/src/service.rs
// Amac: Olay tetiklemelerini sinirli ve iptal edilebilir tarama islerine donustur
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: Tek yuvali, kayipsiz yeniden tarama sinyali; OS servisi degil
// Bagimli Oldugu Katman: Service | Tool

use crate::monitor::{DirectoryObserver, ObservedChange};
use anyhow::{bail, Result};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

/// A one-slot work request. Every accepted hint means "reconcile the entire
/// trusted root"; raw OS paths never become an authority to scan arbitrary
/// locations. Multiple hints can share one pending full-tree reconciliation.
#[derive(Clone)]
pub struct ReconcileSignal {
    pending: Arc<AtomicBool>,
}

impl ReconcileSignal {
    /// @dev-id TAV-QUEUE-010
    /// @purpose Coalesce concurrent OS hints into one bounded root-scoped work item.
    /// @reason OS notifications can be duplicated or flooded by untrusted actors.
    /// @contract No paths, payloads, or per-event allocations enter the queue.
    pub fn request(&self) -> bool {
        !self.pending.swap(true, Ordering::AcqRel)
    }

    pub fn is_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }
}

/// A service-core boundary, NOT a Windows Service, systemd unit, daemon,
/// privilege boundary, sandbox, malware verdict, or automatic background job.
pub struct ScanCoordinator {
    observer: DirectoryObserver,
    signal: ReconcileSignal,
}

impl ScanCoordinator {
    pub fn new(observer: DirectoryObserver) -> Self {
        Self {
            observer,
            signal: ReconcileSignal {
                pending: Arc::new(AtomicBool::new(false)),
            },
        }
    }

    pub fn root(&self) -> &Path {
        self.observer.root()
    }

    pub fn tracked_files(&self) -> usize {
        self.observer.tracked_files()
    }

    pub fn signal(&self) -> ReconcileSignal {
        self.signal.clone()
    }

    /// @dev-id TAV-QUEUE-020
    /// @purpose Reconcile a pending root-scoped request with the trusted snapshot.
    /// @reason Failures and cancellation must not silently discard scan work.
    /// @contract Any signal arriving during a scan remains pending for another
    /// reconciliation; an unsuccessful scan re-queues its own work.
    pub fn run_pending(&mut self, cancelled: &AtomicBool) -> Result<Option<Vec<ObservedChange>>> {
        if cancelled.load(Ordering::Relaxed) {
            bail!("Scan coordination cancelled");
        }
        if !self.signal.pending.swap(false, Ordering::AcqRel) {
            return Ok(None);
        }
        match self.observer.poll(cancelled) {
            Ok(changes) => Ok(Some(changes)),
            Err(error) => {
                self.signal.pending.store(true, Ordering::Release);
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::ChangeKind;
    use std::{fs, sync::atomic::Ordering};

    #[test]
    fn event_storm_coalesces_into_one_bounded_work_item() {
        let temp = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let mut coordinator =
            ScanCoordinator::new(DirectoryObserver::new(temp.path(), &cancel).unwrap());
        let signal = coordinator.signal();
        assert!(!signal.is_pending());
        assert!(signal.request());
        for _ in 0..20_000 {
            assert!(!signal.request());
        }
        assert!(signal.is_pending());
        assert!(coordinator
            .run_pending(&cancel)
            .unwrap()
            .unwrap()
            .is_empty());
        assert!(!signal.is_pending());
        assert!(coordinator.run_pending(&cancel).unwrap().is_none());
    }

    #[test]
    fn lost_visibility_must_not_acknowledge_a_pending_request() {
        let temp = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let file = temp.path().join("observed");
        fs::write(&file, b"initial").unwrap();
        let mut coordinator =
            ScanCoordinator::new(DirectoryObserver::new(temp.path(), &cancel).unwrap());
        let signal = coordinator.signal();

        fs::File::create(&file)
            .unwrap()
            .set_len(crate::config::MAX_FILE_SIZE + 1)
            .unwrap();
        assert!(signal.request());
        assert!(coordinator.run_pending(&cancel).is_err());
        assert!(signal.is_pending());

        fs::write(&file, b"repaired").unwrap();
        let changes = coordinator.run_pending(&cancel).unwrap().unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ChangeKind::Modified);
        assert!(!signal.is_pending());
    }

    #[test]
    fn cancelled_request_stays_pending_until_success() {
        let temp = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let mut coordinator =
            ScanCoordinator::new(DirectoryObserver::new(temp.path(), &cancel).unwrap());
        let signal = coordinator.signal();
        signal.request();
        let stopped = AtomicBool::new(true);
        assert!(coordinator.run_pending(&stopped).is_err());
        assert!(signal.is_pending());
        assert!(coordinator.run_pending(&cancel).unwrap().is_some());
        assert!(!signal.is_pending());
    }

    #[test]
    fn independent_thread_can_request_followup_without_path_queue() {
        let temp = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let mut coordinator =
            ScanCoordinator::new(DirectoryObserver::new(temp.path(), &cancel).unwrap());
        let signal = coordinator.signal();
        assert!(signal.request());
        assert!(coordinator.run_pending(&cancel).unwrap().is_some());
        let worker = std::thread::spawn(move || {
            assert!(signal.request());
            signal.is_pending()
        });
        assert!(worker.join().unwrap());
        assert!(coordinator.run_pending(&cancel).unwrap().is_some());
    }

    #[test]
    fn cancellation_during_reconciliation_retains_work() {
        let temp = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let mut coordinator =
            ScanCoordinator::new(DirectoryObserver::new(temp.path(), &cancel).unwrap());
        let signal = coordinator.signal();
        signal.request();
        cancel.store(true, Ordering::Relaxed);
        assert!(coordinator.run_pending(&cancel).is_err());
        assert!(signal.is_pending());
        cancel.store(false, Ordering::Relaxed);
        assert!(coordinator.run_pending(&cancel).unwrap().is_some());
    }
}
