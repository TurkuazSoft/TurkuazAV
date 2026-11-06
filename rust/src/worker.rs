// Dosya Yolu: REPO_ROOT/rust/src/worker.rs
// Amac: Sinirli tarama koordinatörünü denetlenen arka plan iscisine bagla
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: Tek isci, kooperatif durdurma, saglik durumu ve hata geri denemesi
// Bagimli Oldugu Katman: Service | Tool | Config

use crate::{monitor::DirectoryObserver, service::ScanCoordinator};
use anyhow::{bail, ensure, Context, Result};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const MAX_INTERVAL: Duration = Duration::from_secs(60);
const MIN_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerPhase {
    Starting,
    Idle,
    Scanning,
    Degraded,
    Stopped,
    Panicked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerFault {
    ScanIncomplete,
    ThreadPanicked,
}

/// No paths, raw events, digests or exception bodies are retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerHealth {
    pub phase: WorkerPhase,
    pub successful_scans: u64,
    pub failed_scans: u64,
    pub observed_changes: u64,
    pub last_batch_changes: usize,
    pub last_fault: Option<WorkerFault>,
}

struct Shared {
    signal: crate::service::ReconcileSignal,
    health: Mutex<WorkerHealth>,
    wake: Condvar,
    stopping: AtomicBool,
    cancelled: AtomicBool,
}

/// Owns exactly one worker thread. This does NOT install a Windows Service,
/// systemd unit, daemon, privilege boundary or a malware protection hook.
pub struct SupervisedScanWorker {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
}

impl SupervisedScanWorker {
    /// @dev-id TAV-WORKER-010
    /// @purpose Start one read-only worker on a validated, already-baselined root.
    /// @reason Avoid spawning a thread per untrusted filesystem notification.
    /// @contract An OS service does not start automatically. Stop is cooperative.
    pub fn start(
        observer: DirectoryObserver,
        interval: Duration,
        retry_delay: Duration,
    ) -> Result<Self> {
        ensure!(
            (MIN_INTERVAL..=MAX_INTERVAL).contains(&interval),
            "Invalid worker polling interval"
        );
        ensure!(
            (MIN_INTERVAL..=MAX_INTERVAL).contains(&retry_delay),
            "Invalid worker retry interval"
        );

        let coordinator = ScanCoordinator::new(observer);
        let health = WorkerHealth {
            phase: WorkerPhase::Starting,
            successful_scans: 0,
            failed_scans: 0,
            observed_changes: 0,
            last_batch_changes: 0,
            last_fault: None,
        };
        let shared = Arc::new(Shared {
            signal: coordinator.signal(),
            health: Mutex::new(health),
            wake: Condvar::new(),
            stopping: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        });
        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("turkuazav-scan-worker".into())
            .spawn(move || run_worker(coordinator, worker_shared, interval, retry_delay))
            .context("Cannot start scan worker")?;
        Ok(Self {
            shared,
            worker: Some(worker),
        })
    }

    /// Returns false if a request is already pending or shutdown has started.
    pub fn request(&self) -> bool {
        let health = self.shared.health.lock().unwrap();
        if self.shared.stopping.load(Ordering::Acquire)
            || matches!(health.phase, WorkerPhase::Stopped | WorkerPhase::Panicked)
        {
            return false;
        }
        let accepted = self.shared.signal.request();
        self.shared.wake.notify_all();
        accepted
    }

    pub fn health(&self) -> WorkerHealth {
        let mut snapshot = *self.shared.health.lock().unwrap();
        if self
            .worker
            .as_ref()
            .is_some_and(|handle| handle.is_finished())
            && snapshot.phase != WorkerPhase::Stopped
        {
            snapshot.phase = WorkerPhase::Panicked;
            snapshot.last_fault = Some(WorkerFault::ThreadPanicked);
        }
        snapshot
    }

    /// Waits for an observed successful complete scan (not a malware verdict).
    pub fn wait_for_success(&self, at_least: u64, timeout: Duration) -> Result<WorkerHealth> {
        let health = self.shared.health.lock().unwrap();
        let (health, _) = self
            .shared
            .wake
            .wait_timeout_while(health, timeout, |state| {
                state.successful_scans < at_least
                    && !self.shared.stopping.load(Ordering::Acquire)
                    && !matches!(state.phase, WorkerPhase::Stopped | WorkerPhase::Panicked)
            })
            .unwrap();
        if health.successful_scans < at_least {
            bail!("Worker did not complete required scans");
        }
        Ok(*health)
    }

    /// @dev-id TAV-WORKER-020
    /// @purpose Cancel in-flight hashing and join the owned thread on shutdown.
    /// @reason Avoid detached workers and use-after-shutdown event processing.
    /// @contract Cooperative cancellation cannot bound a hung filesystem read.
    pub fn stop(mut self) -> Result<WorkerHealth> {
        self.join_worker()?;
        Ok(self.health())
    }

    fn join_worker(&mut self) -> Result<()> {
        self.shared.stopping.store(true, Ordering::Release);
        self.shared.cancelled.store(true, Ordering::Release);
        self.shared.wake.notify_all();
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                let mut health = self.shared.health.lock().unwrap();
                health.phase = WorkerPhase::Panicked;
                health.last_fault = Some(WorkerFault::ThreadPanicked);
                self.shared.wake.notify_all();
                bail!("Scan worker terminated unexpectedly");
            }
        }
        Ok(())
    }
}

impl Drop for SupervisedScanWorker {
    fn drop(&mut self) {
        let _ = self.join_worker();
    }
}

fn run_worker(
    mut coordinator: ScanCoordinator,
    shared: Arc<Shared>,
    interval: Duration,
    retry_delay: Duration,
) {
    {
        let mut health = shared.health.lock().unwrap();
        health.phase = WorkerPhase::Idle;
        shared.wake.notify_all();
    }
    let mut next_periodic = Instant::now() + interval;
    let mut retry_after: Option<Instant> = None;
    loop {
        let mut health = shared.health.lock().unwrap();
        if shared.stopping.load(Ordering::Acquire) {
            health.phase = WorkerPhase::Stopped;
            shared.wake.notify_all();
            return;
        }
        let now = Instant::now();
        if now >= next_periodic {
            shared.signal.request();
            next_periodic = now + interval;
        }
        if shared.signal.is_pending() && retry_after.is_none_or(|after| now >= after) {
            health.phase = WorkerPhase::Scanning;
            shared.wake.notify_all();
            drop(health);

            let result = coordinator.run_pending(&shared.cancelled);
            let mut health = shared.health.lock().unwrap();
            if shared.stopping.load(Ordering::Acquire) {
                health.phase = WorkerPhase::Stopped;
                shared.wake.notify_all();
                return;
            }
            match result {
                Ok(Some(changes)) => {
                    health.successful_scans = health.successful_scans.saturating_add(1);
                    health.observed_changes =
                        health.observed_changes.saturating_add(changes.len() as u64);
                    health.last_batch_changes = changes.len();
                    health.last_fault = None;
                    health.phase = WorkerPhase::Idle;
                    retry_after = None;
                }
                Ok(None) => {
                    health.phase = WorkerPhase::Idle;
                    retry_after = None;
                }
                Err(_) => {
                    health.failed_scans = health.failed_scans.saturating_add(1);
                    health.last_fault = Some(WorkerFault::ScanIncomplete);
                    health.phase = WorkerPhase::Degraded;
                    retry_after = Some(Instant::now() + retry_delay);
                }
            }
            shared.wake.notify_all();
            continue;
        }
        let deadline = match retry_after {
            Some(retry) if shared.signal.is_pending() => next_periodic.min(retry),
            _ => next_periodic,
        };
        let duration = deadline.saturating_duration_since(now);
        let (health, _) = shared.wake.wait_timeout(health, duration).unwrap();
        drop(health);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MAX_FILE_SIZE;
    use std::{fs, path::Path};

    fn start_worker(root: &Path) -> SupervisedScanWorker {
        let observer = DirectoryObserver::new(root, &AtomicBool::new(false)).unwrap();
        SupervisedScanWorker::start(
            observer,
            Duration::from_secs(10),
            Duration::from_millis(100),
        )
        .unwrap()
    }

    #[test]
    fn foreground_request_runs_without_persisting_any_path() {
        let temp = tempfile::tempdir().unwrap();
        let worker = start_worker(temp.path());
        let file = temp.path().join("eklenen.txt");
        fs::write(&file, b"hello").unwrap();
        assert!(worker.request());
        let health = worker.wait_for_success(1, Duration::from_secs(5)).unwrap();
        assert_eq!(health.observed_changes, 1);
        assert_eq!(health.last_batch_changes, 1);
        assert_eq!(health.phase, WorkerPhase::Idle);
        assert_eq!(health.last_fault, None);
        let stopped = worker.stop().unwrap();
        assert_eq!(stopped.phase, WorkerPhase::Stopped);
    }

    #[test]
    fn failed_inventory_degrades_and_retries_after_repair() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("sample");
        fs::write(&file, b"original").unwrap();
        let worker = start_worker(temp.path());
        fs::File::create(&file)
            .unwrap()
            .set_len(MAX_FILE_SIZE + 1)
            .unwrap();
        worker.request();
        let deadline = Instant::now() + Duration::from_secs(5);
        while worker.health().failed_scans == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let degraded = worker.health();
        assert!(degraded.failed_scans >= 1);
        assert_eq!(degraded.phase, WorkerPhase::Degraded);
        fs::write(&file, b"repaired").unwrap();
        let restored = worker.wait_for_success(1, Duration::from_secs(5)).unwrap();
        assert!(restored.observed_changes >= 1);
        assert_eq!(restored.phase, WorkerPhase::Idle);
        assert_eq!(restored.last_fault, None);
        worker.stop().unwrap();
    }

    #[test]
    fn worker_shutdown_rejects_future_scans_and_joins() {
        let temp = tempfile::tempdir().unwrap();
        let worker = start_worker(temp.path());
        worker.request();
        let stopped = worker.stop().unwrap();
        assert_eq!(stopped.phase, WorkerPhase::Stopped);
    }

    #[test]
    fn invalid_or_unbounded_intervals_fail_before_thread_creation() {
        let temp = tempfile::tempdir().unwrap();
        let observer = DirectoryObserver::new(temp.path(), &AtomicBool::new(false)).unwrap();
        assert!(SupervisedScanWorker::start(
            observer,
            Duration::from_millis(1),
            Duration::from_secs(1)
        )
        .is_err());
    }

    #[test]
    fn periodic_rescan_works_without_new_notifications() {
        let temp = tempfile::tempdir().unwrap();
        let observer = DirectoryObserver::new(temp.path(), &AtomicBool::new(false)).unwrap();
        let worker = SupervisedScanWorker::start(
            observer,
            Duration::from_millis(100),
            Duration::from_millis(100),
        )
        .unwrap();
        let status = worker.wait_for_success(1, Duration::from_secs(5)).unwrap();
        assert!(status.successful_scans >= 1);
        worker.stop().unwrap();
    }
}
