// Dosya Yolu: REPO_ROOT/rust/src/bin/service_host.rs
// Amac: Rust tarama iscisini Windows SCM veya Linux systemd icin barindir
// Modul - FileType: Tool - Rust
// Version: 0.3.1
// Aciklama: Yalnizca salt-okunur servis onizlemesi; kurulum veya koruma yok
// Bagimli Oldugu Katman: Tool | Service | Config

use anyhow::{bail, ensure, Context, Result};
use std::{
    env,
    ffi::{OsStr, OsString},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use turkuazav::{
    DirectoryObserver, NativeChangeWakeup, SupervisedScanWorker, WakeReason, WorkerPhase,
};

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
const MAX_INTERVAL_SECS: u64 = 60;
const WATCH_SLICE: Duration = Duration::from_millis(250);

#[derive(Clone)]
struct Settings {
    root: PathBuf,
    interval: Duration,
}

fn parse_settings(args: &[OsString]) -> Result<(&str, Settings)> {
    ensure!(
        args.len() == 3,
        "Expected <mode> <absolute-root> <interval-seconds>"
    );
    let mode = args[0].to_str().context("Invalid service host mode")?;
    ensure!(
        matches!(mode, "--once" | "--foreground" | "--scm"),
        "Unknown service host mode"
    );
    let input = Path::new(&args[1]);
    ensure!(input.is_absolute(), "Service root must be absolute");
    ensure!(
        !input
            .components()
            .any(|item| matches!(item, Component::ParentDir)),
        "Parent traversal not allowed in service root"
    );
    let meta = std::fs::symlink_metadata(input).context("Service root unavailable")?;
    ensure!(
        meta.is_dir() && !turkuazav::scan::is_reparse_or_symlink(&meta),
        "Service root must be a real directory"
    );
    let root = std::fs::canonicalize(input).context("Cannot resolve service root")?;
    let seconds: u64 = args[2]
        .to_str()
        .context("Invalid service interval")?
        .parse()
        .context("Invalid service interval")?;
    ensure!(
        (1..=MAX_INTERVAL_SECS).contains(&seconds),
        "Service interval outside safe bounds"
    );
    Ok((
        mode,
        Settings {
            root,
            interval: Duration::from_secs(seconds),
        },
    ))
}

/// @dev-id TAV-SVCHOST-010
/// @purpose Observe the validated root with one supervised worker.
/// @reason The OS notification is a hint, not a trusted per-file scan command.
/// @contract No privileges, persistent file writes or malware verdicts. A lost
/// native watcher or panicked worker exits nonzero for external supervision.
fn host_foreground(settings: &Settings, on_ready: impl FnOnce() -> Result<()>) -> Result<()> {
    let cancelled = AtomicBool::new(false);
    let observer = DirectoryObserver::new(&settings.root, &cancelled)?;
    let mut watch = NativeChangeWakeup::new(observer.root())?;
    let worker = SupervisedScanWorker::start(observer, settings.interval, settings.interval)?;
    on_ready()?;
    worker.request();
    let result = (|| -> Result<()> {
        let mut last_phase = WorkerPhase::Starting;
        while !STOP_REQUESTED.load(Ordering::Acquire) {
            match watch.wait(&STOP_REQUESTED, WATCH_SLICE) {
                Ok(WakeReason::ChangeHint) => {
                    worker.request();
                }
                Ok(WakeReason::Interval) => (),
                Err(_) if STOP_REQUESTED.load(Ordering::Acquire) => break,
                Err(error) => return Err(error),
            }
            let health = worker.health();
            if health.phase == WorkerPhase::Panicked || health.phase == WorkerPhase::Stopped {
                bail!("Service scan worker exited unexpectedly");
            }
            if health.phase != last_phase {
                if health.phase == WorkerPhase::Degraded {
                    eprintln!(
                        "SERVICE_HEALTH=DEGRADED failed_scans={}",
                        health.failed_scans
                    );
                } else if last_phase == WorkerPhase::Degraded {
                    println!(
                        "SERVICE_HEALTH=RECOVERED successful_scans={}",
                        health.successful_scans
                    );
                }
                last_phase = health.phase;
            }
        }
        Ok(())
    })();
    let stopped = worker.stop();
    result?;
    let health = stopped?;
    ensure!(
        health.phase == WorkerPhase::Stopped,
        "Worker did not stop cleanly"
    );
    Ok(())
}

fn run_once(settings: &Settings) -> Result<()> {
    let cancelled = AtomicBool::new(false);
    let observer = DirectoryObserver::new(&settings.root, &cancelled)?;
    let worker = SupervisedScanWorker::start(observer, settings.interval, settings.interval)?;
    worker.request();
    let result = worker.wait_for_success(1, Duration::from_secs(15));
    let stopped = worker.stop()?;
    result?;
    ensure!(
        stopped.phase == WorkerPhase::Stopped,
        "One-shot worker not stopped"
    );
    println!("SERVICE_ONCE=PASS version={}", env!("CARGO_PKG_VERSION"));
    Ok(())
}

#[cfg(target_os = "linux")]
mod signals {
    use super::*;
    use std::ffi::c_int;

    unsafe extern "C" {
        fn signal(number: c_int, handler: extern "C" fn(c_int)) -> usize;
    }

    extern "C" fn request_stop(_: c_int) {
        STOP_REQUESTED.store(true, Ordering::Release);
    }

    pub fn install() -> Result<()> {
        for number in [2, 15] {
            // SAFETY: signal() installs a process-global handler; the handler
            // only sets a lock-free atomic and does not allocate or lock.
            if unsafe { signal(number, request_stop) } == usize::MAX {
                return Err(std::io::Error::last_os_error())
                    .context("Cannot register Linux service signal");
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
mod console {
    use super::*;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }

    unsafe extern "system" fn on_control(code: u32) -> i32 {
        if matches!(code, 0 | 1 | 2 | 5 | 6) {
            STOP_REQUESTED.store(true, Ordering::Release);
            1
        } else {
            0
        }
    }

    pub fn install() -> Result<()> {
        // SAFETY: callback has the Win32 console handler ABI.
        if unsafe { SetConsoleCtrlHandler(Some(on_control), 1) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("Cannot register console control handler");
        }
        Ok(())
    }
}

#[cfg(windows)]
mod scm {
    use super::*;
    use std::{
        ffi::c_void,
        ptr,
        sync::{
            atomic::{AtomicPtr, AtomicU32},
            OnceLock,
        },
    };

    const NAME: &str = "TurkuazAVPreview";
    const OWN_PROCESS: u32 = 0x10;
    const STOPPED: u32 = 1;
    const START_PENDING: u32 = 2;
    const STOP_PENDING: u32 = 3;
    const RUNNING: u32 = 4;
    const ACCEPT_STOP: u32 = 1;
    const ACCEPT_SHUTDOWN: u32 = 4;
    const CONTROL_STOP: u32 = 1;
    const CONTROL_INTERROGATE: u32 = 4;
    const CONTROL_SHUTDOWN: u32 = 5;
    const NOT_IMPLEMENTED: u32 = 120;

    #[repr(C)]
    struct ServiceTableEntry {
        name: *const u16,
        entry: Option<unsafe extern "system" fn(u32, *mut *mut u16)>,
    }

    #[repr(C)]
    struct ServiceStatus {
        service_type: u32,
        state: u32,
        controls: u32,
        win32_exit_code: u32,
        service_exit_code: u32,
        checkpoint: u32,
        wait_hint: u32,
    }

    type Handle = *mut c_void;
    static SETTINGS: OnceLock<Settings> = OnceLock::new();
    static STATUS_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
    static SERVICE_EXIT: AtomicU32 = AtomicU32::new(0);

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn StartServiceCtrlDispatcherW(table: *const ServiceTableEntry) -> i32;
        fn RegisterServiceCtrlHandlerExW(
            name: *const u16,
            handler: Option<unsafe extern "system" fn(u32, u32, *mut c_void, *mut c_void) -> u32>,
            context: *mut c_void,
        ) -> Handle;
        fn SetServiceStatus(handle: Handle, status: *const ServiceStatus) -> i32;
    }

    fn wide_name() -> Vec<u16> {
        NAME.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn report(state: u32, controls: u32, exit_code: u32, wait_hint: u32) -> Result<()> {
        let handle = STATUS_HANDLE.load(Ordering::Acquire);
        ensure!(!handle.is_null(), "Windows SCM status not registered");
        let status = ServiceStatus {
            service_type: OWN_PROCESS,
            state,
            controls,
            win32_exit_code: exit_code,
            service_exit_code: 0,
            checkpoint: 0,
            wait_hint,
        };
        // SAFETY: status and registered handle remain valid during the call.
        if unsafe { SetServiceStatus(handle, &status) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("Cannot report Windows service status");
        }
        Ok(())
    }

    unsafe extern "system" fn control(code: u32, _: u32, _: *mut c_void, _: *mut c_void) -> u32 {
        match code {
            CONTROL_STOP | CONTROL_SHUTDOWN => {
                STOP_REQUESTED.store(true, Ordering::Release);
                let _ = report(STOP_PENDING, 0, 0, 30_000);
                0
            }
            CONTROL_INTERROGATE => 0,
            _ => NOT_IMPLEMENTED,
        }
    }

    fn service_body() -> Result<()> {
        let service_name = wide_name();
        // SAFETY: service_name is NUL-terminated and the handler ABI matches Win32.
        let handle = unsafe {
            RegisterServiceCtrlHandlerExW(service_name.as_ptr(), Some(control), ptr::null_mut())
        };
        ensure!(!handle.is_null(), "Cannot register Windows service handler");
        STATUS_HANDLE.store(handle, Ordering::Release);
        report(START_PENDING, 0, 0, 120_000)?;

        let settings = SETTINGS.get().context("Missing service settings")?;
        let result = host_foreground(settings, || {
            report(RUNNING, ACCEPT_STOP | ACCEPT_SHUTDOWN, 0, 0)
        });
        let _ = report(STOP_PENDING, 0, 0, 30_000);
        let code = if result.is_ok() { 0 } else { 1 };
        let _ = report(STOPPED, 0, code, 0);
        STATUS_HANDLE.store(ptr::null_mut(), Ordering::Release);
        result
    }

    unsafe extern "system" fn service_main(_: u32, _: *mut *mut u16) {
        // No Rust panic may unwind across a Windows callback boundary.
        let result = std::panic::catch_unwind(service_body);
        if !matches!(result, Ok(Ok(()))) {
            SERVICE_EXIT.store(1, Ordering::Release);
        }
    }

    pub fn dispatch(settings: Settings) -> Result<()> {
        SETTINGS
            .set(settings)
            .map_err(|_| anyhow::anyhow!("Windows service settings already set"))?;
        let name = wide_name();
        let table = [
            ServiceTableEntry {
                name: name.as_ptr(),
                entry: Some(service_main),
            },
            ServiceTableEntry {
                name: ptr::null(),
                entry: None,
            },
        ];
        // SAFETY: the table and name remain live until dispatcher returns.
        if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("Cannot connect to Windows Service Control Manager");
        }
        ensure!(
            SERVICE_EXIT.load(Ordering::Acquire) == 0,
            "Windows service process failed"
        );
        Ok(())
    }
}

fn run(args: &[OsString]) -> Result<()> {
    let (mode, settings) = parse_settings(args)?;
    match mode {
        "--once" => run_once(&settings),
        "--foreground" => {
            #[cfg(target_os = "linux")]
            signals::install()?;
            #[cfg(windows)]
            console::install()?;
            #[cfg(not(any(windows, target_os = "linux")))]
            bail!("Service host unavailable on this platform");

            host_foreground(&settings, || {
                println!("SERVICE_HOST=READY version={}", env!("CARGO_PKG_VERSION"));
                Ok(())
            })
        }
        "--scm" => {
            #[cfg(windows)]
            {
                scm::dispatch(settings)
            }
            #[cfg(not(windows))]
            {
                let _ = settings;
                bail!("Windows SCM mode is unavailable on this platform")
            }
        }
        _ => bail!("Unknown service host mode"),
    }
}

fn main() -> std::process::ExitCode {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    match run(&args) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("SERVICE_HOST_ERROR: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_root_and_short_interval_are_required() {
        let dir = tempfile::tempdir().unwrap();
        let arguments = [
            OsString::from("--once"),
            dir.path().as_os_str().to_os_string(),
            OsString::from("2"),
        ];
        assert!(parse_settings(&arguments).is_ok());
        let invalid = [
            OsString::from("--once"),
            OsString::from("relative/path"),
            OsString::from("2"),
        ];
        assert!(parse_settings(&invalid).is_err());
        let mut out_of_range = arguments.clone();
        out_of_range[2] = OsString::from("0");
        assert!(parse_settings(&out_of_range).is_err());
        out_of_range[2] = OsString::from("61");
        assert!(parse_settings(&out_of_range).is_err());
    }

    #[test]
    fn missing_root_and_parent_traversal_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let bad = [
            OsString::from("--once"),
            dir.path().join("missing").into_os_string(),
            OsString::from("1"),
        ];
        assert!(parse_settings(&bad).is_err());
        let traversal = [
            OsString::from("--once"),
            dir.path().join("child").join("..").into_os_string(),
            OsString::from("1"),
        ];
        assert!(parse_settings(&traversal).is_err());
    }
}
