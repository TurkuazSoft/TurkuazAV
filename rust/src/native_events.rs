// Dosya Yolu: REPO_ROOT/rust/src/native_events.rs
// Amac: Platform dosya degisim ipuclarini guvenli SHA256 yeniden taramasina ilet
// Modul - FileType: Tool - Rust
// Version: 0.3.1
// Aciklama: Windows change notification ve Linux inotify uyandirici; dosya karari yok
// Bagimli Oldugu Katman: Tool | Service

use anyhow::{bail, Result};
use std::{
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeReason {
    ChangeHint,
    Interval,
}

/// Native signals are untrusted *hints*, not a complete event log.
/// Always run DirectoryObserver::poll after EVERY hint and interval. Linux
/// subscribes to the root directory only; periodic full-tree sampling catches
/// nested changes that its root watch cannot report.
pub struct NativeChangeWakeup {
    #[cfg(any(windows, target_os = "linux"))]
    inner: platform::Watcher,
}

impl NativeChangeWakeup {
    pub fn new(root: &Path) -> Result<Self> {
        let meta = std::fs::symlink_metadata(root)?;
        if crate::scan::is_reparse_or_symlink(&meta) || !meta.is_dir() {
            bail!("Native observer requires a real directory");
        }
        #[cfg(any(windows, target_os = "linux"))]
        {
            Ok(Self {
                inner: platform::Watcher::new(root)?,
            })
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            bail!("Native change notifications unsupported on this platform")
        }
    }

    pub fn wait(&mut self, cancelled: &AtomicBool, interval: Duration) -> Result<WakeReason> {
        if cancelled.load(Ordering::Relaxed) {
            bail!("Native observer cancelled");
        }
        #[cfg(any(windows, target_os = "linux"))]
        {
            self.inner.wait(cancelled, interval)
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = interval;
            bail!("Native change notifications unsupported on this platform")
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use anyhow::Context;
    use std::{ffi::c_void, os::windows::ffi::OsStrExt, ptr, time::Instant};

    type Handle = *mut c_void;
    const WATCH_CHANGES: u32 =
        0x0000_0001 | 0x0000_0002 | 0x0000_0004 | 0x0000_0008 | 0x0000_0010 | 0x0000_0040;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "FindFirstChangeNotificationW"]
        fn first_change(path: *const u16, subtree: i32, filter: u32) -> Handle;
        #[link_name = "FindNextChangeNotification"]
        fn next_change(handle: Handle) -> i32;
        #[link_name = "FindCloseChangeNotification"]
        fn close_change(handle: Handle) -> i32;
        #[link_name = "WaitForSingleObject"]
        fn wait_object(handle: Handle, milliseconds: u32) -> u32;
    }

    pub struct Watcher {
        handle: Handle,
    }

    impl Watcher {
        pub fn new(root: &Path) -> Result<Self> {
            let path: Vec<u16> = root
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            // SAFETY: path is NUL-terminated and lives throughout this call.
            let handle = unsafe { first_change(path.as_ptr(), 1, WATCH_CHANGES) };
            if handle == (-1isize as Handle) || handle == ptr::null_mut() {
                return Err(std::io::Error::last_os_error())
                    .context("Cannot register Windows change notification");
            }
            Ok(Self { handle })
        }

        pub fn wait(&mut self, cancelled: &AtomicBool, interval: Duration) -> Result<WakeReason> {
            let start = Instant::now();
            loop {
                if cancelled.load(Ordering::Relaxed) {
                    bail!("Native observer cancelled");
                }
                let remaining = interval.saturating_sub(start.elapsed());
                if remaining.is_zero() {
                    return Ok(WakeReason::Interval);
                }
                // Short waits make cancellation responsive; no busy loop.
                let timeout = remaining.as_millis().min(100).max(1) as u32;
                // SAFETY: the notification handle remains owned by Watcher.
                let outcome = unsafe { wait_object(self.handle, timeout) };
                match outcome {
                    WAIT_OBJECT_0 => {
                        // Rearm BEFORE the caller hashes its complete snapshot.
                        // A missed/coalesced event is caught by interval polling.
                        // SAFETY: the handle is valid until Drop.
                        if unsafe { next_change(self.handle) } == 0 {
                            return Err(std::io::Error::last_os_error())
                                .context("Cannot rearm Windows change notification");
                        }
                        return Ok(WakeReason::ChangeHint);
                    }
                    WAIT_TIMEOUT => (),
                    _ => {
                        return Err(std::io::Error::last_os_error())
                            .context("Windows change wait failed");
                    }
                }
            }
        }
    }

    impl Drop for Watcher {
        fn drop(&mut self) {
            // SAFETY: exactly one owner closes the OS handle.
            unsafe {
                close_change(self.handle);
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use anyhow::Context;
    use std::{
        ffi::CString,
        fs::File,
        io::{self, Read},
        os::{
            fd::FromRawFd,
            raw::{c_char, c_int},
            unix::ffi::OsStrExt,
        },
        thread,
        time::Instant,
    };

    const IN_NONBLOCK: c_int = 0x800;
    const IN_CLOEXEC: c_int = 0x80000;
    // Do NOT watch IN_ACCESS (0x1), IN_CLOSE_NOWRITE (0x10) or IN_OPEN
    // (0x20). Inventory reads would otherwise trigger their own next scan.
    const IN_EVENTS: u32 = 0x0000_0002
        | 0x0000_0004
        | 0x0000_0008
        | 0x0000_0040
        | 0x0000_0080
        | 0x0000_0100
        | 0x0000_0200
        | 0x0000_0400
        | 0x0000_0800
        | 0x0100_0000
        | 0x0200_0000;
    const IN_Q_OVERFLOW: u32 = 0x0000_4000;
    const IN_IGNORED: u32 = 0x0000_8000;
    const IN_SELF_LOST: u32 = 0x0000_0400 | 0x0000_0800 | 0x0000_2000;

    unsafe extern "C" {
        fn inotify_init1(flags: c_int) -> c_int;
        fn inotify_add_watch(fd: c_int, path: *const c_char, mask: u32) -> c_int;
    }

    pub struct Watcher {
        file: File,
    }

    impl Watcher {
        pub fn new(root: &Path) -> Result<Self> {
            let name = CString::new(root.as_os_str().as_bytes())
                .context("Native observer root contains NUL")?;
            // SAFETY: Linux inotify_init1 allocates an owned file descriptor.
            let fd = unsafe { inotify_init1(IN_NONBLOCK | IN_CLOEXEC) };
            if fd < 0 {
                return Err(io::Error::last_os_error()).context("Cannot open inotify");
            }
            // SAFETY: fd is valid; File takes ownership and closes it on failure.
            let file = unsafe { File::from_raw_fd(fd) };
            // SAFETY: CString has a trailing NUL and the descriptor is open.
            if unsafe { inotify_add_watch(fd, name.as_ptr(), IN_EVENTS) } < 0 {
                return Err(io::Error::last_os_error()).context("Cannot watch Linux directory");
            }
            Ok(Self { file })
        }

        pub fn wait(&mut self, cancelled: &AtomicBool, interval: Duration) -> Result<WakeReason> {
            let start = Instant::now();
            let mut buffer = [0u8; 65_536];
            loop {
                if cancelled.load(Ordering::Relaxed) {
                    bail!("Native observer cancelled");
                }
                match self.file.read(&mut buffer) {
                    Ok(0) => bail!("Linux change notification closed"),
                    Ok(count) => {
                        let mut offset = 0usize;
                        while offset < count {
                            // struct inotify_event has 16 fixed header bytes,
                            // followed by a length-prefixed optional name.
                            if count - offset < 16 {
                                bail!("Truncated Linux change notification");
                            }
                            let mask =
                                u32::from_ne_bytes(buffer[offset + 4..offset + 8].try_into()?);
                            let length =
                                u32::from_ne_bytes(buffer[offset + 12..offset + 16].try_into()?)
                                    as usize;
                            let end = offset
                                .checked_add(16)
                                .and_then(|p| p.checked_add(length))
                                .context("Invalid Linux event length")?;
                            if end > count {
                                bail!("Truncated Linux change notification");
                            }
                            if mask & (IN_Q_OVERFLOW | IN_IGNORED | IN_SELF_LOST) != 0 {
                                bail!("Linux native watch lost or overflowed");
                            }
                            offset = end;
                        }
                        return Ok(WakeReason::ChangeHint);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error).context("Linux change wait failed"),
                }
                let remaining = interval.saturating_sub(start.elapsed());
                if remaining.is_zero() {
                    return Ok(WakeReason::Interval);
                }
                thread::sleep(remaining.min(Duration::from_millis(50)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn native_event_wakes_after_a_file_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let mut watcher = NativeChangeWakeup::new(dir.path()).unwrap();
        let target = dir.path().join("new.txt");
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            std::fs::write(target, b"example").unwrap();
        });
        let result = watcher.wait(&AtomicBool::new(false), Duration::from_secs(5));
        worker.join().unwrap();
        assert_eq!(result.unwrap(), WakeReason::ChangeHint);
    }

    #[cfg(unix)]
    #[test]
    fn native_watcher_denies_symlink_root() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        let link = dir.path().join("linked");
        std::fs::create_dir(&real).unwrap();
        symlink(&real, &link).unwrap();
        assert!(NativeChangeWakeup::new(&link).is_err());
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn native_observer_does_not_wake_for_read_only_access() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("unchanged");
        std::fs::write(&file, b"unchanged contents").unwrap();
        let mut watcher = NativeChangeWakeup::new(dir.path()).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"unchanged contents");
        let result = watcher
            .wait(&AtomicBool::new(false), Duration::from_millis(250))
            .unwrap();
        assert_eq!(result, WakeReason::Interval);
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn cancelled_native_wait_fails_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let mut watcher = NativeChangeWakeup::new(dir.path()).unwrap();
        assert!(watcher
            .wait(&AtomicBool::new(true), Duration::from_secs(5))
            .is_err());
    }
}
