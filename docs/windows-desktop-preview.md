<!--
Dosya Yolu: REPO_ROOT/docs/windows-desktop-preview.md
Amac: Rust native GUI 0.3.1 arayuz akislarini tanimlar
Modul - FileType: Documentation - Markdown
Version: 0.3.1
Aciklama: Windows ve Linux Rust arayuz testi
Bagimli Oldugu Katman: View | Controller | Service
-->
# Rust Native Desktop Preview

The Rust desktop (`rust/src/bin/desktop.rs`) uses eframe/egui, a native file picker and clipboard. It is available as an optional Cargo feature on Windows and Linux. It replaces the WinUI 3 preview and does not expose trusted publisher or YARA-X scanning.

Features: select a single file, clear old hash when selection changes, SHA-256 scan with cancel control, report status/byte size/hash, copy hash, maximum 20 in-memory history entries, clear history and diagnostics with code/category only (no paths, digests or exception messages). Diagnostics are written under the OS-specific local data directory, retained for seven days.

No real-time protection, deletion, quarantine, driver or malware verdict is provided. Windows/Linux native GUI compilation in CI is not a substitute for real interactive smoke testing. Unsigned Windows and Linux CI archives include the Rust GUI and CLI together, plus SHA256SUMS and archive checksum. They are for isolated local testing, not production installers.

Manual acceptance still required for file picker, cancellation, clipboard, history reset, resize, Unicode paths, Linux desktop launch, Windows desktop launch and unexpected failures.
