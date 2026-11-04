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

Features: select a file or directory, clear old hash when selection changes, stream SHA-256 scan results through a worker with cancel control and live hashed/skipped/failed counters, display the last completed file report/status/byte size/hash, copy its hash, limit session history to 20 in-memory entries, clear history and write diagnostics with code/category only (no paths, digests or exception messages). A partial or cancelled scan never presents its final result as successful. Diagnostics are written under the OS-specific local data directory, retained for seven days.

The packaged GUI executable supports the explicitly requested `--headless-self-test` mode. It creates one harmless temporary sample, runs the same desktop scan worker used by the GUI, checks the SHA-256 result and emits a versioned success marker. Both Windows and Linux packaging CI execute this mode from the extracted archive in a relocated Unicode working directory. The test does not open a native window or validate file pickers, clipboard or rendered UI.

No real-time protection, deletion, quarantine, driver or malware verdict is provided. Windows/Linux native GUI compilation in CI is not a substitute for real interactive smoke testing. Unsigned Windows and Linux CI archives include the Rust GUI and CLI together, plus SHA256SUMS and archive checksum. They are for isolated local testing, not production installers.

Manual acceptance still required for file and folder pickers, folder progress, cancellation, clipboard, history reset, resize, Unicode paths, Linux desktop launch, Windows desktop launch and unexpected failures. No manual testing is requested from the user before the ongoing Rust conversion is ready for acceptance.
