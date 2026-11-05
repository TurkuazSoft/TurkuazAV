<!--
Dosya Yolu: REPO_ROOT/docs/windows-desktop-preview.md
Amac: Rust native GUI 0.3.1 arayuz akislarini tanimlar
Modul - FileType: Documentation - Markdown
Version: 0.3.1
Aciklama: Windows ve Linux Rust arayuz testi
Bagimli Oldugu Katman: View | Controller | Service
-->
# Rust Native Desktop Preview

The Rust desktop (`rust/src/bin/desktop.rs`) uses eframe/egui, a native file picker and clipboard. It is available as an optional Cargo feature on Windows and Linux. The GUI does not expose trusted publisher or YARA-X scanning.

Features: select a file or directory, clear old hash when selection changes, stream SHA-256 scan results through a worker with cancel control and live hashed/skipped/failed counters, display the last completed file report/status/byte size/hash, copy its hash, limit session history to 20 in-memory entries, clear history and write diagnostics with code/category only (no paths, digests or exception messages). A partial or cancelled scan never presents its final result as successful. Diagnostics are written under the OS-specific local data directory, retained for seven days.

The Horizon preview adds five navigable areas (Overview, File Analysis, Session History, Modules and Settings), an optional light theme, teal action buttons, visible scan counters and explicit unavailable-feature labels. Navigation becomes a wrapped row at narrow window widths; the native window starts at 1120x770 logical points with a 600x480 minimum. The in-progress scan has no completion percentage because directory enumeration does not supply a reliable total file count. Theme selection and session history are not persisted across launches. Controls remain native egui widgets; the visual concept artwork is not a shipped UI asset.

The packaged GUI executable supports the explicitly requested `--headless-self-test` mode. It creates one harmless temporary sample, runs the same desktop scan worker used by the GUI, checks the SHA-256 result and emits a versioned success marker. Both Windows and Linux packaging CI execute this mode from the extracted archive in a relocated Unicode working directory. The test does not open a native window or validate file pickers, clipboard or rendered UI.

No real-time protection, deletion, quarantine, driver or malware verdict is provided. Windows/Linux native GUI compilation in CI is not a substitute for real interactive smoke testing. Unsigned Windows and Linux CI archives include the Rust GUI and CLI together, plus SHA256SUMS, archive checksum and a Turkish user-facing `TEST_KILAVUZU_TR.md` quickstart. The guide is covered by the post-extraction file-count and SHA-256 verification. They are for isolated local testing, not production installers. The Windows archive also includes an opt-in PowerShell per-user setup/uninstall script, covered by SHA256SUMS. Trusted hosted Windows CI validates that the script refuses tampered files and unapproved replacement, and its CI-only simulated recycle destination retains prior user files through successful and interrupted reinstall paths. Interactive replacement requests Windows Shell's SendToRecycleBin only after explicit confirmation and package staging; actual shell recycle and recovery still require a manual desktop acceptance test. The installed desktop headless worker and safe uninstall are also exercised. It does not provision a protected service, change registry entries or prove interactive Start Menu behavior.

Manual acceptance still required for file and folder pickers, folder progress, cancellation, clipboard, history reset, light/dark theme, compact navigation at 600px minimum width, resize, Unicode paths, Linux desktop launch, Windows desktop launch and unexpected failures. A successful automated build does not complete these manual acceptance requirements.
