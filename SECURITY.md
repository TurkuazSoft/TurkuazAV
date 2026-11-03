<!--
Dosya Yolu: REPO_ROOT/SECURITY.md
Amac: Guvenli acik bildirimi ve Rust preview sinirlarini aciklar
Modul - FileType: Documentation - Markdown
Version: 0.3.1
Aciklama: Gercek antivirus korumasi olmadan deneysel analiz
Bagimli Oldugu Katman: Documentation
-->
# Security Policy

TurkuazAV 0.3.1 Rust preview is **not** an antivirus, EDR, ransomware blocker or replacement for operating system protection. No realtime blocking, quarantine or malware verdict is implemented. The optional `observe` CLI is a **user-started, bounded SHA-256 polling preview**, not a real-time filesystem event source, AV service or protection mechanism. It neither blocks nor modifies files, may miss changes between polls, skips symlinks/reparse points and files over the scan size limit, and stops on partial/inaccessible scans. It only prints selected paths to the local console; no observer history is persisted.

Do not disclose exploit details in public issues or PRs. Prefer GitHub private vulnerability reporting when available. Do not commit malware samples, secrets, private keys or customer data; use harmless test fixtures.

Publisher keyring must come from a separately trusted application bootstrap. Developer CLI public keys are not production trust roots. Pinned YARA-X engine files must be verified; pre-execution TOCTOU and subprocess isolation require additional production hardening. Version state must be stored in a protected service-owned directory.

Never disable host AV to run unsigned CI artifacts on a production system. Test on isolated machines and manually verify native GUI behavior before any production deployment.

[Security model](docs/security-model.md).
