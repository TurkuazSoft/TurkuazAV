<!--
Dosya Yolu: REPO_ROOT/SECURITY.md
Amac: Guvenli acik bildirimi ve Rust preview sinirlarini aciklar
Modul - FileType: Documentation - Markdown
Version: 0.3.1
Aciklama: Gercek antivirus korumasi olmadan deneysel analiz
Bagimli Oldugu Katman: Documentation
-->
# Security Policy

TurkuazAV 0.3.1 Rust preview is **not** an antivirus, EDR, ransomware blocker or replacement for operating system protection. No realtime scanning, quarantine or malware verdict is implemented.

Do not disclose exploit details in public issues or PRs. Prefer GitHub private vulnerability reporting when available. Do not commit malware samples, secrets, private keys or customer data; use harmless test fixtures.

Publisher keyring must come from a separately trusted application bootstrap. Developer CLI public keys are not production trust roots. Pinned YARA-X engine files must be verified; pre-execution TOCTOU and subprocess isolation require additional production hardening. Version state must be stored in a protected service-owned directory.

Never disable host AV to run unsigned CI artifacts on a production system. Test on isolated machines and manually verify native GUI behavior before any production deployment.

[Security model](docs/security-model.md).
