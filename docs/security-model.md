<!--
Dosya Yolu: REPO_ROOT/docs/security-model.md
Amac: Rust signed-rule trust ve anti-rollback guven kontrati
Modul - FileType: Documentation - Markdown
Version: 0.3.1
Aciklama: V0.2.4 signature/state compatibility and remaining risks
Bagimli Oldugu Katman: Service | Repo | Tool | Config
-->
# TurkuazAV Rust Security Model

This v0.3.1 experimental implementation is not a full antivirus. It does not provide real-time blocking or malware verdicts.

## Signed rule package contract (preserved from 0.2.4)

1. Publisher keys are pinned by an independently trusted application bootstrap, never by the untrusted manifest or public-key CLI argument.
2. Strict manifest fields: `schema`, `sequence` (positive signed 64-bit integer), `keyId`, `rulesSha256` (64 lower-case hex characters).
3. Canonical RSA-PSS-SHA256 signature input: `TurkuazAV.rule-package.v1\n<sequence>\n<keyId>\n<rulesSha256>\n`.
4. Verify key ID and RSA key strength (at least 2048-bit), signature and content hash before providing rule bytes to the engine.
5. Store verified rule bytes and bounded target snapshot in a temporary private directory; stage a bounded private executable copy and verify **the staged bytes** against the pinned official YARA-X SHA-256 before spawning it.
6. Only after successful real engine execution and validated NDJSON output, commit the anti-rollback state.
7. Persistent state has exactly 40 bytes: 8-byte little-endian positive sequence + 32-byte SHA-256 canonical-payload fingerprint. Older sequences and same-sequence/different-payload are denied. Invalid/legacy 8-byte records fail closed.

The storage location must be protected by host permissions; file locking does not defeat privileged tampering or rollback. No automatic legacy state migration occurs.

## Incomplete production controls

Publisher trust-root provisioning, secure signed key rotation, protected service installation, process sandboxing and full process-tree termination, remaining local privilege/temporary-directory tamper hardening, target filesystem TOCTOU hardening, atomic state update/power-loss tests, fuzz and performance coverage, real interactive GUI smoke, production signing, quarantine and real-time blocking.

Do not run unsigned preview artifacts as the device's only endpoint protection.
