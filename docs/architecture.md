<!--
Dosya Yolu: REPO_ROOT/docs/architecture.md
Amac: Rust core/CLI/desktop sinirlarini belgeler
Modul - FileType: Documentation - Markdown
Version: 0.3.1
Aciklama: Native guvenlik analiz mimarisi
Bagimli Oldugu Katman: Documentation
-->
# Rust Architecture (0.3.1)

- `rust/src/config.rs`: fixed limits and platform-specific YARA-X executable SHA-256 pins
- `rust/src/scan.rs`: read-only file enumeration, bounded streaming SHA-256, symlink/reparse handling and cancellation
- `rust/src/monitor.rs`: bounded read-only SHA-256 directory polling and in-memory delta state
- `rust/src/native_events.rs`: opt-in Windows recursive change notification / Linux inotify root notification hint adapter; periodic full-tree polling fallback remains authoritative, no daemon or blocking hook
- `rust/src/service.rs`: bounded one-slot atomic reconciliation request, independent trigger handle, failure/cancel replay, root-scoped scanning
- `rust/src/worker.rs`: opt-in owned background thread with periodic reconciliation, bounded retry, path-free health counters, cooperative cancel/join; no installed OS service
- `rust/src/rules.rs`: RSA-PSS-SHA256 verification, bounded snapshots, engine hash validation, subprocess timeout/output limit and NDJSON parsing
- `rust/src/trusted.rs`: strict manifest parser, pinned publisher keyring, canonical signed payload and protected anti-rollback 40-byte format
- `rust/src/bin/cli.rs`: console controller and textual report
- `rust/src/bin/desktop.rs`: native UI, in-memory session history, clipboard and privacy-preserving diagnostics

Rust modules retain logical Controller / Service / Repository / Tool / View / Config separation. No permanent scan history and no automatic malware verdict. YARA-X uses a pinned external executable; integration is deliberately library-controlled and independent of UI. A production-provisioned trust root is still required.

When copying a mutable target for YARA-X, the snapshot may contain concurrent writes; additional filesystem and process isolation is needed for production antivirus uses.

See [migration tests](rust-migration.md) and [security model](security-model.md).
