<!--
Dosya Yolu: REPO_ROOT/README.md
Amac: Native Rust TurkuazAV v0.3.1 test surumunu tanitmak
Modul - FileType: Documentation - Markdown
Version: 0.3.1
Aciklama: Rust core, CLI ve GUI; real-time AV yok
Bagimli Oldugu Katman: Documentation
-->
# TurkuazAV 0.3.1 - Rust Native Preview

TurkuazAV is a **read-only experimental file analysis tool**, **not an antivirus**. The v0.3.1 implementation is written in Rust: scanning core, signed-rule processor, CLI and native desktop preview.

## Capabilities

- **Rust Core**: SHA-256 file/directory scan, 100 MiB default per-file ceiling, skip symlinks/reparse points, cancellation and explicit error reporting. CLI streams results through `scan_path_each` without retaining an unbounded result list; `scan_path` remains as a compatibility API for small in-memory consumers.
- **Rust CLI**: `scan`, developer-only `scan-rules`, and **explicit bounded polling** `observe` commands. `observe` inventories SHA-256 read-only, detects added/modified/removed regular files, and never starts automatically; this is neither OS event monitoring nor antivirus protection.
- **YARA-X**: verifies RSA-PSS-SHA256 rule signature, snapshots rules and target, verifies pinned executable SHA-256 (Windows/Linux x64), bounded output and timeout.
- **Trusted publisher API**: independent pinned keyring, strict four-field manifest, canonical payload, signed rule digest and persistent 40-byte anti-rollback state (same contract as .NET 0.2.4).
- **Rust Desktop**: cross-platform egui GUI for read-only *file or folder SHA-256* scanning, file/folder picker, cancel, live progress counters, last-file digest report, clipboard copy, maximum 20 in-memory session entries and redacted local diagnostics with 7-day retention. This is not a malware verdict.
- No real-time protection, quarantine, driver, automatic malicious/clean verdict or production signing.

## Build / run

Requires Rust (minimum declared 1.85; CI uses stable).

```bash
cargo fmt --all -- --check
cargo clippy --lib --bin turkuazav --tests -- -D warnings
cargo test --lib --test rust_compat
cargo run --bin turkuazav -- scan .
cargo run --features desktop --bin turkuazav-desktop
```

Optional foreground observer preview (a fixed number of cycles, no daemon or autostart):

```bash
cargo run --bin turkuazav -- observe ./my-directory 3 2
```

The service-core coordinator (`rust/src/service.rs`) coalesces repeated event hints into **one pending full-tree rescan**, without buffering raw paths. A failed or cancelled rescan remains pending for retry; requests arriving during a scan remain pending. This is a synchronous, read-only core designed for a future supervised worker, **not** an installed, privileged or protected OS service.

Supervised worker preview (explicitly started; one thread, no installed service):

```bash
cargo run --bin turkuazav -- observe-worker ./my-directory 3 2
```

The worker owns the root-scoped coordinator and exposes limited health counters (completed/failed scans and change counts), without storing paths or digests. A single pending bit coalesces requests, periodic full-tree scans still run, and failed scans enter bounded retry backoff. The worker stops cooperatively and is joined; a hung filesystem operation is **not** guaranteed to stop within a fixed deadline. A separate `turkuazav-service` preview binary can now be supervised by Windows SCM or run in the foreground under Linux systemd. **No service is installed, enabled, privileged or hardened by the application.**

Native change notification preview (also foreground and bounded):

```bash
cargo run --bin turkuazav -- observe-events ./my-directory 3 2
```

`observe-events` waits for a native change **hint** or an interval deadline, then runs the same complete, read-only SHA-256 inventory. Windows uses recursive change notifications; Linux currently listens to its root directory, so **nested changes rely on the periodic full-tree fallback**. Watch loss and inotify queue overflow fail closed. A notification is never treated as malware evidence or a complete event history.

The observer hashes each eligible file on each cycle (up to 4,096 files, each under the 100 MiB scan limit). Skipped files, symlinks and reparse directories are **not covered**. If a previously tracked file becomes inaccessible or too large, the cycle fails closed without updating its baseline. No events are guaranteed between polls. Sensitive filenames are only printed to the local console; there is no persisted observation log.

Developer-only signed rule scan, not an independent production trust root:

```bash
cargo run --bin turkuazav -- scan-rules TARGET RULES.YAR RULES.SIG PUBLIC.PEM ABSOLUTE_YR_PATH
```

Real signed YARA-X tests (Windows/Linux x64):

```powershell
pwsh ./tools/install-yarax.ps1
# With TURKUAZ_YR_PATH exported by CI or manually defined:
cargo test --test yarax_e2e
```

CI: `.github/workflows/rust-ci.yml` on Windows 2022 and Ubuntu 24.04 includes locked builds, Rust CLI subprocess checks, desktop worker lifecycle tests, real pinned YARA-X tests, Clippy and package verification. On each OS the unsigned local test bundle contains `turkuazav` (CLI), `turkuazav-desktop` (GUI), `turkuazav-service` (service host), `README.md`, `SECURITY.md` and `SHA256SUMS` (plus an uninstalled example unit/env file on Linux).

- Windows: `TurkuazAV-0.3.1-RUST-UNSIGNED-LOCAL-TEST-win-x64.zip`
- Linux: `TurkuazAV-0.3.1-RUST-UNSIGNED-LOCAL-TEST-linux-x64.tar.gz`
- Each archive also has an archive-level `.sha256` sidecar. CI extracts the archive, verifies all payload checksums **and runs the unpacked Rust CLI** against a known SHA-256 sample from a relocated Unicode working directory. See `tools/package-rust-preview.ps1`.
- Both packages are **unsigned CI test artifacts only**, not installers or published production releases. Linux GUI requires compatible system display/graphics dependencies.

A successful CI build does **not** prove interactive GUI behavior on end-user machines; file picker, clipboard and cancellation still require real Windows/Linux manual smoke tests.

## OS service host preview (not installed)

The new `turkuazav-service` binary supports `--once` (one-shot acceptance smoke), `--foreground` (long-lived read-only observer) and on Windows `--scm` (Service Control Manager entrypoint). It requires an existing **absolute** watched directory and an interval of 1-60 seconds; `..` components and a symlink/reparse root are refused. The root must be authorized and made readable by the **least-privileged OS service account** in a separate administrator-controlled provisioning step. The application does not create accounts, modify ACLs, install services, request elevation or create persistent scan logs.

The Linux template `deploy/service/turkuazav-preview.service` and `deploy/service/preview.env.example` are **uninstalled examples**. The unit uses `Type=simple` (not a ready/healthy notification), read-only filesystem hardening and `Restart=on-failure`; the operator must provision a service user, immutable binary path, watched directory, environment file and approve the sandbox restrictions before installation. A healthy process is **not** proof of antivirus protection. Windows SCM integration supports STOP/SHUTDOWN, but service registration, restricted ACL/account configuration and SCM recovery policy are not automated and **not tested under a live SCM**.

For an unprivileged local test with no service registration:

```bash
cargo run --bin turkuazav-service -- --once /absolute/watched/directory 2
```

CI exercises `--once` from a relocated extracted test package on both OSes, and Linux subprocess SIGTERM shutdown, but does not install systemd/SCM or prove production service recovery. Exit on native watcher failure is nonzero so an externally configured supervisor may restart it. Cooperative shutdown may block if an OS file read hangs.

## Security / compatibility

See [security model](docs/security-model.md), [migration contract](docs/rust-migration.md) and [desktop preview](docs/windows-desktop-preview.md). The previous .NET v0.3.1 implementation remains available in git history on `main` until this Rust branch is explicitly merged. No automatic release.
