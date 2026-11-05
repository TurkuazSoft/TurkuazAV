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
- **TurkuazAV Scanner (experimental API)**: engine-neutral `ScannerBackend` interface and path-free `ScannerReport`. The SHA-256 and trusted YARA-X adapters keep separate capabilities; YARA-X is the upstream engine name, not a name to overwrite. Existing CLI and desktop behavior is unchanged.
- **YARA-X**: verifies RSA-PSS-SHA256 rule signature, snapshots rules and target, verifies pinned executable SHA-256 (Windows/Linux x64), bounded output and timeout.
- **Trusted publisher API**: independent pinned keyring, strict four-field manifest, canonical payload, signed rule digest and persistent 40-byte anti-rollback state (strict signed-state format).
- **Rust Desktop**: cross-platform egui GUI for read-only *file or folder SHA-256* scanning, file/folder picker, cancel, live progress counters, last-file digest report, clipboard copy, maximum 20 in-memory session entries and redacted local diagnostics with 7-day retention. This is not a malware verdict.
- **Threat assessment model (experimental)**: a read-only Rust API separates scan coverage, unknown threat category and rule evidence. SHA-256 alone never implies a clean verdict; YARA-X matches require review, not automatic blocking. See [threat assessment design](docs/threat-assessment-model.md).
- No real-time protection, quarantine, driver, automatic malicious/clean verdict or production signing.

## Build / run

The active source tree is Rust-only. CI checks tracked files for retired native source projects and older workflows with `tools/assert-rust-only.ps1`. This does not rewrite Git history.

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
- Each archive also has an archive-level `.sha256` sidecar. CI extracts the archive, verifies all payload checksums **and runs the unpacked Rust CLI, service host and desktop headless scan worker** against a known SHA-256 sample from a relocated Unicode working directory. See `tools/package-rust-preview.ps1`. The GUI's `--headless-self-test` does not render a window or establish successful interactive use.
- Both packages now include the UTF-8 Turkish end-user `TEST_KILAVUZU_TR.md` with extraction steps, a portable headless self-test command and an interactive acceptance checklist. Its SHA-256 is validated after archive extraction.
- Both packages are **unsigned CI test artifacts only**, not installers or published production releases. Linux GUI requires compatible system display/graphics dependencies.

The Windows x64 archive additionally includes `TurkuazAV-Preview-Setup.ps1` for **opt-in, current-user-only preview installation and uninstallation**. It checks every extracted file against `SHA256SUMS`, stages a fresh installation under the user's LocalApplicationData and creates a Start Menu shortcut. When the destination already exists, the script verifies and stages the new package **before prompting** the user to type `EVET`. Only after explicit consent does it request Windows Shell's `SendToRecycleBin` for the complete old folder, followed by a no-clobber installation. Declining leaves the original folder intact; a recycle failure stops the install. If installation fails after recycling, the user can look for the previous folder in the Recycle Bin. **Recovery is not guaranteed** (Recycle Bin policies, capacity, cleanup or unsupported storage), so important files should be backed up separately. There is no silent permanent-delete fallback in the script. Elevation, service registration, scheduled tasks, drivers, registry integration and automatic protection are not enabled. The installed script uninstalls only its own known files. Hosted Windows CI tests confirmation refusal, a simulated recycle destination, interrupted replacement, tamper rejection and safe removal; **real Windows Recycle Bin integration still needs a manual interactive acceptance test**. This script and archive are **unsigned**; SHA-256 does not authenticate the publisher. See the [Turkish test guide](TEST_KILAVUZU_TR.md).

A successful CI build does **not** prove interactive GUI behavior on end-user machines; file picker, clipboard and cancellation still require real Windows/Linux manual smoke tests.

## Signed service-update verification gate (library only)

`rust/src/update.rs` adds `verify_service_update`: a read-only, bounded RSA-PSS-SHA256 verification gate for a signed **service executable snapshot** (maximum 64 MiB). Its strict manifest (`turkuazav.service-update.v1`) covers sequence, publisher key ID, three-part version, target OS/architecture, binary size and SHA-256. The signed domain `TurkuazAV.service-update.v1` is separate from YARA rule-package signatures, so a rule signature cannot authorize a service executable.

The library requires an **independently trusted publisher keyring** and a **separately protected update-version state file**. It rejects unknown publishers, malformed/extra fields, wrong architecture, tampering, stale versions and same-sequence different payloads. The caller receives an immutable view of the verified binary bytes, avoiding reliance on a mutable source path. **Verification does not change any installed service, write update state, download files, or grant trust to a CLI PEM.** Installation would require a future privileged updater to stage and re-hash the executable, maintain its own protected rollback journal, switch and health-check the OS service, and only then atomically commit the 40-byte anti-rollback state. An interrupted install must be recoverable without treating an uninstalled version as committed. This verifier alone is not a signed updater or automatic AV protection.

## Verified update transaction preview (not production)

`rust/src/update_transaction.rs` adds `apply_verified_service_update`, accepting **only** an already signed-and-verified update snapshot. It requires an administrator-protected, pre-existing absolute install directory and an independent service-update anti-rollback state path in that directory. Under an exclusive cooperative transaction lock it checks that the signed sequence strictly increases, stages a separate versioned executable using no-clobber persistence and a second digest verification, then invokes a supplied `ServiceActivation` interface. An adapter must prove the actual service's authorized identity and running executable; none is installed or enabled in this preview.

Pre-activation path checks now refuse update-state files that collide with transaction records/locks, any versioned service executable or the currently active service binary, along with traversal paths. This prevents known state-commit failures from being introduced by a misconfigured updater path; it does not make the preview a production installer.

A pending-update marker is now written and synchronized **before** the activation hook. A crash or an unresolved restore/commit error leaves that marker behind and blocks later transactions until manual reconciliation; the record is diagnostic data, never an instruction trusted for automatic restore. Successful restoration or successful version commit clears it. This is a fail-closed interruption latch, **not** a complete durable crash-recovery journal or power-loss-proof update system.

The read-only `inspect_pending_service_update` API checks the bounded, strict pending-record schema and whether the separate 40-byte version record matches the pending sequence/fingerprint. New v2 pending records also contain the staged candidate's size and SHA-256 so inspection can report matching, changed or missing candidate bytes. Old v1 records remain readable, but explicitly report that no candidate digest is available. A matching locally recorded hash is **not** publisher authentication, service identity proof or authorization for recovery. Its status is **diagnostic only**: even a matching record does not establish that any executable is running or authorized. Invalid, linked or oversized records fail closed; the inspector neither follows recorded paths nor clears the pending marker. New CI contract tests cover interruption, matched committed state, tampering and no automatic reentry.

A failed activation or health check attempts to restore the prior executable, removes the candidate only if restoration succeeds and never commits the new sequence. After a successful health check, the existing atomically written 40-byte version record is advanced. **If committing that record returns an error, the transaction refuses automatic rollback** because the record may already be durable: manual reconciliation is required. Tests inject activation errors, health errors, rollback failures and version-state conflicts. An interrupted process or power outage is **not yet crash recoverable**: there is no persistent rollback journal, signed updater executable, trusted production key provisioning or real SCM/systemd adapter. This is a service update orchestration **contract**, not a safe production installer.

## OS service host preview (not installed)

The new `turkuazav-service` binary supports `--once` (one-shot acceptance smoke), `--foreground` (long-lived read-only observer) and on Windows `--scm` (Service Control Manager entrypoint). It requires an existing **absolute** watched directory and an interval of 1-60 seconds; `..` components and a symlink/reparse root are refused. The root must be authorized and made readable by the **least-privileged OS service account** in a separate administrator-controlled provisioning step. The application does not create accounts, modify ACLs, install services, request elevation or create persistent scan logs.

The Linux template `deploy/service/turkuazav-preview.service` and `deploy/service/preview.env.example` are **uninstalled examples**. The unit uses `Type=simple` (not a ready/healthy notification), read-only filesystem hardening and `Restart=on-failure`; the operator must provision a service user, immutable binary path, watched directory, environment file and approve the sandbox restrictions before installation. A healthy process is **not** proof of antivirus protection. Windows SCM integration supports STOP/SHUTDOWN, but service registration, restricted ACL/account configuration and SCM recovery policy are not automated and **not tested under a live SCM**.

For an unprivileged local test with no service registration:

```bash
cargo run --bin turkuazav-service -- --once /absolute/watched/directory 2
```

CI exercises `--once` from a relocated extracted test package on both OSes and Linux subprocess SIGTERM shutdown. Trusted, ephemeral **GitHub-hosted** CI additionally tests a real Windows SCM service running under `LocalService` (manual start/stop, restart-only recovery policy with a forced own-process crash, and STOP without restart) and an isolated Linux `systemd` unit rendered from the shipped template (start/stop and `Restart=on-failure` after a forced crash). These tests clean up their temporary registrations, do not enable autostart, and are excluded for fork PRs. Both hosted CI acceptance scripts now also stage a second copy of the **same verified build**, switch only their temporary service's executable path while stopped, start and verify the staged executable, reject a deliberately tampered candidate **before applying it**, and restore/execute the original configuration. These are installer-transition contract tests, **not** a signed updater or a real version-to-version migration. They are **not** production service-account provisioning, customer-machine acceptance, or proof of protection. Exit on native watcher failure is nonzero so an externally configured supervisor may restart it. Cooperative shutdown may block if an OS file read hangs.

## Security and current documentation

Read the [security model](docs/security-model.md), [native architecture](docs/architecture.md), [desktop preview](docs/windows-desktop-preview.md) and [Turkish acceptance guide](TEST_KILAVUZU_TR.md). The Rust preview is under active development: unsigned test artifacts are not production releases. Interactive desktop acceptance, a protected installer, trusted publisher provisioning and actual malware protection are not yet implemented.
