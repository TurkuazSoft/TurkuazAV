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
- **Rust CLI**: `scan` and developer-only `scan-rules` commands.
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

CI: `.github/workflows/rust-ci.yml` on Windows 2022 and Ubuntu 24.04 includes locked builds, Rust CLI subprocess checks, desktop worker lifecycle tests, real pinned YARA-X tests, Clippy and package verification. On each OS the unsigned local test bundle contains `turkuazav` (CLI), `turkuazav-desktop` (GUI), `README.md`, `SECURITY.md` and `SHA256SUMS`.

- Windows: `TurkuazAV-0.3.1-RUST-UNSIGNED-LOCAL-TEST-win-x64.zip`
- Linux: `TurkuazAV-0.3.1-RUST-UNSIGNED-LOCAL-TEST-linux-x64.tar.gz`
- Each archive also has an archive-level `.sha256` sidecar. See `tools/package-rust-preview.ps1`.
- Both packages are **unsigned CI test artifacts only**, not installers or published production releases. Linux GUI requires compatible system display/graphics dependencies.

A successful CI build does **not** prove interactive GUI behavior on end-user machines; file picker, clipboard and cancellation still require real Windows/Linux manual smoke tests.

## Security / compatibility

See [security model](docs/security-model.md), [migration contract](docs/rust-migration.md) and [desktop preview](docs/windows-desktop-preview.md). The previous .NET v0.3.1 implementation remains available in git history on `main` until this Rust branch is explicitly merged. No automatic release.
