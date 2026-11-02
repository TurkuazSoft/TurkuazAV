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

- **Rust Core**: SHA-256 file/directory scan, 100 MiB default per-file ceiling, skip symlinks/reparse points, cancellation and explicit error reporting.
- **Rust CLI**: `scan` and developer-only `scan-rules` commands.
- **YARA-X**: verifies RSA-PSS-SHA256 rule signature, snapshots rules and target, verifies pinned executable SHA-256 (Windows/Linux x64), bounded output and timeout.
- **Trusted publisher API**: independent pinned keyring, strict four-field manifest, canonical payload, signed rule digest and persistent 40-byte anti-rollback state (same contract as .NET 0.2.4).
- **Rust Desktop**: cross-platform egui GUI for *single file SHA-256 only*, file picker, cancel, read-only digest report, clipboard copy, maximum 20 in-memory session entries and redacted local diagnostics with 7-day retention.
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

CI: `.github/workflows/rust-ci.yml` on Windows 2022 and Ubuntu 24.04, including native GUI build and unsigned test artifact. CI build **does not** prove interactive GUI startup; manual OS smoke is separately required.

## Security / compatibility

See [security model](docs/security-model.md), [migration contract](docs/rust-migration.md) and [desktop preview](docs/windows-desktop-preview.md). The previous .NET v0.3.1 implementation remains available in git history on `main` until this Rust branch is explicitly merged. No automatic release.
