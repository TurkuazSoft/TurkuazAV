<!--
Dosya Yolu: REPO_ROOT/AGENTS.md
Amac: TurkuazAV Rust icin DevStandards v3.0.0 gelistirme kontrati
Modul - FileType: Documentation - Markdown
Version: 3.0.0
Aciklama: Rust native guvenlik uygulamasi kurallari
Bagimli Oldugu Katman: Documentation
-->
# TurkuazAV - Project Agent Contract

**BURAK DEV STANDARD v3.0.0:** pinned `72f6f642128fa29ec9a68b18881e9aa225739c9d`.
**Source:** https://github.com/TurkuazSoft/DevStandards/tree/72f6f642128fa29ec9a68b18881e9aa225739c9d
**Teknoloji:** Rust native; `platforms/rust.md`. User-facing TR remains correct UTF-8.

## Obligations

- Read `AGENTS.md`, project branches/PR/CI and linked central standard before changes.
- Maintain safety, read-only baseline, 0.3.1 protocol, signing and version-state compatibility.
- Rust modules keep Service / Repository / Tool / View / Config responsibilities.
- Use standard file metadata where format allows; Markdown metadata lives in HTML comments.
- Do not hardcode system-specific absolute runtime paths or commit secrets.
- Run cargo fmt, clippy, unit/contract, real YARA-X E2E and OS-specific GUI smoke as available.
- Unrun tests are NOT success; artifacts are NOT releases.
- Never auto-merge, publish a release or modify other repos.
- Never use personal self-hosted runners on untrusted fork PR code.

## Security-specific

Publisher trust root must be independently bootstrapped, not accepted from untrusted manifests.
Verified version state 40-byte contract is fail-closed; no silent migration.
Engine executable hash pin and signed rules must pass before launching YARA-X.
Do not claim malware verdict or real-time antivirus until actual protection exists.
