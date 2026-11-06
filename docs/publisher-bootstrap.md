<!--
Dosya Yolu: REPO_ROOT/docs/publisher-bootstrap.md
Amac: Imzali kural yayinici koklerinin bagimsiz guven ilkesini tanimlar
Modul - FileType: Documentation - Markdown
Version: 0.3.1
Aciklama: Yerel PEM verisi, uygulamaya sabitlenmis digest ve surum politikasi
Bagimli Oldugu Katman: Config | Service | Security
-->

# Publisher trust bootstrap (experimental)

## Scope

A public PEM file beside an unsigned rules package is **not** a trust
anchor. Neither user-supplied PEMs nor a `keyId` in an untrusted rule
manifest may authorize a publisher. `rust/src/publisher_bootstrap.rs`
contains a read-only loader for public PEM material that must match an
independently chosen, exact-byte SHA-256 digest pinned in the application
at build time. The existing `TrustedKeyring` then validates its RSA
public-key structure and minimum key size.

The preview binary deliberately has an **empty pinned publisher list**.
There is no production public/private key in this repository, build
artifact or runtime environment. Consequently signed-rule preflight
and YARA-X desktop analysis remain disabled in the unsigned preview.

## Expected layout for a future authenticated build

The application derives its per-user data root using the operating
system API, not an arbitrary environment-supplied publisher location:

```text
<OS local application data>/TurkuazAV/trusted-rules/
  publishers/
    <independently-pinned-key-id>.pem
  rules.yar
  manifest.json
  rules.sig
  state.bin                 # 40 bytes after a trusted scan
```

The official pinned YARA-X engine is separately located beside the
desktop executable; it must pass the existing executable SHA-256 check.
This layout is **not** an instruction to create a production
installation in a user-writable location. The production state and
rule directory require dedicated OS access controls and a safe updater.

## Secure activation requirements

1. Generate the **publisher private key outside the repository and CI
   artifacts**, in a dedicated controlled signing environment. Only
   the public key is distributable.
2. Independently authenticate the intended release publisher and
   choose the approved public PEM bytes and lower-case SHA-256 digest.
   Review that digest in code and build it into the trusted executable.
3. Sign and authenticate the application distribution separately
   (Windows code signing and appropriate platform verification). A
   SHA-256 digest inside an **unsigned** application is not independent
   proof of application authenticity.
4. Provision the matching public PEM file and rule package only via
   a controlled, privilege-appropriate installer/update transaction.
   Missing, oversized, malformed, linked, mismatched or unknown keys
   must fail closed; do **not** install or download missing trust
   anchors from the rule manifest.
5. Validate the signed rules, verified engine and protected 40-byte
   rollback state before allowing any local scan. The GUI's read-only
   preflight is advisory; the actual scan re-verifies independently.
6. Rotate publisher roots only through another authenticated application
   release with an explicit overlap/revocation policy. Do not let a
   downloaded rule package rotate or introduce roots.

## Test boundaries

The real YARA-X E2E test generates a throwaway RSA key, computes its
public PEM digest, provisions it under a private test directory and
checks that a valid signed package can be evaluated. It also checks
that replacing the local PEM is rejected and does not change the
version state. Unit tests cover invalid/duplicate IDs, malformed
digest pins and symlinked publisher paths on Unix. These tests do not
constitute production key provisioning or user-machine ACL testing.

The separate [candidate staging contract](rule-candidate-staging.md)
uses this independently provisioned keyring to validate staged rule
bytes. It never introduces roots, installs active rules, downloads
packages or advances version state.

No automatic download, key import dialog, privileged install, malware
verdict, real-time protection or quarantine is enabled by this change.
