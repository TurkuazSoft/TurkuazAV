<!--
Dosya Yolu: REPO_ROOT/docs/installer-scan-contract.md
Amac: TurkuazInstaller ile TurkuazAV arasindaki cross-platform rule scan protokolu
Modul - Documentation Markdown
Version: 0.1.0
Aciklama: Sema v1, guven siniri, sonuc yorumu, CLI/adapter uyumu
Bagimli Oldugu Katman: Security | Tool | Integration
-->

# TurkuazAV installer rule-scan evidence v1

## CLI

`scan-rules-json TARGET RULES.YAR RULES.SIG PUBLIC.PEM ABSOLUTE_YR_PATH`

This experimental command uses the existing `RuleScanService` and pinned
YARA-X binary checks. It does **not** change the legacy `scan-rules`
text output or classify files as definitely malware-free.

On successful scan only, stdout contains one JSON object:

```json
{
  "schema": "turkuazav.rule-scan.v1",
  "status": "no_match",
  "sha256": "64-lowercase-hex-characters",
  "matches": []
}
```

`status` is `match` (at least one match) or `no_match` (zero
matches); the `matches` array provides the YARA-X rule identifiers.
JSON `sha256` refers to the original target path observed before and
after the scan, not to the detached rule bundle. The caller must bind
the result to its own immutable staged bytes and check the hash.
These checks mitigate ordinary concurrent file edits, not privileged
or adversarial filesystems with full write access.

Errors (invalid signature, untrusted YARA-X executable, oversized
file, timeout, malformed target) exit nonzero and do not emit success JSON.
The caller MUST validate process exit status, JSON schema, digest, matched
rule count and required fields; never infer a clean file from an empty
or missing report.

## Trust

The CLI receives a public key file from the caller. This validates an
RSA-PSS-SHA256 signature against that key but does **not** prove the key
is an independently trusted publisher. A production adapter must pin
the authorized public-key fingerprint from a separately protected trust
store, plus the identity/integrity of the AV binary itself. YARA-X is
already verified against the TurkuazAV platform-specific engine hash.

`no_match` does not mean virus-free, and trust in a signed rule bundle
does not guarantee its detection coverage. Therefore the Rust adapter
defaults to `BlockAsUnknown`; explicit accepting no-match must be
a deliberate local/operator policy with known rule coverage. A detection
match is at least Suspicious, not an automatic proven-virus assertion.

Cross-repository release automation, authenticated service provisioning,
malware verdict classification, sandboxing, real-time protection, and
macOS E2E are separate work. Do not enable mandatory production scan
until those controls pass real acceptance tests.
