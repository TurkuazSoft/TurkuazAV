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
- `rust/src/scanner.rs`: product-level ScannerBackend API, SHA-256 adapter and signed YARA-X adapter, cancellation guard and path-free ScannerReport
- `rust/src/threat.rs`: neutral threat category, coverage, verdict and bounded evidence model; never creates a clean or malware verdict from hash/rule matches
- `rust/src/source_evidence.rs`: bounded local SHA-256 evidence collection and digest/provider-scoped opt-in contract for future remote providers; no network adapter wired by default
- `rust/src/virustotal.rs`: provider-specific hash-only v3 report adapter with a fixed HTTPS endpoint, generic bounded response parser and injected (not yet implemented) HTTPS transport
- `rust/src/policy.rs`: pure advisory decisions from ScannerReport; incomplete or inconsistent evidence requests another analysis, never automatic blocking
- `rust/src/monitor.rs`: bounded read-only SHA-256 directory polling and in-memory delta state
- `rust/src/native_events.rs`: opt-in Windows recursive change notification / Linux inotify root notification hint adapter; periodic full-tree polling fallback remains authoritative, no daemon or blocking hook
- `rust/src/service.rs`: bounded one-slot atomic reconciliation request, independent trigger handle, failure/cancel replay, root-scoped scanning
- `rust/src/worker.rs`: opt-in owned background thread with periodic reconciliation, bounded retry, path-free health counters, cooperative cancel/join
- `rust/src/bin/service_host.rs`: separate read-only service process, Linux SIGTERM/foreground and Windows SCM STOP/SHUTDOWN entrypoints, opt-in only
- `deploy/service/turkuazav-preview.service`: uninstalled Linux systemd hardening/restart-policy example, not an active service
- `tools/test-service-scm-ci.ps1` / `tools/test-service-systemd-ci.sh`: CI-only privileged ephemeral SCM/systemd acceptance tests on trusted GitHub-hosted runners with cleanup; Windows CI additionally validates restart-only SCM crash recovery and regular STOP not triggering recovery; both verify offline service executable switchover/rollback against a staged trusted-hash copy and reject a corrupt candidate before configuration changes
- `rust/src/rules.rs`: RSA-PSS-SHA256 verification, bounded snapshots, engine hash validation, subprocess timeout/output limit and NDJSON parsing
- `rust/src/trusted.rs`: strict manifest parser, pinned publisher keyring, canonical signed payload and protected anti-rollback 40-byte format
- `rust/src/bin/cli.rs`: console controller and textual report
- `rust/src/bin/desktop.rs`: native UI, in-memory session history, clipboard and privacy-preserving diagnostics

## Scanner naming and dependency boundaries

The **TurkuazAV Scanner** is the product's generic scan capability; **YARA-X**
remains the upstream engine name and must not be renamed in binary pins,
signed manifest contracts, developer CLI commands or vendor attribution.

```text
CLI / Desktop / Service (existing entry points preserved)
                |
   ScannerBackend -> ScannerReport -> ThreatAssessment
      |                                  (no blocking policy)
      +-- Sha256Scanner -> scan.rs (read-only digest)
      +-- TrustedYaraXScanner -> trusted.rs -> rules.rs -> YARA-X binary
                                    |             |
                             verified publisher   pinned executable hash
```

This is a single Rust crate with typed adapters, not an Apache-style cluster
or a new background service. The adapter boundary is optional for existing
callers: legacy APIs remain source- and CLI-compatible, and desktop continues
to show SHA-256 only. ScannerReport contains the engine identifier and a
path-free assessment. It carries no authority to block, quarantine or
persist files. Only the existing trusted signed-rule path can be used by the
new YARA-X adapter; the developer-only `scan-rules` CLI is NOT promoted to
a trusted publisher path.

## Independent source evidence and privacy

The provider evidence contract is separate from the trusted YARA-X scan path.
By default, `collect_source_evidence` rejects every source that declares
`SourceLocation::Remote`. A controller can pass an
`ExternalLookupApproval` only for one exact SHA-256 digest and explicitly
selected provider IDs. The request is prevalidated before any provider runs,
so a later denied provider cannot leak a digest after an earlier local lookup.

The approval struct only checks scope: **the caller must first obtain genuine
user consent**. No UI consent workflow, HTTP adapter, endpoint allowlist,
credential storage or actual remote provider integration exists yet.
Adapter classifications must be implemented by trusted application code;
a dishonest implementation could misdeclare itself local. Raw file contents
and local paths never enter this API. SHA-256 itself can be sensitive metadata
when disclosed externally.

Adapters receive a 3-second **cooperative** budget and cancellation token.
The collector converts a late returned observation or provider error into
`Unavailable`, but cannot interrupt a blocking network call. A future
transport must independently enforce connection/read/overall timeouts,
TLS validation, fixed provider endpoints, response-size bounds and disabled
redirects before remote lookups can be enabled.

`Signal`, `NoSignal` and `Unavailable` remain attributed observations,
not antivirus verdicts, threat-family assertions or authorization to block
or quarantine files. The default preview performs no remote lookups.

### VirusTotal report adapter (contract and fixture tests only)

The optional `VirusTotalHashSource` implements `EvidenceSource` as a
**remote** source, so the existing SHA-256/provider-scoped approval is
required *before* a transport is invoked. Its only endpoint is the fixed
`GET https://www.virustotal.com/api/v3/files/{sha256}`. The API credential
is injected at runtime into an `x-apikey` header; neither the credential nor
a local path enters the URL or reports. No file bytes are uploaded.

The `HttpsGetTransport` contract requires TLS certificate/hostname
verification, redirects disabled, a 1-second connect and 3-second overall
budget, plus a 512 KiB response limit **while receiving**. The adapter also
checks the returned body size, JSON shape, matching SHA-256 and nonempty
analysis counters. Missing reports, rate limits, non-200 responses, oversized
or malformed JSON, or mismatched digests become `Unavailable`. Vendor
detections are represented only as `Signal` or `NoSignal`; they never grant
quarantine/blocking authority. A `NoSignal` observation is not a clean
verdict. No automatic retries or pagination are performed.

**There is no concrete network transport or UI consent workflow yet.**
The request policy is tested with an in-memory fake. An actual implementation
must prove TLS enforcement, redirects/proxies policy, hard timeouts,
bounded decompression, cancellation and secret redaction with separate
integration tests before it is exposed in the desktop.

The VirusTotal public API has noncommercial usage restrictions and quotas.
Commercial distribution requires the appropriate licensed API agreement;
this preview must not enable it by default. See the
[official API endpoint](https://docs.virustotal.com/reference/file-info)
and [API usage terms](https://docs.virustotal.com/docs/difference-public-private).

The policy layer is intentionally read-only: `advise(&ScannerReport)`
checks the reported engine, scan coverage and evidence consistency.
It can suggest manual review, no automatic action or a retry, but exposes
no quarantine, deletion or process-control interface. The desktop now uses
this same policy when deciding whether to display trusted YARA-X evidence.
The ScannerId field alone does not authenticate the origin of a report;
existing publisher signature and pinned executable verification remain
the security boundary.

The core principles borrowed from mature Apache projects are small public
interfaces, clear responsibilities, explicit error behavior, isolated
adapters and automated contract tests. We do not copy project-specific
Apache infrastructure or introduce extra crates solely for layering.

Rust modules retain logical Controller / Service / Repository / Tool / View / Config separation. No permanent scan history and no automatic malware verdict. YARA-X uses a pinned external executable; integration is deliberately library-controlled and independent of UI. A production-provisioned trust root is still required.

When copying a mutable target for YARA-X, the snapshot may contain concurrent writes; additional filesystem and process isolation is needed for production antivirus uses.

See the [security model](security-model.md), [desktop preview](windows-desktop-preview.md) and the root [test guide](../TEST_KILAVUZU_TR.md).
