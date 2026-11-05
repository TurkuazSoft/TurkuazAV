<!--
Dosya Yolu: REPO_ROOT/docs/threat-assessment-model.md
Amac: TurkuazAV tehdit taksonomisi ve kanit modeli sozlesmesini aciklar
Modul - FileType: Documentation - Markdown
Version: 0.3.1
Aciklama: Hash/YARA-X raporlamasi, guvenlik sinirlari ve harici motor karari
Bagimli Oldugu Katman: Service | Documentation
-->

# Threat Assessment Model (experimental)

## Scope

`rust/src/threat.rs` provides a small, side-effect-free representation for a future
multi-source detection pipeline. No external API, database, driver, blocking,
quarantine or real-time protection is added by this change. Existing CLI, desktop,
service and signed-rule pipelines retain their previous behavior.

`ThreatAssessment::from_hash_scan` records scan coverage and an optional valid
SHA-256 digest. It ALWAYS returns `not_evaluated` with category `unknown`.
Skipped, failed and invalid digest results never retain a digest.

`ThreatAssessment::from_rule_scan` records a bounded, deduplicated set of YARA-X
rule IDs. Any nonempty result is `requires_review`, never a malware verdict.
Empty results are `not_evaluated`, not `clean`. No threat family or severity is
guessed from the rule identifier. This adapter does not assert that rules came
from a trusted package: that must be verified by the caller's existing signed
rule flow before its result can be trusted.

## Product scanner adapters

`rust/src/scanner.rs` adds a small `ScannerBackend` trait and a
`ScannerReport` wrapper with an engine ID. `Sha256Scanner` delegates to the
existing bounded hash implementation and never assigns a malware verdict.
`TrustedYaraXScanner` delegates **only** to the existing
`scan_trusted_rules_with_cancel` trust chain, which checks signed rule
packages and the pinned executable; the developer-only YARA-X path is not
used. It produces review evidence, not a blocking decision.

A cancellation before or after adapter execution returns an error and no
`ScannerReport`. The report serializes the engine ID and assessment only;
file paths, raw rule payloads, engine paths and publisher secrets are absent.
The original scan, CLI and GUI APIs stay unchanged. No automatic multiengine
correlation is attempted, and no new persistent state schema is introduced.
The YARA-X component retains its vendor name; **Scanner** names the
product-level abstraction.

## Contracts and boundaries

- `AnalysisCoverage`: `completed`, `skipped`, `failed`.
- `ThreatVerdict`: `not_evaluated`, `requires_review`.
- `ThreatCategory`: taxonomy only; all results currently default to `unknown`.
- `ThreatEvidence`: rule identifier only, maximum 32 and no file path.
- Data is serializable with stable snake_case enum values.
- No automatic action, clean verdict, malicious verdict, network request or cloud upload.
- No attempt to join hash and YARA results across files. Future aggregation must
  bind evidence to the same verified target snapshot to avoid mismatched files.
- External threat feed labels and automatic response must not be introduced
  until source licenses, signatures, provenance, expiry, false-positive handling,
  user consent and rollback are separately specified and tested.

## Why not use an Apache antivirus?

- Apache Metron was retired in December 2020:
  https://attic.apache.org/projects/metron.html
- Apache Spot was retired on 2023-03-17:
  https://incubator.apache.org/projects/spot.html
- Apache NiFi is an active data pipeline platform, not an endpoint antivirus:
  https://nifi.apache.org/
- Apache SpamAssassin is for email filtering, not executable file scanning:
  https://spamassassin.apache.org/
- ClamAV is a separate project maintained by Cisco, not Apache, and has GPLv2
  integration/distribution considerations:
  https://docs.clamav.net/

Do not embed ClamAV or add a new Apache service to the 0.3.1 baseline.
A future external engine adapter must be independently reviewed for license,
process isolation, update authenticity, Windows support, and false positives.

## Verification

Automatic tests in `rust/src/scanner.rs` verify scanner labels, read-only hash reports, cancellation and trusted YARA-X fail-closed behavior.

Automatic tests in `rust/src/threat.rs` check that hash-only results never
claim malware safety, failures discard digests, YARA matches do not assign
families or blocking decisions, evidence remains bounded, and serialized
reports do not contain paths.

Run `cargo fmt --all -- --check`,
`cargo test --locked --lib`, and
`cargo clippy --locked --lib --tests -- -D warnings`.
Build and OS-specific native desktop tests remain separate CI responsibilities.

## Future change sequence

1. Add source attribution and trust decisions behind typed adapters, without
   accepting external feed content as executable rules.
2. Correlate hashed files and trusted YARA matches on a verified target snapshot.
3. Add an explicit policy engine (review first) and false-positive appeals.
4. Only after independent testing, consider a quarantining or blocking adapter.

Do not treat this model as a finished antivirus detection engine.
