<!--
Dosya Yolu: REPO_ROOT/docs/rule-candidate-staging.md
Amac: Imzali kural paketlerini etkinlestirmeden gecici staging kontrati
Modul - FileType: Documentation - Markdown
Version: 0.3.1
Aciklama: Aday dogrulama, kaynak mutasyonu, no-overwrite ve eksik guven sinirlari
Bagimli Oldugu Katman: Service | Tool | Security
-->

# Signed YARA-X rule candidate staging (experimental)

`rust/src/rule_staging.rs` implements a bounded, **uncommitted**
candidate snapshot intended for a future protected rule updater. The
caller must supply an **independently authenticated** `TrustedKeyring`
and existing, absolute paths to the signed rule source, manifest,
signature, official pinned YARA-X engine, existing version state and
protected staging parent. The preview still ships no production root.

## What is guaranteed in the current library

- The parent staging directory must already exist and be a normal,
  non-reparse directory. Invalid or traversal-containing paths fail
  closed before candidate creation.
- The official engine SHA-256 is checked **without executing it**.
  Source rule, manifest and signature bytes are read with existing
  bounded regular-file checks and copied into a new randomized temporary
  directory using create-new and synchronized file writes.
- **The staged copies**, not merely the mutable original paths, are
  verified against the independent publisher keyring and signed rule
  digest. Mutating source files after staging does not change the
  candidate. Invalid signatures are rejected and ordinary failures
  clean up their temporary candidate.
- The existing 40-byte anti-rollback state is inspected **read-only**.
  Stale versions, same-sequence conflicting payloads and corrupt
  states are refused. No state file or lock is created or advanced.
- A successful result retains the temporary directory for the lifetime
  of `StagedRuleCandidate`. Dropping the value normally removes it.
  There is no active-rule overwrite, version commitment, engine
  execution, service restart or automatic downloading.

## No-clobber versioned publication

The library-only `rust/src/rule_publication.rs` can retain an already
verified candidate under a NEW deterministic version name. It checks
the signed staging snapshot, independently pinned YARA-X engine and
advisory 40-byte rollback record before reserving the destination
with `create_dir`. A preexisting directory, file or link at that name
is **not overwritten**. Files are written with `create_new` and synced,
the retained copies are independently signature-verified, and the
`CANDIDATE_READY` marker is created LAST.

The marker is **not authorization** to activate rules. It is not
proof of immutable files, a trusted publisher or crash-safe publish.
An error after reservation or power failure may leave an incomplete
directory. Later attempts refuse to overwrite that name. The API
neither deletes such residue nor changes active rules, rollback state
or the running service.

Concurrent writers and hostile filesystem actors are not excluded by
path-based checks. The 40-byte state inspection is advisory only.
Production activation still requires OS ACLs, no-follow handles,
a protected cross-process lock, a verified atomic activation pointer,
a durable power-loss journal and a recovery policy. Every reader MUST
verify signed contents and protected state again regardless of READY.

Real signed YARA-X E2E tests cover a published candidate, duplicate
version refusal, modified staged bytes, tampered retained contents and
state preservation.

## Limits before any production activation

This is **not** an atomic installer or verified permanent store.
An attacker with write access to the staging directory may modify a
candidate after verification. File path checks have filesystem race and
ancestor-symlink limitations. An interrupted process may leave orphan
temporary directories. The version snapshot is advisory and can race
other state writers; the real trusted scan and any future updater must
revalidate under an appropriate lock.

A production updater would need administrator-controlled ownership and
ACLs, handles or immutable verified snapshots, a transactional
no-clobber publish/activation protocol, a durable journal, recovery
after power loss, controlled retention/cleanup, a live state lock and
post-activation health checks. Never infer success from a staged hash,
and never use this API alone to replace `rules.yar`, `manifest.json`
or `rules.sig` in a live installation.

Hosted CI tests a throwaway publisher and real pinned YARA-X: valid
signed candidates, source changes after staging, bad signatures, stale
versions, state preservation and ordinary cleanup. These tests are not
OS-level ACL or crash-recovery acceptance.
