<!--
Dosya Yolu: REPO_ROOT/docs/security-model.md
Amac: Rust signed-rule trust ve anti-rollback guven kontrati
Modul - FileType: Documentation - Markdown
Version: 0.3.1
Aciklama: Rust imza dogrulama, state semasi ve guvenlik sinirlari
Bagimli Oldugu Katman: Service | Repo | Tool | Config
-->
# TurkuazAV Rust Security Model

This v0.3.1 experimental implementation is not a full antivirus. It does not provide real-time blocking or malware verdicts.

## Signed rule package contract (v1)

1. Publisher keys are pinned by an independently trusted application bootstrap, never by the untrusted manifest or public-key CLI argument.
2. Strict manifest fields: `schema`, `sequence` (positive signed 64-bit integer), `keyId`, `rulesSha256` (64 lower-case hex characters).
3. Canonical RSA-PSS-SHA256 signature input: `TurkuazAV.rule-package.v1\n<sequence>\n<keyId>\n<rulesSha256>\n`.
4. Verify key ID and RSA key strength (at least 2048-bit), signature and content hash before providing rule bytes to the engine.
5. Store verified rule bytes and bounded target snapshot in a temporary private directory; stage a bounded private executable copy and verify **the staged bytes** against the pinned official YARA-X SHA-256 before spawning it.
6. Only after successful real engine execution and validated NDJSON output, commit the anti-rollback state.
7. Persistent state has exactly 40 bytes: 8-byte little-endian positive sequence + 32-byte SHA-256 canonical-payload fingerprint. Older sequences and same-sequence/different-payload are denied. Invalid 8-byte-only records fail closed.

The storage location must be protected by host permissions. Cooperative writers lock a stable sibling `.lock` file, stage the 40-byte record in the same directory, fsync the staging file and atomically replace the state (plus directory sync on Unix). An existing 0-byte state is now corruption, while a missing state can bootstrap a new installation. Atomic updates reduce partial-write exposure but cannot defeat privileged state deletion/rollback, filesystem compromise or power-loss guarantees on every Windows filesystem. No automatic repair or conversion of an invalid state record occurs.

## Incomplete production controls

Publisher trust-root provisioning, secure signed key rotation, protected service installation, process sandboxing and full process-tree termination, remaining local privilege/temporary-directory tamper hardening, target filesystem TOCTOU hardening, additional filesystem fault-injection and crash/power-loss testing, fuzz and performance coverage, real interactive GUI smoke, production signing, quarantine and real-time blocking.

Do not run unsigned preview artifacts as the device's only endpoint protection.

## Service executable update verification (separate from rule updates)

`rust/src/update.rs` exposes only a **read-only** signed service-update verifier. Domain-separated RSA-PSS-SHA256 covers strict signed metadata (schema, monotonically increasing sequence, independently trusted publisher ID, numeric version, OS, arch, executable length and digest). A bounded snapshot of the verified bytes is returned so the original user-controlled path does not need to be trusted again. The verifier checks a separate 40-byte service-update anti-rollback state but **does not advance it**; only a future trusted installer could commit an accepted update after installation and successful service health acceptance.

The optimistic state check may race a cooperating writer; a real installer must take the protected state lock and re-check before an atomic install and commit. A rollback journal, crash consistency for switching executable targets, publisher key provisioning/rotation, OS code signing, elevated provisioning and real version-to-version migration are not implemented. A SHA-256 digest alone or a caller-supplied PEM is **not** a production publisher trust root.

## Service update transaction preview

`rust/src/update_transaction.rs` stages an already signed and verified executable snapshot in a caller-protected absolute install directory. It applies an exclusive cooperative `.txn.lock`, checks for stale version/replay, persists a versioned no-clobber executable, hashes the persisted bytes, then calls the `ServiceActivation` adapter's activate and health methods. Health failures trigger an in-process best-effort rollback. Only successful acceptance calls the existing 40-byte anti-rollback state writer; **state commit errors are not automatically rolled back** because the atomic replacement may already have taken effect.

This preview deliberately ships **no real platform activation adapter**. The provided test-only adapter models failure cases without controlling any OS service. The transaction lock does not prevent other privileged code from writing the version state via a different API. A synchronized, protected pending-update marker now blocks a subsequent transaction if an earlier operation was interrupted or could not be reconciled. Pre-activation validation additionally rejects state-file names colliding with the pending marker, transaction lock or its sidecar, staging namespace and any versioned service executable and the existing active service path; traversal components are refused. These checks avoid known configuration collisions but do not replace OS ACL/handle-based TOCTOU protection. It records only diagnostic identity, never authority to restore or execute an untrusted path. A full crash-recovery journal and replay-safe automatic recovery remain unimplemented.

A separate read-only pending-state inspector now rejects malformed, oversized or redirected records and reports whether the protected 40-byte sequence/fingerprint matches the pending marker. Versioned v2 records include bounded candidate size and SHA-256 evidence, which is recomputed during inspection; v1 records remain readable but are explicitly unverified. The candidate is matched against its expected versioned filename and symlink/reparse candidates are refused. This local marker is not itself publisher-signed, so a hash match is diagnostic only, not proof of authorization. It does not follow paths embedded in the marker, clear the latch, or authorize rollback. Inspection may race writers and is **not** an automatic crash-recovery mechanism.

Process-restart recovery, durable pointer updates, ACL provisioning and signer root bootstrap are incomplete: do not connect the transaction to a production SCM/systemd service until these safeguards are implemented and separately tested.
