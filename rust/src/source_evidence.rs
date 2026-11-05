// Dosya Yolu: REPO_ROOT/rust/src/source_evidence.rs
// Amac: Bagimsiz kaynak kanitlarini salt-okunur olarak toplamak
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: SHA-256 kaniti, kaynak bazli erisim onayi ve sinirli lookup kontrati
// Bagimli Oldugu Katman: Service | Tool

use anyhow::{bail, Result};
use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const MAX_SOURCES: usize = 8;
const MAX_SOURCE_ID_BYTES: usize = 32;
const COOPERATIVE_LOOKUP_BUDGET: Duration = Duration::from_secs(3);

/// Neither a signal nor its absence establishes a clean or malicious verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceSignal {
    Signal,
    NoSignal,
    Unavailable,
}

/// Remote hash lookups disclose a file fingerprint to a third party.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLocation {
    Local,
    Remote,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceObservation {
    pub source_id: String,
    pub signal: SourceSignal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEvidenceReport {
    pub observations: Vec<SourceObservation>,
}

/// Scoped permission for exactly one digest and an explicit provider list.
///
/// This type validates an approval supplied by the caller. Only the UI or
/// application controller can verify that the user actually consented.
/// Creating this value never performs a network request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalLookupApproval {
    digest: String,
    approved_sources: BTreeSet<String>,
}

impl ExternalLookupApproval {
    pub fn new(sha256: &str, approved_sources: &[&str]) -> Result<Self> {
        if !valid_digest(sha256) {
            bail!("Invalid SHA-256 digest");
        }
        if approved_sources.is_empty() || approved_sources.len() > MAX_SOURCES {
            bail!("Invalid external source count");
        }

        let mut approved = BTreeSet::new();
        for source in approved_sources {
            if !valid_source_id(source) || !approved.insert((*source).to_owned()) {
                bail!("Invalid or duplicate external source");
            }
        }

        Ok(Self {
            digest: sha256.to_ascii_uppercase(),
            approved_sources: approved,
        })
    }

    fn permits(&self, sha256: &str, source_id: &str) -> bool {
        self.digest.eq_ignore_ascii_case(sha256) && self.approved_sources.contains(source_id)
    }
}

/// Provider implementations must not upload file content or raw paths.
/// The budget is cooperative, not a hard deadline: a future network adapter
/// must configure its own transport-level timeouts and disable redirects.
pub trait EvidenceSource {
    fn id(&self) -> &str;
    fn location(&self) -> SourceLocation;
    fn lookup_sha256(
        &self,
        sha256: &str,
        budget: Duration,
        cancelled: &AtomicBool,
    ) -> Result<SourceSignal>;
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|character| character.is_ascii_hexdigit())
}

fn valid_source_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SOURCE_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// @dev-id TAV-SOURCE-EVIDENCE-001
/// @purpose Collect bounded evidence with remote requests disabled by default.
/// @reason A hash lookup itself discloses information and no match is not clean.
/// @contract No network transport, persistence, verdict or protection actions.
/// Provider failures and expired cooperative budgets become Unavailable.
pub fn collect_source_evidence(
    sha256: &str,
    sources: &[&dyn EvidenceSource],
    cancelled: &AtomicBool,
) -> Result<SourceEvidenceReport> {
    collect(sha256, sources, None, cancelled)
}

/// @dev-id TAV-SOURCE-EVIDENCE-002
/// @purpose Allow only explicitly scoped external hash queries.
/// @reason Consent for one digest and provider cannot silently expand.
/// @contract Caller verifies actual user consent; this module never performs
/// network I/O or guarantees wall-clock timeout for a blocking adapter.
pub fn collect_source_evidence_with_approval(
    sha256: &str,
    sources: &[&dyn EvidenceSource],
    approval: &ExternalLookupApproval,
    cancelled: &AtomicBool,
) -> Result<SourceEvidenceReport> {
    collect(sha256, sources, Some(approval), cancelled)
}

fn collect(
    sha256: &str,
    sources: &[&dyn EvidenceSource],
    approval: Option<&ExternalLookupApproval>,
    cancelled: &AtomicBool,
) -> Result<SourceEvidenceReport> {
    if !valid_digest(sha256) {
        bail!("Invalid SHA-256 digest");
    }
    if sources.len() > MAX_SOURCES {
        bail!("Too many evidence sources");
    }

    // Validate the entire request before calling even the first adapter.
    let mut seen = BTreeSet::new();
    for source in sources {
        if !valid_source_id(source.id()) || !seen.insert(source.id()) {
            bail!("Invalid or duplicate evidence source");
        }
        if source.location() == SourceLocation::Remote
            && !approval.is_some_and(|value| value.permits(sha256, source.id()))
        {
            bail!("External hash lookup not approved");
        }
    }

    let mut observations = Vec::with_capacity(sources.len());
    for source in sources {
        if cancelled.load(Ordering::Relaxed) {
            bail!("Evidence collection cancelled");
        }
        let started = Instant::now();
        let result = source.lookup_sha256(sha256, COOPERATIVE_LOOKUP_BUDGET, cancelled);
        if cancelled.load(Ordering::Relaxed) {
            bail!("Evidence collection cancelled");
        }
        let signal = if started.elapsed() > COOPERATIVE_LOOKUP_BUDGET {
            SourceSignal::Unavailable
        } else {
            result.unwrap_or(SourceSignal::Unavailable)
        };
        observations.push(SourceObservation {
            source_id: source.id().to_owned(),
            signal,
        });
    }

    Ok(SourceEvidenceReport { observations })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use std::sync::atomic::AtomicUsize;

    const DIGEST: &str = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
    const OTHER_DIGEST: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

    struct Fixture<'a> {
        name: &'a str,
        location: SourceLocation,
        result: SourceSignal,
        calls: &'a AtomicUsize,
        fail: bool,
        cancel_on_call: bool,
    }

    impl EvidenceSource for Fixture<'_> {
        fn id(&self) -> &str {
            self.name
        }

        fn location(&self) -> SourceLocation {
            self.location
        }

        fn lookup_sha256(
            &self,
            sha256: &str,
            budget: Duration,
            cancelled: &AtomicBool,
        ) -> Result<SourceSignal> {
            assert!(valid_digest(sha256));
            assert_eq!(budget, COOPERATIVE_LOOKUP_BUDGET);
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.cancel_on_call {
                cancelled.store(true, Ordering::Relaxed);
            }
            if self.fail {
                Err(anyhow!("do not expose provider secrets"))
            } else {
                Ok(self.result)
            }
        }
    }

    fn fixture<'a>(
        name: &'a str,
        location: SourceLocation,
        calls: &'a AtomicUsize,
    ) -> Fixture<'a> {
        Fixture {
            name,
            location,
            result: SourceSignal::Signal,
            calls,
            fail: false,
            cancel_on_call: false,
        }
    }

    #[test]
    fn independent_local_observations_never_claim_a_verdict() {
        let calls = AtomicUsize::new(0);
        let a = fixture("source_a", SourceLocation::Local, &calls);
        let mut b = fixture("source_b", SourceLocation::Local, &calls);
        b.result = SourceSignal::NoSignal;
        let report = collect_source_evidence(DIGEST, &[&a, &b], &AtomicBool::new(false)).unwrap();

        assert_eq!(report.observations.len(), 2);
        assert_eq!(report.observations[0].signal, SourceSignal::Signal);
        assert_eq!(report.observations[1].signal, SourceSignal::NoSignal);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn remote_sources_are_denied_without_explicit_digest_scoped_approval() {
        let calls = AtomicUsize::new(0);
        let local = fixture("local", SourceLocation::Local, &calls);
        let remote = fixture("remote_a", SourceLocation::Remote, &calls);
        let cancelled = AtomicBool::new(false);

        assert!(collect_source_evidence(DIGEST, &[&local, &remote], &cancelled).is_err());
        let wrong_digest = ExternalLookupApproval::new(OTHER_DIGEST, &["remote_a"]).unwrap();
        assert!(collect_source_evidence_with_approval(
            DIGEST,
            &[&local, &remote],
            &wrong_digest,
            &cancelled,
        )
        .is_err());
        let wrong_source = ExternalLookupApproval::new(DIGEST, &["remote_b"]).unwrap();
        assert!(collect_source_evidence_with_approval(
            DIGEST,
            &[&remote],
            &wrong_source,
            &cancelled,
        )
        .is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn explicitly_approved_remote_source_is_attributed() {
        let calls = AtomicUsize::new(0);
        let remote = fixture("remote_a", SourceLocation::Remote, &calls);
        let approval = ExternalLookupApproval::new(DIGEST, &["remote_a"]).unwrap();
        let report = collect_source_evidence_with_approval(
            DIGEST,
            &[&remote],
            &approval,
            &AtomicBool::new(false),
        )
        .unwrap();

        assert_eq!(report.observations[0].source_id, "remote_a");
        assert_eq!(report.observations[0].signal, SourceSignal::Signal);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn failures_remain_unavailable_not_clean() {
        let calls = AtomicUsize::new(0);
        let mut failed = fixture("local", SourceLocation::Local, &calls);
        failed.fail = true;
        let report = collect_source_evidence(DIGEST, &[&failed], &AtomicBool::new(false)).unwrap();
        assert_eq!(report.observations[0].signal, SourceSignal::Unavailable);
    }

    #[test]
    fn invalid_input_duplicate_sources_and_invalid_approval_are_fail_closed() {
        let calls = AtomicUsize::new(0);
        let a = fixture("local", SourceLocation::Local, &calls);
        let cancelled = AtomicBool::new(false);

        assert!(collect_source_evidence("bad", &[&a], &cancelled).is_err());
        assert!(collect_source_evidence(DIGEST, &[&a, &a], &cancelled).is_err());
        assert!(ExternalLookupApproval::new(DIGEST, &[]).is_err());
        assert!(ExternalLookupApproval::new(DIGEST, &["remote_a", "remote_a"]).is_err());
        assert!(ExternalLookupApproval::new(DIGEST, &["invalid/url"]).is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cancellation_never_returns_partial_evidence() {
        let calls = AtomicUsize::new(0);
        let mut a = fixture("source_a", SourceLocation::Local, &calls);
        let b = fixture("source_b", SourceLocation::Local, &calls);
        let cancelled = AtomicBool::new(true);
        assert!(collect_source_evidence(DIGEST, &[&a], &cancelled).is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 0);

        cancelled.store(false, Ordering::Relaxed);
        a.cancel_on_call = true;
        assert!(collect_source_evidence(DIGEST, &[&a, &b], &cancelled).is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}
