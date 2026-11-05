// Dosya Yolu: REPO_ROOT/rust/src/source_evidence.rs
// Amac: Bagimsiz kaynak kanitlarini salt-okunur olarak toplamak
// Modul - FileType: Service - Rust
// Version: 0.3.1
// Aciklama: SHA-256 uzerinden sinirli, atifli ve hukumsuz kaynak sozlesmesi
// Bagimli Oldugu Katman: Service | Tool

use anyhow::{bail, Result};
use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicBool, Ordering},
};

const MAX_SOURCES: usize = 8;
const MAX_SOURCE_ID_BYTES: usize = 32;

/// "NoSignal" is not a clean verdict. Providers are not trusted scan engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceSignal {
    Signal,
    NoSignal,
    Unavailable,
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

/// An adapter may use a configured provider, but must not upload file contents.
/// Implementations own authentication, timeouts and privacy enforcement.
pub trait EvidenceSource {
    fn id(&self) -> &str;
    fn lookup_sha256(&self, sha256: &str, cancelled: &AtomicBool) -> Result<SourceSignal>;
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_source_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SOURCE_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// @dev-id TAV-SOURCE-EVIDENCE-001
/// @purpose Collect bounded provider observations without making a threat verdict.
/// @reason Independent data sources can be stale, unavailable or contradictory.
/// @contract No file paths/content, no persisted state, no automatic protection.
/// Source failures become Unavailable, never NoSignal or "clean".
pub fn collect_source_evidence(
    sha256: &str,
    sources: &[&dyn EvidenceSource],
    cancelled: &AtomicBool,
) -> Result<SourceEvidenceReport> {
    if !valid_digest(sha256) {
        bail!("Invalid SHA-256 digest");
    }
    if sources.len() > MAX_SOURCES {
        bail!("Too many evidence sources");
    }
    let mut seen = BTreeSet::new();
    for source in sources {
        if !valid_source_id(source.id()) || !seen.insert(source.id()) {
            bail!("Invalid or duplicate evidence source");
        }
    }

    let mut observations = Vec::with_capacity(sources.len());
    for source in sources {
        if cancelled.load(Ordering::Relaxed) {
            bail!("Evidence collection cancelled");
        }
        let signal = source
            .lookup_sha256(sha256, cancelled)
            .unwrap_or(SourceSignal::Unavailable);
        if cancelled.load(Ordering::Relaxed) {
            bail!("Evidence collection cancelled");
        }
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

    struct Fixture<'a> {
        name: &'a str,
        result: SourceSignal,
        calls: &'a AtomicUsize,
        fail: bool,
    }

    impl EvidenceSource for Fixture<'_> {
        fn id(&self) -> &str { self.name }
        fn lookup_sha256(&self, sha256: &str, _: &AtomicBool) -> Result<SourceSignal> {
            assert_eq!(sha256, DIGEST);
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.fail { Err(anyhow!("do not expose provider secrets")) }
            else { Ok(self.result) }
        }
    }

    #[test]
    fn independent_observations_do_not_create_a_malware_verdict() {
        let calls = AtomicUsize::new(0);
        let a = Fixture { name: "provider_a", result: SourceSignal::Signal, calls: &calls, fail: false };
        let b = Fixture { name: "provider_b", result: SourceSignal::NoSignal, calls: &calls, fail: false };
        let report = collect_source_evidence(DIGEST, &[&a, &b], &AtomicBool::new(false)).unwrap();
        assert_eq!(report.observations.len(), 2);
        assert_eq!(report.observations[0].signal, SourceSignal::Signal);
        assert_eq!(report.observations[1].signal, SourceSignal::NoSignal);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn provider_failure_is_unavailable_not_no_signal() {
        let calls = AtomicUsize::new(0);
        let failed = Fixture { name: "provider_a", result: SourceSignal::NoSignal, calls: &calls, fail: true };
        let report = collect_source_evidence(DIGEST, &[&failed], &AtomicBool::new(false)).unwrap();
        assert_eq!(report.observations[0].signal, SourceSignal::Unavailable);
    }

    #[test]
    fn invalid_input_or_duplicate_sources_never_call_adapters() {
        let calls = AtomicUsize::new(0);
        let a = Fixture { name: "provider_a", result: SourceSignal::Signal, calls: &calls, fail: false };
        assert!(collect_source_evidence("bad", &[&a], &AtomicBool::new(false)).is_err());
        assert!(collect_source_evidence(DIGEST, &[&a, &a], &AtomicBool::new(false)).is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cancellation_prevents_evidence_disclosure() {
        let calls = AtomicUsize::new(0);
        let a = Fixture { name: "provider_a", result: SourceSignal::Signal, calls: &calls, fail: false };
        assert!(collect_source_evidence(DIGEST, &[&a], &AtomicBool::new(true)).is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }
}
