// Dosya Yolu: REPO_ROOT/rust/src/virustotal.rs
// Amac: VirusTotal SHA-256 raporunu salt-okunur kaynak kanitina donusturmek
// Modul - FileType: Tool - Rust
// Version: 0.3.1
// Aciklama: Sabit HTTPS endpoint, sinirli JSON ayrisma ve bagimsiz transport sozlesmesi
// Bagimli Oldugu Katman: Tool | Service

use crate::source_evidence::{EvidenceSource, SourceLocation, SourceSignal};
use anyhow::{bail, Result};
use serde_json::Value;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

const SOURCE_ID: &str = "virustotal";
const FILE_REPORT_URL: &str = "https://www.virustotal.com/api/v3/files/";
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_ENGINE_COUNT: u64 = 10_000;
const MAX_LOOKUP_TIME: Duration = Duration::from_secs(3);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

/// This type deliberately does not implement Debug because it holds a secret.
/// The future transport must verify HTTPS certificates and hostnames, disable
/// redirects and enforce response-byte limits during reading.
pub struct HttpsGetRequest<'a> {
    pub url: String,
    pub header_name: &'static str,
    pub header_value: &'a str,
    pub total_timeout: Duration,
    pub connect_timeout: Duration,
    pub max_response_bytes: usize,
    pub follow_redirects: bool,
}

#[derive(Clone)]
pub struct HttpsGetResponse {
    pub status_code: u16,
    pub body: Vec<u8>,
}

/// This is a contract, not a live HTTP client. Implementors must enforce
/// TLS hostname/certificate validation, no redirects, bounded reads, timeouts
/// and avoid leaking authentication headers in errors or logs.
pub trait HttpsGetTransport {
    fn get(
        &self,
        request: &HttpsGetRequest<'_>,
        cancelled: &AtomicBool,
    ) -> Result<HttpsGetResponse>;
}

/// A read-only provider adapter, not wired into the default desktop or CLI.
/// The caller supplies a key at runtime and must obtain genuine user consent.
pub struct VirusTotalHashSource<'a, T: HttpsGetTransport + ?Sized> {
    transport: &'a T,
    api_key: &'a str,
}

impl<'a, T: HttpsGetTransport + ?Sized> VirusTotalHashSource<'a, T> {
    pub fn new(transport: &'a T, api_key: &'a str) -> Result<Self> {
        if api_key.is_empty()
            || api_key.len() > 256
            || !api_key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            bail!("Invalid provider credential");
        }
        Ok(Self { transport, api_key })
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn stat(stats: &Value, key: &str) -> Result<u64> {
    match stats.get(key).and_then(Value::as_u64) {
        Some(count) if count <= MAX_ENGINE_COUNT => Ok(count),
        _ => bail!("Invalid provider report"),
    }
}

/// @dev-id TAV-VT-HASH-001
/// @purpose Interpret a bounded file report without claiming a malware verdict.
/// @reason Missing reports and undetected files must never be labeled safe.
/// @contract Reject mismatched SHA-256, malformed counters and empty analysis.
fn parse_file_report(body: &[u8], digest: &str) -> Result<SourceSignal> {
    if body.len() > MAX_RESPONSE_BYTES {
        bail!("Provider report exceeds size limit");
    }
    let report: Value =
        serde_json::from_slice(body).map_err(|_| anyhow::anyhow!("Invalid provider report"))?;
    let id = report
        .pointer("/data/id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Invalid provider report"))?;
    if !id.eq_ignore_ascii_case(digest)
        || report.pointer("/data/type").and_then(Value::as_str) != Some("file")
    {
        bail!("Mismatched provider report");
    }
    let stats = report
        .pointer("/data/attributes/last_analysis_stats")
        .ok_or_else(|| anyhow::anyhow!("Invalid provider report"))?;

    let malicious = stat(stats, "malicious")?;
    let suspicious = stat(stats, "suspicious")?;
    let harmless = stat(stats, "harmless")?;
    let undetected = stat(stats, "undetected")?;
    let total = malicious + suspicious + harmless + undetected;
    if total == 0 || total > MAX_ENGINE_COUNT {
        bail!("Provider report has no usable analysis");
    }
    if malicious > 0 || suspicious > 0 {
        Ok(SourceSignal::Signal)
    } else {
        // NoSignal does not mean clean or safe.
        Ok(SourceSignal::NoSignal)
    }
}

/// @dev-id TAV-VT-HASH-002
/// @purpose Prepare one fixed-endpoint read-only request after opt-in approval.
/// @reason Dynamic endpoints, redirects and unbounded replies expose credentials.
/// @contract Transport enforcement and UI consent are not implemented here.
impl<T: HttpsGetTransport + ?Sized> EvidenceSource for VirusTotalHashSource<'_, T> {
    fn id(&self) -> &str {
        SOURCE_ID
    }

    fn location(&self) -> SourceLocation {
        SourceLocation::Remote
    }

    fn lookup_sha256(
        &self,
        sha256: &str,
        budget: Duration,
        cancelled: &AtomicBool,
    ) -> Result<SourceSignal> {
        if !valid_digest(sha256) || budget.is_zero() {
            bail!("Invalid hash lookup");
        }
        if cancelled.load(Ordering::Relaxed) {
            bail!("Hash lookup cancelled");
        }

        let timeout = budget.min(MAX_LOOKUP_TIME);
        let request = HttpsGetRequest {
            url: format!("{FILE_REPORT_URL}{}", sha256.to_ascii_lowercase()),
            header_name: "x-apikey",
            header_value: self.api_key,
            total_timeout: timeout,
            connect_timeout: timeout.min(CONNECT_TIMEOUT),
            max_response_bytes: MAX_RESPONSE_BYTES,
            follow_redirects: false,
        };
        let response = self.transport.get(&request, cancelled)?;
        if cancelled.load(Ordering::Relaxed) {
            bail!("Hash lookup cancelled");
        }
        if response.status_code != 200 {
            bail!("Provider report unavailable");
        }
        parse_file_report(&response.body, sha256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_evidence::{
        collect_source_evidence, collect_source_evidence_with_approval, ExternalLookupApproval,
    };
    use std::sync::atomic::AtomicUsize;

    const DIGEST: &str = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";

    fn report(malicious: u64, suspicious: u64, harmless: u64, undetected: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "data": {
                "id": DIGEST,
                "type": "file",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": undetected
                    }
                }
            }
        }))
        .unwrap()
    }

    struct FixtureTransport {
        calls: AtomicUsize,
        response: HttpsGetResponse,
    }

    impl HttpsGetTransport for FixtureTransport {
        fn get(&self, request: &HttpsGetRequest<'_>, _: &AtomicBool) -> Result<HttpsGetResponse> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            assert_eq!(
                request.url,
                format!("{FILE_REPORT_URL}{}", DIGEST.to_ascii_lowercase())
            );
            assert_eq!(request.header_name, "x-apikey");
            assert_eq!(request.header_value, "fixture_key");
            assert!(!request.url.contains("fixture_key"));
            assert_eq!(request.total_timeout, MAX_LOOKUP_TIME);
            assert_eq!(request.connect_timeout, CONNECT_TIMEOUT);
            assert_eq!(request.max_response_bytes, MAX_RESPONSE_BYTES);
            assert!(!request.follow_redirects);
            Ok(self.response.clone())
        }
    }

    fn fixture(status_code: u16, body: Vec<u8>) -> FixtureTransport {
        FixtureTransport {
            calls: AtomicUsize::new(0),
            response: HttpsGetResponse { status_code, body },
        }
    }

    #[test]
    fn remote_source_requires_explicit_opt_in_before_transport() {
        let transport = fixture(200, report(1, 0, 0, 5));
        let source = VirusTotalHashSource::new(&transport, "fixture_key").unwrap();
        let cancelled = AtomicBool::new(false);

        assert!(collect_source_evidence(DIGEST, &[&source], &cancelled).is_err());
        assert_eq!(transport.calls.load(Ordering::Relaxed), 0);

        let approval = ExternalLookupApproval::new(DIGEST, &[SOURCE_ID]).unwrap();
        let result =
            collect_source_evidence_with_approval(DIGEST, &[&source], &approval, &cancelled)
                .unwrap();
        assert_eq!(result.observations[0].signal, SourceSignal::Signal);
        assert_eq!(transport.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn undetected_is_no_signal_never_clean() {
        let transport = fixture(200, report(0, 0, 5, 10));
        let source = VirusTotalHashSource::new(&transport, "fixture_key").unwrap();
        let approval = ExternalLookupApproval::new(DIGEST, &[SOURCE_ID]).unwrap();
        let result = collect_source_evidence_with_approval(
            DIGEST,
            &[&source],
            &approval,
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(result.observations[0].signal, SourceSignal::NoSignal);
    }

    #[test]
    fn malformed_and_non_success_responses_are_unavailable() {
        let mut bad_bodies = vec![
            (404, report(1, 0, 0, 3)),
            (429, report(1, 0, 0, 3)),
            (302, report(1, 0, 0, 3)),
            (200, b"not JSON".to_vec()),
            (200, report(0, 0, 0, 0)),
            (200, vec![b'x'; MAX_RESPONSE_BYTES + 1]),
        ];
        let wrong_digest = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        let mismatched = serde_json::to_vec(&serde_json::json!({
            "data": {
                "id": wrong_digest,
                "type": "file",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 1,
                        "suspicious": 0,
                        "harmless": 0,
                        "undetected": 3
                    }
                }
            }
        }))
        .unwrap();
        bad_bodies.push((200, mismatched));

        for (status_code, body) in bad_bodies {
            let transport = fixture(status_code, body);
            let source = VirusTotalHashSource::new(&transport, "fixture_key").unwrap();
            let approval = ExternalLookupApproval::new(DIGEST, &[SOURCE_ID]).unwrap();
            let result = collect_source_evidence_with_approval(
                DIGEST,
                &[&source],
                &approval,
                &AtomicBool::new(false),
            )
            .unwrap();
            assert_eq!(result.observations[0].signal, SourceSignal::Unavailable);
        }
    }

    #[test]
    fn invalid_credential_and_digest_fail_closed() {
        let transport = fixture(200, report(1, 0, 0, 3));
        assert!(VirusTotalHashSource::new(&transport, "bad\nkey").is_err());
        let source = VirusTotalHashSource::new(&transport, "fixture_key").unwrap();
        assert!(source
            .lookup_sha256("invalid", MAX_LOOKUP_TIME, &AtomicBool::new(false))
            .is_err());
        assert_eq!(transport.calls.load(Ordering::Relaxed), 0);
    }
}
