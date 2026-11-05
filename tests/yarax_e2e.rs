// Dosya Yolu: REPO_ROOT/tests/yarax_e2e.rs
// Amac: Gercek sabit YARA-X ile 0.3.1 imzali tarama E2E
// Modul - FileType: Tests - Rust
// Version: 0.3.1
// Aciklama: Pozitif/negatif, imza, engine pin, state ve anti-rollback
// Bagimli Oldugu Katman: Service | Repo | Tool | Config

use rsa::{
    pkcs8::EncodePublicKey,
    pss::SigningKey,
    rand_core::OsRng,
    signature::{RandomizedSigner, SignatureEncoding},
    RsaPrivateKey,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};
use turkuazav::trusted::{parse_manifest, signature_payload};
use turkuazav::{
    publish_verified_rule_candidate, scan_rules, scan_rules_with_cancel, scan_trusted_rules,
    scan_trusted_rules_with_cancel, stage_signed_rule_candidate, verify_package, AnalysisCoverage,
    CandidatePublicationPaths, DesktopTrustedRules, PublisherDigestPin, RuleCandidatePaths,
    ScannerId, ThreatCategory, ThreatVerdict, TrustedKeyring, TrustedScanPaths,
};

const RULE: &str =
    r#"rule TurkuazAvTest { strings: $marker = "TURKUAZ-AV-TEST-MARKER" condition: $marker }"#;
const OTHER_RULE: &str =
    r#"rule TurkuazAvOther { strings: $marker = "SOMETHING-ABSENT" condition: $marker }"#;

fn sign(private: &RsaPrivateKey, data: &[u8]) -> Vec<u8> {
    SigningKey::<Sha256>::new(private.clone())
        .sign_with_rng(&mut OsRng, data)
        .to_vec()
}

fn write_package(
    base: &Path,
    private: &RsaPrivateKey,
    seq: i64,
    rules_text: &str,
) -> (PathBuf, PathBuf, PathBuf) {
    let rules = base.join("rules.yar");
    let manifest = base.join("manifest.json");
    let signature = base.join("rules.sig");
    fs::write(&rules, rules_text).unwrap();
    let digest = hex::encode(Sha256::digest(rules_text.as_bytes()));
    let json = serde_json::json!({
        "schema": "turkuazav.rule-package.v1",
        "sequence": seq,
        "keyId": "trusted-a",
        "rulesSha256": digest,
    })
    .to_string();
    let parsed = parse_manifest(json.as_bytes()).unwrap();
    fs::write(&manifest, json).unwrap();
    fs::write(&signature, sign(private, &signature_payload(&parsed))).unwrap();
    (rules, manifest, signature)
}

#[test]
fn real_yarax_signed_and_trusted_regressions() {
    let engine = PathBuf::from(
        std::env::var("TURKUAZ_YR_PATH")
            .expect("Install pinned YARA-X with tools/install-yarax.ps1 before this E2E test"),
    );
    let temp = tempfile::tempdir().unwrap();
    let positive = temp.path().join("positive.txt");
    let negative = temp.path().join("negative.txt");
    let fake_engine = temp.path().join("fake-yr");
    fs::write(&positive, "TURKUAZ-AV-TEST-MARKER").unwrap();
    fs::write(&negative, "ordinary content").unwrap();
    fs::write(&fake_engine, "not a genuine engine").unwrap();

    let mut rng = OsRng;
    let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pem = private
        .to_public_key()
        .to_public_key_pem(Default::default())
        .unwrap();
    let pem_file = temp.path().join("key.pem");
    fs::write(&pem_file, &pem).unwrap();

    // Developer CLI parity: the public key is untrusted and only authorizes this invocation.
    let rules = temp.path().join("rules.yar");
    let signature = temp.path().join("rules.sig");
    fs::write(&rules, RULE).unwrap();
    fs::write(&signature, sign(&private, RULE.as_bytes())).unwrap();
    let match_result = scan_rules(&positive, &rules, &signature, &pem_file, &engine).unwrap();
    assert_eq!(match_result.rule_identifiers, vec!["TurkuazAvTest"]);
    assert!(
        scan_rules(&negative, &rules, &signature, &pem_file, &engine)
            .unwrap()
            .rule_identifiers
            .is_empty()
    );
    fs::write(&rules, OTHER_RULE).unwrap();
    assert!(scan_rules(&positive, &rules, &signature, &pem_file, &engine).is_err());
    fs::write(&rules, RULE).unwrap();
    assert!(scan_rules(&positive, &rules, &signature, &pem_file, &fake_engine).is_err());

    // Production library API must pin publisher identity independently from a CLI argument.
    let ring =
        TrustedKeyring::from_pinned_pem(vec![("trusted-a".to_owned(), pem.clone())]).unwrap();
    let state = temp.path().join("state");
    let (rules, manifest, signature) = write_package(temp.path(), &private, 1, RULE);
    let scan = |path: &Path, yr: &Path| {
        scan_trusted_rules(path, &rules, &manifest, &signature, yr, &state, &ring)
    };
    assert_eq!(
        scan(&positive, &engine).unwrap().rule_identifiers,
        vec!["TurkuazAvTest"]
    );
    assert!(scan(&negative, &engine)
        .unwrap()
        .rule_identifiers
        .is_empty());
    assert_eq!(fs::read(&state).unwrap().len(), 40);

    // The desktop application uses the SAME signed trusted scan adapter,
    // never the developer-only scan-rules entry point.
    let desktop = DesktopTrustedRules::from_trusted_bootstrap(
        &[("trusted-a", pem.as_str())],
        temp.path(),
        &engine,
        &state,
    )
    .unwrap();
    let report = desktop.scan(&positive, &AtomicBool::new(false)).unwrap();
    assert_eq!(report.scanner, ScannerId::YaraX);
    assert_eq!(report.assessment.coverage, AnalysisCoverage::Completed);
    assert_eq!(report.assessment.verdict, ThreatVerdict::RequiresReview);
    assert_eq!(report.assessment.category, ThreatCategory::Unknown);
    assert!(report.assessment.sha256.is_none());
    assert_eq!(report.assessment.evidence.len(), 1);
    assert_eq!(report.assessment.evidence[0].identifier, "TurkuazAvTest");
    assert_eq!(fs::read(&state).unwrap().len(), 40);
    let accepted_state = fs::read(&state).unwrap();
    let preflight = desktop.preflight().unwrap();
    assert_eq!(preflight.publisher_key_id, "trusted-a");
    assert_eq!(preflight.sequence, 1);
    assert_eq!(fs::read(&state).unwrap(), accepted_state);

    // Only an independent application digest can authorize the on-disk PEM.
    let publishers = temp.path().join("publishers");
    fs::create_dir(&publishers).unwrap();
    let publisher_file = publishers.join("trusted-a.pem");
    fs::write(&publisher_file, pem.as_bytes()).unwrap();
    let expected_pem_sha256 = hex::encode(Sha256::digest(pem.as_bytes()));
    let pins = [PublisherDigestPin {
        key_id: "trusted-a",
        pem_sha256: &expected_pem_sha256,
    }];
    let disk_bootstrap = DesktopTrustedRules::from_pinned_digest_directory(
        &pins,
        &publishers,
        temp.path(),
        &engine,
        &state,
    )
    .unwrap();
    assert_eq!(disk_bootstrap.preflight().unwrap().sequence, 1);
    let report = disk_bootstrap
        .scan(&positive, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(report.assessment.verdict, ThreatVerdict::RequiresReview);
    assert_eq!(report.assessment.evidence[0].identifier, "TurkuazAvTest");
    assert_eq!(fs::read(&state).unwrap(), accepted_state);
    // Altered publisher PEM cannot grant trust or change rollback state.
    fs::write(&publisher_file, b"replaced-public-key").unwrap();
    assert!(DesktopTrustedRules::from_pinned_digest_directory(
        &pins,
        &publishers,
        temp.path(),
        &engine,
        &state,
    )
    .is_err());
    assert_eq!(fs::read(&state).unwrap(), accepted_state);
    fs::write(&publisher_file, pem.as_bytes()).unwrap();

    let unknown_publisher = DesktopTrustedRules::from_trusted_bootstrap(
        &[("different-publisher", pem.as_str())],
        temp.path(),
        &engine,
        &state,
    )
    .unwrap();
    assert!(unknown_publisher.preflight().is_err());
    assert_eq!(fs::read(&state).unwrap(), accepted_state);

    // Missing or untrusted publisher material must never be read from
    // a rule package or accepted as a user-selected PEM.
    assert!(
        DesktopTrustedRules::from_trusted_bootstrap(&[], temp.path(), &engine, &state).is_err()
    );

    // A candidate is snapshotted in a fresh temporary directory, never
    // activated or persisted as the currently trusted package.
    let candidate_root = temp.path().join("candidate-staging");
    fs::create_dir(&candidate_root).unwrap();
    let active_rules = fs::read(&rules).unwrap();
    let version_before_candidate = fs::read(&state).unwrap();
    let candidate = stage_signed_rule_candidate(
        RuleCandidatePaths {
            rules: &rules,
            manifest: &manifest,
            signature: &signature,
            engine: &engine,
            version_state: &state,
        },
        &ring,
        &candidate_root,
    )
    .unwrap();
    assert_eq!(candidate.sequence, 1);
    assert_eq!(candidate.publisher_key_id, "trusted-a");
    assert_eq!(fs::read(candidate.rules()).unwrap(), active_rules);
    assert_eq!(fs::read(&state).unwrap(), version_before_candidate);
    assert_eq!(fs::read_dir(&candidate_root).unwrap().count(), 1);

    let staged_verified = verify_package(
        &candidate.rules(),
        &candidate.manifest(),
        &candidate.signature(),
        &ring,
    )
    .unwrap();
    assert_eq!(staged_verified.sequence, 1);

    // Copy a signed candidate into a new versioned directory without
    // selecting it as active or advancing the 40-byte state.
    let versions_root = temp.path().join("versioned-candidates");
    fs::create_dir(&versions_root).unwrap();
    let locations = CandidatePublicationPaths {
        repository_root: &versions_root,
        engine: &engine,
        version_state: &state,
    };
    let published = publish_verified_rule_candidate(&candidate, &ring, locations).unwrap();
    assert_eq!(published.sequence, 1);
    assert_eq!(published.publisher_key_id, "trusted-a");
    assert_eq!(fs::read(published.rules()).unwrap(), active_rules);
    assert_eq!(
        fs::read(published.directory().join("CANDIDATE_READY")).unwrap(),
        b"uncommitted-candidate-only\n"
    );
    assert_eq!(fs::read(&state).unwrap(), version_before_candidate);
    let version_dir = published.directory().to_path_buf();

    // A collision must never overwrite or remove previously published bytes.
    assert!(publish_verified_rule_candidate(
        &candidate,
        &ring,
        CandidatePublicationPaths {
            repository_root: &versions_root,
            engine: &engine,
            version_state: &state,
        },
    )
    .is_err());
    assert_eq!(
        fs::read(version_dir.join("rules.yar")).unwrap(),
        active_rules
    );
    assert_eq!(fs::read_dir(&versions_root).unwrap().count(), 1);

    // Tampered staged bytes cannot be re-published; READY does not confer
    // authority on a persistent directory if its bytes are later altered.
    fs::write(candidate.rules(), b"untrusted staged replacement").unwrap();
    assert!(publish_verified_rule_candidate(
        &candidate,
        &ring,
        CandidatePublicationPaths {
            repository_root: &versions_root,
            engine: &engine,
            version_state: &state,
        },
    )
    .is_err());
    assert_eq!(fs::read_dir(&versions_root).unwrap().count(), 1);
    fs::write(candidate.rules(), &active_rules).unwrap();
    fs::write(
        version_dir.join("rules.yar"),
        b"untrusted retained replacement",
    )
    .unwrap();
    assert!(verify_package(
        &version_dir.join("rules.yar"),
        &version_dir.join("manifest.json"),
        &version_dir.join("rules.sig"),
        &ring,
    )
    .is_err());
    assert_eq!(fs::read(&state).unwrap(), version_before_candidate);

    // Replacing the source after staging cannot modify the verified copy.
    fs::write(&rules, b"tampered source after staging").unwrap();
    assert!(verify_package(&rules, &manifest, &signature, &ring).is_err());
    assert_eq!(fs::read(candidate.rules()).unwrap(), active_rules);
    assert_eq!(
        verify_package(
            &candidate.rules(),
            &candidate.manifest(),
            &candidate.signature(),
            &ring
        )
        .unwrap()
        .sequence,
        1
    );
    assert_eq!(fs::read(&state).unwrap(), version_before_candidate);
    drop(candidate);
    assert_eq!(fs::read_dir(&candidate_root).unwrap().count(), 0);
    // Original active source contents were not overwritten by the staging API.
    assert_eq!(fs::read(&rules).unwrap(), b"tampered source after staging");
    fs::write(&rules, &active_rules).unwrap();

    // An invalid candidate must fail without writing state or leaving a
    // partial candidate directory behind.
    let good_signature = fs::read(&signature).unwrap();
    fs::write(&signature, b"invalid signature").unwrap();
    assert!(stage_signed_rule_candidate(
        RuleCandidatePaths {
            rules: &rules,
            manifest: &manifest,
            signature: &signature,
            engine: &engine,
            version_state: &state,
        },
        &ring,
        &candidate_root,
    )
    .is_err());
    assert_eq!(fs::read_dir(&candidate_root).unwrap().count(), 0);
    assert_eq!(fs::read(&state).unwrap(), version_before_candidate);
    fs::write(&signature, good_signature).unwrap();

    // Different signed content cannot reuse an accepted sequence.
    write_package(temp.path(), &private, 1, OTHER_RULE);
    assert!(desktop.preflight().is_err());
    assert!(scan(&positive, &engine).is_err());
    assert_eq!(
        i64::from_le_bytes(fs::read(&state).unwrap()[..8].try_into().unwrap()),
        1
    );

    write_package(temp.path(), &private, 2, OTHER_RULE);
    let approved_next = desktop.preflight().unwrap();
    assert_eq!(approved_next.sequence, 2);
    // Advisory preflight never advances the persistent state.
    assert_eq!(fs::read(&state).unwrap(), accepted_state);
    assert!(scan(&negative, &engine)
        .unwrap()
        .rule_identifiers
        .is_empty());
    assert_eq!(
        i64::from_le_bytes(fs::read(&state).unwrap()[..8].try_into().unwrap()),
        2
    );

    // Cancelling an otherwise valid new sequence must not advance trusted state.
    write_package(temp.path(), &private, 3, RULE);
    let cancelled = AtomicBool::new(true);
    assert!(scan_trusted_rules_with_cancel(
        TrustedScanPaths {
            target: &positive,
            rules_path: &rules,
            manifest: &manifest,
            signature: &signature,
            engine: &engine,
            state_file: &state,
        },
        &ring,
        &cancelled,
    )
    .is_err());
    assert!(
        scan_rules_with_cancel(&positive, &rules, &signature, &pem_file, &engine, &cancelled,)
            .is_err()
    );
    assert_eq!(
        i64::from_le_bytes(fs::read(&state).unwrap()[..8].try_into().unwrap()),
        2
    );

    write_package(temp.path(), &private, 1, RULE);
    let old_state = fs::read(&state).unwrap();
    assert!(stage_signed_rule_candidate(
        RuleCandidatePaths {
            rules: &rules,
            manifest: &manifest,
            signature: &signature,
            engine: &engine,
            version_state: &state,
        },
        &ring,
        &candidate_root,
    )
    .is_err());
    assert_eq!(fs::read_dir(&candidate_root).unwrap().count(), 0);
    assert_eq!(fs::read(&state).unwrap(), old_state);
    assert!(scan(&positive, &engine).is_err());

    // Failed engine check does not advance the accepted sequence.
    write_package(temp.path(), &private, 3, RULE);
    let wrong_engine = DesktopTrustedRules::from_trusted_bootstrap(
        &[("trusted-a", pem.as_str())],
        temp.path(),
        &fake_engine,
        &state,
    )
    .unwrap();
    assert!(wrong_engine.preflight().is_err());
    assert!(scan(&positive, &fake_engine).is_err());
    assert_eq!(
        i64::from_le_bytes(fs::read(&state).unwrap()[..8].try_into().unwrap()),
        2
    );

    fs::write(&rules, OTHER_RULE).unwrap();
    assert!(desktop.preflight().is_err());
    assert!(scan(&positive, &engine).is_err());
}
