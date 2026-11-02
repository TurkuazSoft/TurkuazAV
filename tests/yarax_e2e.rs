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
};
use turkuazav::trusted::{parse_manifest, signature_payload};
use turkuazav::{scan_rules, scan_trusted_rules, TrustedKeyring};

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
    let ring = TrustedKeyring::from_pinned_pem(vec![("trusted-a".to_owned(), pem)]).unwrap();
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

    // Different signed content cannot reuse an accepted sequence.
    write_package(temp.path(), &private, 1, OTHER_RULE);
    assert!(scan(&positive, &engine).is_err());
    assert_eq!(
        i64::from_le_bytes(fs::read(&state).unwrap()[..8].try_into().unwrap()),
        1
    );

    write_package(temp.path(), &private, 2, OTHER_RULE);
    assert!(scan(&negative, &engine)
        .unwrap()
        .rule_identifiers
        .is_empty());
    assert_eq!(
        i64::from_le_bytes(fs::read(&state).unwrap()[..8].try_into().unwrap()),
        2
    );

    write_package(temp.path(), &private, 1, RULE);
    assert!(scan(&positive, &engine).is_err());

    // Failed engine check does not advance the accepted sequence.
    write_package(temp.path(), &private, 3, RULE);
    assert!(scan(&positive, &fake_engine).is_err());
    assert_eq!(
        i64::from_le_bytes(fs::read(&state).unwrap()[..8].try_into().unwrap()),
        2
    );

    fs::write(&rules, OTHER_RULE).unwrap();
    assert!(scan(&positive, &engine).is_err());
}
