// Dosya Yolu: REPO_ROOT/tests/service_update_contract.rs
// Amac: Imzali servis ikilisi ve ayri anti-rollback dogrulama kontrati
// Modul - FileType: Tests - Rust
// Version: 0.3.1
// Aciklama: Gercek RSA-PSS, platform, tamper, state, downgrade ve domain ayrimi
// Bagimli Oldugu Katman: Service | Tool | Config

use rsa::{
    pkcs8::EncodePublicKey,
    pss::SigningKey,
    rand_core::OsRng,
    signature::{RandomizedSigner, SignatureEncoding},
    RsaPrivateKey,
};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use turkuazav::{
    accept_version,
    update::{
        parse_service_update_manifest, service_update_signature_payload, MAX_SERVICE_BINARY_BYTES,
        SERVICE_UPDATE_SCHEMA,
    },
    verify_service_update, TrustedKeyring,
};

fn sign(key: &RsaPrivateKey, bytes: &[u8]) -> Vec<u8> {
    SigningKey::<Sha256>::new(key.clone())
        .sign_with_rng(&mut OsRng, bytes)
        .to_vec()
}

fn signed_fixture(
    root: &Path,
    key: &RsaPrivateKey,
    sequence: i64,
    bytes: &[u8],
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let binary = root.join("candidate-service");
    let manifest = root.join("manifest.json");
    let signature = root.join("manifest.sig");
    fs::write(&binary, bytes).unwrap();
    let platform = if cfg!(windows) { "windows" } else { "linux" };
    let value = serde_json::json!({
        "schema": SERVICE_UPDATE_SCHEMA,
        "sequence": sequence,
        "keyId": "update-publisher",
        "version": "0.3.1",
        "targetOs": platform,
        "targetArch": "x86_64",
        "binarySize": bytes.len(),
        "binarySha256": hex::encode(Sha256::digest(bytes))
    });
    let json = value.to_string();
    let parsed = parse_service_update_manifest(json.as_bytes()).unwrap();
    let signature_bytes = sign(key, &service_update_signature_payload(&parsed));
    fs::write(&manifest, json).unwrap();
    fs::write(&signature, signature_bytes).unwrap();
    (binary, manifest, signature)
}

#[test]
fn publisher_signed_update_is_domain_separated_and_read_only() {
    let root = tempfile::tempdir().unwrap();
    let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let pem = key.to_public_key().to_public_key_pem(Default::default()).unwrap();
    let ring = TrustedKeyring::from_pinned_pem(vec![("update-publisher".into(), pem)]).unwrap();
    let state = root.path().join("service-update-state");
    let (bin, man, sig) = signed_fixture(root.path(), &key, 2, b"test service binary");
    let pkg = verify_service_update(&bin, &man, &sig, &ring, &state).unwrap();
    assert_eq!(pkg.sequence(), 2);
    assert_eq!(pkg.version(), "0.3.1");
    assert_eq!(pkg.publisher_key_id(), "update-publisher");
    assert_eq!(pkg.verified_binary(), b"test service binary");
    assert!(!state.exists(), "Verification must not commit update state");

    // A successful installer, not the verifier, would separately advance
    // its protected 40-byte update state after durable successful switchover.
    accept_version(&state, pkg.sequence(), pkg.manifest_fingerprint()).unwrap();
    let saved = fs::read(&state).unwrap();
    assert_eq!(saved.len(), 40);
    assert_eq!(i64::from_le_bytes(saved[..8].try_into().unwrap()), 2);

    let (bin, man, sig) = signed_fixture(root.path(), &key, 1, b"older build");
    assert!(verify_service_update(&bin, &man, &sig, &ring, &state).is_err());
    assert_eq!(fs::read(&state).unwrap(), saved);

    // A matching sequence signed for different content must not replace
    // the accepted signed update, even with the same authorized key.
    let (bin, man, sig) = signed_fixture(root.path(), &key, 2, b"different build");
    assert!(verify_service_update(&bin, &man, &sig, &ring, &state).is_err());
    assert_eq!(fs::read(&state).unwrap(), saved);
}

#[test]
fn unsigned_tampered_and_wrong_publisher_inputs_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let pem = key.to_public_key().to_public_key_pem(Default::default()).unwrap();
    let ring = TrustedKeyring::from_pinned_pem(vec![("update-publisher".into(), pem)]).unwrap();
    let state = root.path().join("service-state");
    let (bin, man, sig) = signed_fixture(root.path(), &key, 1, b"good binary");
    assert!(verify_service_update(&bin, &man, &sig, &ring, &state).is_ok());
    fs::write(&bin, b"bad binary!").unwrap();
    assert!(verify_service_update(&bin, &man, &sig, &ring, &state).is_err());
    fs::write(&bin, b"good binary").unwrap();
    fs::write(&sig, b"wrong signature").unwrap();
    assert!(verify_service_update(&bin, &man, &sig, &ring, &state).is_err());

    let unknown = TrustedKeyring::from_pinned_pem(Vec::<(String, String)>::new()).unwrap();
    assert!(verify_service_update(&bin, &man, &sig, &unknown, &state).is_err());

    let (bin, man, sig) = signed_fixture(root.path(), &key, 2, b"good signed binary");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&man).unwrap()).unwrap();
    value["targetOs"] = serde_json::json!(if cfg!(windows) { "linux" } else { "windows" });
    fs::write(&man, value.to_string()).unwrap();
    assert!(verify_service_update(&bin, &man, &sig, &ring, &state).is_err());
    assert!(!state.exists());
}

#[test]
fn strict_schema_and_separate_rule_signature_domain() {
    let valid = format!(
        r#"{{"schema":"{}","sequence":1,"keyId":"publisher","version":"0.3.1","targetOs":"{}","targetArch":"x86_64","binarySize":1,"binarySha256":"{}"}}"#,
        SERVICE_UPDATE_SCHEMA,
        if cfg!(windows) { "windows" } else { "linux" },
        "a".repeat(64)
    );
    let parsed = parse_service_update_manifest(valid.as_bytes()).unwrap();
    let payload = service_update_signature_payload(&parsed);
    assert!(payload.starts_with(b"TurkuazAV.service-update.v1\n"));
    assert!(!payload.starts_with(b"TurkuazAV.rule-package.v1\n"));
    assert!(parse_service_update_manifest(valid.replace("0.3.1", "01.3.1").as_bytes()).is_err());
    assert!(parse_service_update_manifest(valid.replace("0.3.1", "0.3.1-extra").as_bytes()).is_err());
    assert!(parse_service_update_manifest(valid.replace("\"sequence\":1", "\"sequence\":0").as_bytes()).is_err());
    assert!(parse_service_update_manifest(valid.replace("\"binarySize\":1", "\"binarySize\":0").as_bytes()).is_err());
    assert!(parse_service_update_manifest(valid.replace("\"binarySize\":1", &format!("\"binarySize\":{}", MAX_SERVICE_BINARY_BYTES + 1)).as_bytes()).is_err());
    assert!(parse_service_update_manifest(valid.replace("\"binarySha256\":\"", "\"binarySha256\":\"A").as_bytes()).is_err());
    assert!(parse_service_update_manifest(valid.replace("}", ",\"extra\":1}").as_bytes()).is_err());
    assert!(parse_service_update_manifest(valid.replace("\"sequence\":1", "\"sequence\":1,\"sequence\":1").as_bytes()).is_err());
}

#[test]
fn corrupt_state_and_binary_link_are_rejected_without_mutation() {
    let root = tempfile::tempdir().unwrap();
    let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let pem = key.to_public_key().to_public_key_pem(Default::default()).unwrap();
    let ring = TrustedKeyring::from_pinned_pem(vec![("update-publisher".into(), pem)]).unwrap();
    let state = root.path().join("service-update-state");
    let (bin, man, sig) = signed_fixture(root.path(), &key, 1, b"safe executable");
    fs::write(&state, b"broken").unwrap();
    assert!(verify_service_update(&bin, &man, &sig, &ring, &state).is_err());
    assert_eq!(fs::read(&state).unwrap(), b"broken");

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        fs::remove_file(&state).unwrap();
        symlink(&bin, &state).unwrap();
        assert!(verify_service_update(&bin, &man, &sig, &ring, &state).is_err());
        fs::remove_file(&state).unwrap();

        let other = root.path().join("other");
        fs::write(&other, b"safe executable").unwrap();
        fs::remove_file(&bin).unwrap();
        symlink(other, &bin).unwrap();
        assert!(verify_service_update(&bin, &man, &sig, &ring, &state).is_err());
    }
}
