// Dosya Yolu: REPO_ROOT/rust/src/publisher_bootstrap.rs
// Amac: Uygulamaya onceden sabitlenen publisher PEM ozetlerini dogrula
// Modul - FileType: Config/Tool - Rust
// Version: 0.3.1
// Aciklama: Yerel PEM dosyalari yalnizca bagimsiz guven ozetleriyle eslesirse kabul edilir
// Bagimli Oldugu Katman: Config | Service | Tool

use crate::{config, scan, trusted};
use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    path::{Component, Path},
};
use subtle::ConstantTimeEq;

/// Public, compile-time trust metadata. Only an independently authenticated
/// application release can authorize these values. Never populate them from
/// a rule manifest, downloaded bundle, CLI argument or environment variable.
#[derive(Clone, Copy, Debug)]
pub struct PublisherDigestPin<'a> {
    pub key_id: &'a str,
    pub pem_sha256: &'a str,
}

/// @dev-id TAV-PUBLISHER-BOOTSTRAP-001
/// @purpose Load local publisher PEM bytes without letting their source grant trust.
/// @contract The independent pin must match the entire bounded PEM file.
/// This never downloads, imports, changes file permissions or writes state.
pub fn load_pinned_publisher_pems(
    pins: &[PublisherDigestPin<'_>],
    publishers_dir: &Path,
) -> Result<Vec<(String, String)>> {
    ensure!(
        !pins.is_empty() && pins.len() <= 8,
        "One to eight independently pinned publishers required"
    );
    ensure!(
        publishers_dir.is_absolute()
            && !publishers_dir
                .components()
                .any(|c| matches!(c, Component::ParentDir)),
        "Publisher directory must be an absolute path without parent traversal"
    );
    let parent_metadata =
        fs::symlink_metadata(publishers_dir).context("Publisher directory missing")?;
    ensure!(
        parent_metadata.is_dir() && !scan::is_reparse_or_symlink(&parent_metadata),
        "Publisher directory must not be a link or reparse point"
    );
    let mut seen = HashSet::new();
    let mut verified = Vec::with_capacity(pins.len());
    for pin in pins {
        ensure!(
            trusted::valid_key_id(pin.key_id)
                && pin.key_id != "."
                && pin.key_id != ".."
                && seen.insert(pin.key_id),
            "Invalid or duplicate publisher ID"
        );
        ensure!(
            pin.pem_sha256.len() == 64
                && pin
                    .pem_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "Publisher PEM digest must be lowercase SHA-256 hex"
        );
        let mut expected = [0u8; 32];
        hex::decode_to_slice(pin.pem_sha256, &mut expected)
            .context("Malformed pinned publisher digest")?;
        let path = publishers_dir.join(format!("{}.pem", pin.key_id));
        // read_bounded rejects links/reparse points and oversized/nonregular files.
        let pem_bytes = scan::read_bounded(&path, config::MAX_PUBLIC_KEY_BYTES)?;
        let actual: [u8; 32] = Sha256::digest(&pem_bytes).into();
        if actual.ct_eq(&expected).unwrap_u8() != 1 {
            bail!("Local publisher PEM does not match the independent application pin");
        }
        let pem = String::from_utf8(pem_bytes).context("Publisher PEM must be UTF-8")?;
        verified.push((pin.key_id.to_owned(), pem));
    }
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unprovisioned_and_invalid_pins_fail_closed_without_creating_files() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_pinned_publisher_pems(&[], dir.path()).is_err());
        let key = dir.path().join("publisher.pem");
        fs::write(&key, "untrusted").unwrap();
        for (id, digest) in [
            ("../escape", "0".repeat(64)),
            ("..", "0".repeat(64)),
            ("publisher", "INVALID".to_owned()),
            ("publisher", "A".repeat(64)),
            ("publisher", "0".repeat(63)),
        ] {
            let p = [PublisherDigestPin {
                key_id: id,
                pem_sha256: &digest,
            }];
            assert!(load_pinned_publisher_pems(&p, dir.path()).is_err());
        }
        let good_shape = hex::encode(Sha256::digest(b"untrusted"));
        let duplicate = [
            PublisherDigestPin {
                key_id: "publisher",
                pem_sha256: &good_shape,
            },
            PublisherDigestPin {
                key_id: "publisher",
                pem_sha256: &good_shape,
            },
        ];
        assert!(load_pinned_publisher_pems(&duplicate, dir.path()).is_err());
        assert_eq!(fs::read(&key).unwrap(), b"untrusted");
    }

    #[test]
    fn matching_digest_only_loads_bytes_not_authority() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("publisher.pem"), "not an RSA public key").unwrap();
        let digest = hex::encode(Sha256::digest(b"not an RSA public key"));
        let pins = [PublisherDigestPin {
            key_id: "publisher",
            pem_sha256: &digest,
        }];
        let loaded = load_pinned_publisher_pems(&pins, dir.path()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, "publisher");
        assert_eq!(loaded[0].1, "not an RSA public key");
        // The independent RSA parser still rejects this as a trusted key.
        assert!(trusted::TrustedKeyring::from_pinned_pem(loaded).is_err());
        fs::write(dir.path().join("publisher.pem"), "changed").unwrap();
        assert!(load_pinned_publisher_pems(&pins, dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_publisher_file_and_directory_are_rejected() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("publisher.pem"), "public-key").unwrap();
        let digest = hex::encode(Sha256::digest(b"public-key"));
        let pins = [PublisherDigestPin {
            key_id: "publisher",
            pem_sha256: &digest,
        }];
        let dir_link = dir.path().join("dir-link");
        symlink(&real, &dir_link).unwrap();
        assert!(load_pinned_publisher_pems(&pins, &dir_link).is_err());
        let file_link = real.join("another.pem");
        symlink(real.join("publisher.pem"), &file_link).unwrap();
        let link_pin = [PublisherDigestPin {
            key_id: "another",
            pem_sha256: &digest,
        }];
        assert!(load_pinned_publisher_pems(&link_pin, &real).is_err());
    }
}
