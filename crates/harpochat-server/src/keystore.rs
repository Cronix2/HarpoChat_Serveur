// SPDX-License-Identifier: Apache-2.0
//! The node key file: the only persistent secret (spec §4.1).
//!
//! Holds the long-term Ed25519 identity seed and the long-term X25519 Noise
//! static secret. No user data, ever. The Sphinx key is *not* stored: it is
//! regenerated in RAM at each start, so a restart also invalidates every SURB
//! built for this node, consistent with "a restart wipes everything" (P2).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let k = NodeKeys::generate();
        save(dir.path(), &k).unwrap();
        let back = load(dir.path()).unwrap();
        assert_eq!(back.identity.public(), k.identity.public());
        assert_eq!(back.noise.public(), k.noise.public());
    }

    #[test]
    fn save_refuses_existing() {
        let dir = tempfile::tempdir().unwrap();
        save(dir.path(), &NodeKeys::generate()).unwrap();
        let before = std::fs::read(dir.path().join(KEY_FILE)).unwrap();
        assert!(matches!(
            save(dir.path(), &NodeKeys::generate()),
            Err(KeyStoreError::AlreadyExists)
        ));
        assert_eq!(std::fs::read(dir.path().join(KEY_FILE)).unwrap(), before);
    }

    #[test]
    fn missing_keyfile() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(load(dir.path()), Err(KeyStoreError::Missing)));
    }

    #[test]
    fn corrupt_keyfile_rejected() {
        let dir = tempfile::tempdir().unwrap();
        save(dir.path(), &NodeKeys::generate()).unwrap();
        let path = dir.path().join(KEY_FILE);
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..10]).unwrap();
        assert!(matches!(load(dir.path()), Err(KeyStoreError::Corrupt)));
        std::fs::write(&path, b"").unwrap();
        assert!(matches!(load(dir.path()), Err(KeyStoreError::Corrupt)));
    }

    #[test]
    fn wrong_version_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let file = KeyFile {
            v: 2,
            identity_seed: [1; 32],
            noise_secret: [2; 32],
        };
        std::fs::write(dir.path().join(KEY_FILE), harpochat_core::cbor::to_vec(&file)).unwrap();
        assert!(matches!(load(dir.path()), Err(KeyStoreError::Corrupt)));
    }

    #[cfg(unix)]
    #[test]
    fn keyfile_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        save(dir.path(), &NodeKeys::generate()).unwrap();
        let mode = std::fs::metadata(dir.path().join(KEY_FILE)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
