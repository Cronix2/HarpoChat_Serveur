// SPDX-License-Identifier: Apache-2.0
//! The node key file: the only persistent secret (spec §4.1).
//!
//! Holds the long-term Ed25519 identity seed and the long-term X25519 Noise
//! static secret. No user data, ever. The Sphinx key is *not* stored: it is
//! regenerated in RAM at each start, so a restart also invalidates every SURB
//! built for this node, consistent with "a restart wipes everything" (P2).

use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::path::Path;

use harpochat_core::cbor;
use harpochat_core::keys::{SigningKey, X25519Secret};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Key file name inside the data directory.
pub const KEY_FILE: &str = "node.key";
const VERSION: u8 = 1;

/// Long-term keys of a node.
#[derive(Debug, Clone)]
pub struct NodeKeys {
    /// Ed25519 identity (`id_pub` in descriptors).
    pub identity: SigningKey,
    /// X25519 Noise static key (`noise_pub`, design E4/E5).
    pub noise: X25519Secret,
}

impl NodeKeys {
    /// Fresh random keys.
    pub fn generate() -> Self {
        Self {
            identity: SigningKey::generate(),
            noise: X25519Secret::generate(),
        }
    }
}

/// Key store failure.
#[derive(Debug)]
pub enum KeyStoreError {
    /// `node.key` already exists: never overwritten.
    AlreadyExists,
    /// `node.key` not found.
    Missing,
    /// `node.key` unreadable as a key file.
    Corrupt,
    /// Other I/O error.
    Io(std::io::Error),
}

impl std::fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyStoreError::AlreadyExists => write!(f, "{KEY_FILE} existe déjà (jamais écrasé)"),
            KeyStoreError::Missing => write!(f, "{KEY_FILE} introuvable : lancez `init` d'abord"),
            KeyStoreError::Corrupt => write!(f, "{KEY_FILE} illisible ou corrompu"),
            KeyStoreError::Io(e) => write!(f, "erreur d'accès à {KEY_FILE} : {e}"),
        }
    }
}

impl std::error::Error for KeyStoreError {}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyFile {
    pub(crate) v: u8,
    #[serde(with = "serde_bytes")]
    pub(crate) identity_seed: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) noise_secret: [u8; 32],
}

/// Write `node.key` in `dir`. Refuses to overwrite an existing file.
pub fn save(dir: &Path, keys: &NodeKeys) -> Result<(), KeyStoreError> {
    let file = KeyFile {
        v: VERSION,
        identity_seed: *keys.identity.seed(),
        noise_secret: *keys.noise.to_bytes(),
    };
    let bytes = Zeroizing::new(cbor::to_vec(&file));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(dir.join(KEY_FILE)).map_err(|e| match e.kind() {
        ErrorKind::AlreadyExists => KeyStoreError::AlreadyExists,
        _ => KeyStoreError::Io(e),
    })?;
    f.write_all(&bytes).map_err(KeyStoreError::Io)?;
    f.sync_all().map_err(KeyStoreError::Io)
}

/// Read `node.key` from `dir`.
pub fn load(dir: &Path) -> Result<NodeKeys, KeyStoreError> {
    let bytes = Zeroizing::new(
        std::fs::read(dir.join(KEY_FILE)).map_err(|e| match e.kind() {
            ErrorKind::NotFound => KeyStoreError::Missing,
            _ => KeyStoreError::Io(e),
        })?,
    );
    let file: KeyFile = cbor::from_slice(&bytes, 256).map_err(|_| KeyStoreError::Corrupt)?;
    if file.v != VERSION {
        return Err(KeyStoreError::Corrupt);
    }
    Ok(NodeKeys {
        identity: SigningKey::from_seed(&file.identity_seed),
        noise: X25519Secret::from_bytes(file.noise_secret),
    })
}

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
        std::fs::write(
            dir.path().join(KEY_FILE),
            harpochat_core::cbor::to_vec(&file),
        )
        .unwrap();
        assert!(matches!(load(dir.path()), Err(KeyStoreError::Corrupt)));
    }

    #[cfg(unix)]
    #[test]
    fn keyfile_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        save(dir.path(), &NodeKeys::generate()).unwrap();
        let mode = std::fs::metadata(dir.path().join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
