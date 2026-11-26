// SPDX-License-Identifier: Apache-2.0
//! Key types. Secrets are zeroized on drop and redacted from `Debug`.

use core::fmt;

use ed25519_dalek::{Signer, VerifyingKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{CoreError, Result};

/// Fill an array with OS randomness. Panics only if the OS RNG is unavailable,
/// which is unrecoverable for a cryptographic program.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("OS random number generator unavailable");
    out
}

/// Ed25519 signing key (node identity, mailbox keys, sponsors).
#[derive(Clone, ZeroizeOnDrop)]
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    /// Deterministic key from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// Fresh random key.
    pub fn generate() -> Self {
        let seed = Zeroizing::new(random_bytes::<32>());
        Self::from_seed(&seed)
    }

    /// Public key bytes.
    pub fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// The seed, for persisting a node identity. Zeroized when dropped.
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// Ed25519 signature over `len(domain) || domain || msg`.
    pub fn sign(&self, domain: &str, msg: &[u8]) -> [u8; 64] {
        let mut m = crate::domain::prefix(domain);
        m.extend_from_slice(msg);
        self.0.sign(&m).to_bytes()
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("public", &Hex(&self.public()))
            .finish_non_exhaustive()
    }
}

/// Verify a signature produced by [`SigningKey::sign`] (strict verification:
/// rejects small-order keys and non-canonical signatures).
pub fn verify(public: &[u8; 32], domain: &str, msg: &[u8], sig: &[u8; 64]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(public).map_err(|_| CoreError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(sig);
    let mut m = crate::domain::prefix(domain);
    m.extend_from_slice(msg);
    vk.verify_strict(&m, &sig)
        .map_err(|_| CoreError::BadSignature)
}

/// X25519 static secret (Sphinx node key, Noise static key).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519Secret([u8; 32]);

impl X25519Secret {
    /// From raw bytes (clamping happens inside x25519-dalek).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Fresh random secret.
    pub fn generate() -> Self {
        Self(random_bytes())
    }

    /// Raw secret bytes, for persisting. Zeroized when dropped.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0)
    }

    /// Public key bytes.
    pub fn public(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.to_dalek()).to_bytes()
    }

    /// Convert to the x25519-dalek type (used by the Sphinx façade).
    pub(crate) fn to_dalek(&self) -> x25519_dalek::StaticSecret {
        x25519_dalek::StaticSecret::from(self.0)
    }
}

impl fmt::Debug for X25519Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X25519Secret")
            .field("public", &Hex(&self.public()))
            .finish_non_exhaustive()
    }
}

/// Lowercase hex for public values in `Debug` output.
pub(crate) struct Hex<'a>(pub &'a [u8]);

impl fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain;
    use crate::CoreError;

    #[test]
    fn sign_verify_roundtrip() {
        let k = SigningKey::from_seed(&[1; 32]);
        let sig = k.sign(domain::VOUCH, b"msg");
        assert_eq!(verify(&k.public(), domain::VOUCH, b"msg", &sig), Ok(()));
    }

    #[test]
    fn verify_rejects_other_domain() {
        let k = SigningKey::from_seed(&[1; 32]);
        let sig = k.sign(domain::VOUCH, b"msg");
        assert_eq!(
            verify(&k.public(), domain::REVOKE, b"msg", &sig),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn verify_rejects_flipped_bit() {
        let k = SigningKey::from_seed(&[1; 32]);
        let mut sig = k.sign(domain::VOUCH, b"msg");
        sig[10] ^= 1;
        assert_eq!(
            verify(&k.public(), domain::VOUCH, b"msg", &sig),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn verify_rejects_invalid_public_key() {
        let sig = [0u8; 64];
        // Not a valid curve point encoding with a strict check.
        assert!(verify(&[0xff; 32], domain::VOUCH, b"m", &sig).is_err());
    }

    #[test]
    fn debug_redacts_secret() {
        let seed = [0xAB; 32];
        let k = SigningKey::from_seed(&seed);
        let dbg = format!("{k:?}");
        assert!(!dbg.to_lowercase().contains("abababab"));
        assert!(!dbg.contains("171,")); // decimal array of the seed
        let x = X25519Secret::from_bytes([0xAB; 32]);
        let xd = format!("{x:?}");
        assert!(!xd.contains("171,") && !xd.contains("abababab"));
    }

    #[test]
    fn generated_keys_differ() {
        assert_ne!(
            SigningKey::generate().public(),
            SigningKey::generate().public()
        );
        assert_ne!(random_bytes::<16>(), random_bytes::<16>());
    }

    #[test]
    fn x25519_public_is_deterministic() {
        let a = X25519Secret::from_bytes([5; 32]);
        let b = X25519Secret::from_bytes([5; 32]);
        assert_eq!(a.public(), b.public());
    }
}
