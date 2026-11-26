// SPDX-License-Identifier: Apache-2.0
//! Signed objects.
//!
//! A signed object travels as the CBOR map `{ "body": bstr, "sig": bstr(64) }`
//! where `body` is the CBOR encoding of the payload and `sig` is an Ed25519
//! signature (see [`crate::keys::SigningKey::sign`]) over the **exact body
//! bytes** under the payload's domain. Verification never re-encodes, so no
//! canonical-CBOR rule is needed. This layout is design deviation **E6** from
//! the flat `{ …, sig }` structs sketched in the spec.

use core::fmt;
use core::marker::PhantomData;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::keys::{verify, Hex, SigningKey};
use crate::{cbor, Result};

/// Maximum body size of any signed object (directories are the largest).
pub const MAX_SIGNED_BODY: usize = 1 << 20;

/// A payload type that can be wrapped in [`Signed`].
pub trait SignedPayload: Serialize + DeserializeOwned {
    /// Signature domain (one per type, see [`crate::domain`]).
    const DOMAIN: &'static str;
    /// Public key expected to have signed this payload.
    fn signer(&self) -> [u8; 32];
}

/// A CBOR-encoded payload plus its Ed25519 signature.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound = "")]
pub struct Signed<T> {
    /// CBOR encoding of the payload; the signature covers these exact bytes.
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    /// Ed25519 signature over `body` under `T::DOMAIN`.
    #[serde(with = "serde_bytes")]
    pub sig: [u8; 64],
    #[serde(skip)]
    _t: PhantomData<fn() -> T>,
}

impl<T: SignedPayload> Signed<T> {
    /// Encode and sign `value` with `key`.
    pub fn sign(key: &SigningKey, value: &T) -> Self {
        let body = cbor::to_vec(value);
        let sig = key.sign(T::DOMAIN, &body);
        Self {
            body,
            sig,
            _t: PhantomData,
        }
    }

    /// Decode the body and check that `signer()` signed it.
    pub fn verify(&self) -> Result<T> {
        let value = self.peek()?;
        verify(&value.signer(), T::DOMAIN, &self.body, &self.sig)?;
        Ok(value)
    }

    /// Decode the body **without** checking the signature. Diagnostics only.
    pub fn peek(&self) -> Result<T> {
        cbor::from_slice(&self.body, MAX_SIGNED_BODY)
    }
}

impl<T> Clone for Signed<T> {
    fn clone(&self) -> Self {
        Self {
            body: self.body.clone(),
            sig: self.sig,
            _t: PhantomData,
        }
    }
}

impl<T> PartialEq for Signed<T> {
    fn eq(&self, other: &Self) -> bool {
        self.body == other.body && self.sig == other.sig
    }
}

impl<T> Eq for Signed<T> {}

impl<T> fmt::Debug for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signed")
            .field("body", &Hex(&self.body))
            .field("sig", &Hex(&self.sig))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKey;
    use crate::{cbor, CoreError};
    use proptest::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
    #[serde(deny_unknown_fields)]
    struct TestPayload {
        #[serde(with = "serde_bytes")]
        author: [u8; 32],
        n: u32,
    }

    impl SignedPayload for TestPayload {
        const DOMAIN: &'static str = "harpochat/v1/test";
        fn signer(&self) -> [u8; 32] {
            self.author
        }
    }

    fn sample() -> (SigningKey, TestPayload) {
        let k = SigningKey::from_seed(&[3; 32]);
        let p = TestPayload {
            author: k.public(),
            n: 42,
        };
        (k, p)
    }

    #[test]
    fn signed_roundtrip() {
        let (k, p) = sample();
        let s = Signed::sign(&k, &p);
        let wire = cbor::to_vec(&s);
        let back: Signed<TestPayload> = cbor::from_slice(&wire, 1024).unwrap();
        assert_eq!(back.verify(), Ok(p));
    }

    #[test]
    fn signed_rejects_tampered_body() {
        let (k, p) = sample();
        let mut s = Signed::sign(&k, &p);
        let last = s.body.len() - 1;
        s.body[last] ^= 1;
        assert!(s.verify().is_err());
    }

    #[test]
    fn signed_rejects_wrong_signer() {
        let (_, p) = sample();
        let other = SigningKey::from_seed(&[4; 32]);
        let s = Signed::sign(&other, &p); // payload claims author = key 3
        assert_eq!(s.verify(), Err(CoreError::BadSignature));
    }

    #[test]
    fn peek_does_not_verify() {
        let (_, p) = sample();
        let other = SigningKey::from_seed(&[4; 32]);
        let s = Signed::sign(&other, &p);
        assert_eq!(s.peek(), Ok(p));
    }

    proptest! {
        #[test]
        fn decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = cbor::from_slice::<Signed<TestPayload>>(&bytes, 4096);
        }
    }
}
