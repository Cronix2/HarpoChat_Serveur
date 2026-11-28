// SPDX-License-Identifier: Apache-2.0
//! End-to-end encryption between contacts: the Olm double ratchet, from
//! vodozemac (the audited Rust implementation, Apache-2.0).
//!
//! The server never sees any of this: an Olm message is the inside of a
//! mailbox blob. Pure state machines, no I/O. The app stores the states as
//! *pickles*, encrypted here with a 32-byte key it holds (then in SQLCipher).
//!
//! Sessions use Olm v1 (libolm-compatible: AES-256-CBC, HMAC-SHA-256
//! truncated to 8 bytes). A pre-key message carries 154 bytes of overhead,
//! a normal message 48, plus the plaintext padded to 16 bytes.

use std::sync::{Arc, Mutex, MutexGuard};

use vodozemac::olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle};
use vodozemac::Curve25519PublicKey;

use crate::{fixed, FfiError, FfiResult};

/// Most one-time keys generated in one call (the account keeps at most 100).
pub const MAX_ONE_TIME_KEYS: u32 = 50;

fn lock<T>(m: &Mutex<T>) -> FfiResult<MutexGuard<'_, T>> {
    m.lock().map_err(|_| FfiError::InvalidArgument)
}

fn public_key(bytes: &[u8]) -> FfiResult<Curve25519PublicKey> {
    Ok(Curve25519PublicKey::from_bytes(fixed::<32>(bytes)?))
}

fn pickle_key(key: &[u8]) -> FfiResult<[u8; 32]> {
    fixed::<32>(key)
}

fn pickle_text(pickle: &[u8]) -> FfiResult<&str> {
    std::str::from_utf8(pickle).map_err(|_| FfiError::Malformed)
}

/// A device's long-term Olm identity and its one-time keys.
#[derive(uniffi::Object)]
pub struct OlmAccount(Mutex<Account>);

impl std::fmt::Debug for OlmAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OlmAccount")
    }
}

/// An encrypted Olm message: `msg_type` 0 is a pre-key message (first
/// messages of a session, until the other side answers), 1 a normal one.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OlmEncrypted {
    /// 0 = pre-key, 1 = normal.
    pub msg_type: u8,
    /// Message bytes.
    pub body: Vec<u8>,
}

/// Result of opening a session from a received pre-key message.
#[derive(Debug, uniffi::Record)]
pub struct OlmInbound {
    /// The new session (pickle it, and the account: a one-time key was used).
    pub session: Arc<OlmSession>,
    /// Plaintext of the pre-key message.
    pub plaintext: Vec<u8>,
}

#[uniffi::export]
impl OlmAccount {
    /// A fresh account (new identity key).
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(Account::new())))
    }

    /// Restore an account from [`OlmAccount::pickle`] with the same key.
    #[uniffi::constructor]
    pub fn from_pickle(pickle: Vec<u8>, key: Vec<u8>) -> FfiResult<Arc<Self>> {
        let p = AccountPickle::from_encrypted(pickle_text(&pickle)?, &pickle_key(&key)?)
            .map_err(|_| FfiError::BadSignature)?;
        Ok(Arc::new(Self(Mutex::new(Account::from_pickle(p)))))
    }

    /// Encrypted state, to store. `key`: 32 bytes held by the app.
    pub fn pickle(&self, key: Vec<u8>) -> FfiResult<Vec<u8>> {
        let key = pickle_key(&key)?;
        Ok(lock(&self.0)?.pickle().encrypt(&key).into_bytes())
    }

    /// Curve25519 identity key (32 bytes), to give to contacts.
    pub fn identity_key(&self) -> FfiResult<Vec<u8>> {
        Ok(lock(&self.0)?.curve25519_key().to_bytes().to_vec())
    }

    /// Generate `count` one-time keys (at most [`MAX_ONE_TIME_KEYS`]).
    pub fn generate_one_time_keys(&self, count: u32) -> FfiResult<()> {
        if count == 0 || count > MAX_ONE_TIME_KEYS {
            return Err(FfiError::InvalidArgument);
        }
        lock(&self.0)?.generate_one_time_keys(count as usize);
        Ok(())
    }

    /// One-time keys not yet marked published (32 bytes each).
    pub fn one_time_keys(&self) -> FfiResult<Vec<Vec<u8>>> {
        let mut keys: Vec<Vec<u8>> = lock(&self.0)?
            .one_time_keys()
            .into_values()
            .map(|k| k.to_bytes().to_vec())
            .collect();
        keys.sort();
        Ok(keys)
    }

    /// Mark the current one-time keys as handed out.
    pub fn mark_keys_as_published(&self) -> FfiResult<()> {
        lock(&self.0)?.mark_keys_as_published();
        Ok(())
    }

    /// Start a session with a contact, from their identity key and one of
    /// their one-time keys. Its first messages are pre-key messages.
    pub fn create_outbound_session(
        &self,
        their_identity_key: Vec<u8>,
        their_one_time_key: Vec<u8>,
    ) -> FfiResult<Arc<OlmSession>> {
        let session = lock(&self.0)?
            .create_outbound_session(
                SessionConfig::version_1(),
                public_key(&their_identity_key)?,
                public_key(&their_one_time_key)?,
            )
            .map_err(|_| FfiError::InvalidArgument)?;
        Ok(OlmSession::wrap(session))
    }

    /// Open the session a contact started, from their first (pre-key)
    /// message. Consumes the one-time key it used: pickle the account after.
    pub fn create_inbound_session(
        &self,
        their_identity_key: Vec<u8>,
        pre_key_message: Vec<u8>,
    ) -> FfiResult<OlmInbound> {
        let msg = match OlmMessage::from_parts(0, &pre_key_message) {
            Ok(OlmMessage::PreKey(m)) => m,
            _ => return Err(FfiError::Malformed),
        };
        let r = lock(&self.0)?
            .create_inbound_session(
                SessionConfig::version_1(),
                public_key(&their_identity_key)?,
                &msg,
            )
            .map_err(|_| FfiError::BadSignature)?;
        Ok(OlmInbound {
            session: OlmSession::wrap(r.session),
            plaintext: r.plaintext,
        })
    }
}

/// One double-ratchet session with one contact.
#[derive(uniffi::Object)]
pub struct OlmSession(Mutex<Session>);

impl std::fmt::Debug for OlmSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OlmSession")
    }
}

impl OlmSession {
    fn wrap(s: Session) -> Arc<Self> {
        Arc::new(Self(Mutex::new(s)))
    }
}

#[uniffi::export]
impl OlmSession {
    /// Restore a session from [`OlmSession::pickle`] with the same key.
    #[uniffi::constructor]
    pub fn from_pickle(pickle: Vec<u8>, key: Vec<u8>) -> FfiResult<Arc<Self>> {
        let p = SessionPickle::from_encrypted(pickle_text(&pickle)?, &pickle_key(&key)?)
            .map_err(|_| FfiError::BadSignature)?;
        Ok(Self::wrap(Session::from_pickle(p)))
    }

    /// Encrypted state, to store after every encrypt/decrypt.
    pub fn pickle(&self, key: Vec<u8>) -> FfiResult<Vec<u8>> {
        let key = pickle_key(&key)?;
        Ok(lock(&self.0)?.pickle().encrypt(&key).into_bytes())
    }

    /// Stable session identifier (same on both sides).
    pub fn session_id(&self) -> FfiResult<String> {
        Ok(lock(&self.0)?.session_id())
    }

    /// Encrypt a message for the contact.
    pub fn encrypt(&self, plaintext: Vec<u8>) -> FfiResult<OlmEncrypted> {
        let (t, body) = lock(&self.0)?
            .encrypt(&plaintext)
            .map_err(|_| FfiError::InvalidArgument)?
            .to_parts();
        Ok(OlmEncrypted {
            msg_type: u8::try_from(t).map_err(|_| FfiError::Malformed)?,
            body,
        })
    }

    /// Decrypt a message from the contact (out of order is fine; a replay
    /// or a forgery is refused).
    pub fn decrypt(&self, msg_type: u8, body: Vec<u8>) -> FfiResult<Vec<u8>> {
        let msg =
            OlmMessage::from_parts(msg_type.into(), &body).map_err(|_| FfiError::Malformed)?;
        lock(&self.0)?
            .decrypt(&msg)
            .map_err(|_| FfiError::BadSignature)
    }
}
