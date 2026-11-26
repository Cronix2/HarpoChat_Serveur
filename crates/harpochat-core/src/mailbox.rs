// SPDX-License-Identifier: Apache-2.0
//! Mailbox identifiers and stateless access control (design §5.4, spec §7).
//!
//! Per epoch `e`, both contacts derive from their (directional) pair secret a
//! write key and a read key. The mailbox identifier is a hash of the two
//! public keys, so a mailbox node can check any request with no
//! pre-registered state: it recomputes the identifier from the keys carried
//! in the request. Only the sender holds `write_sk`, only the recipient holds
//! `read_sk`.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::hash::{h, h_domain};
use crate::keys::{verify, SigningKey};
use crate::{domain, CoreError, Result};

/// Length of a mailbox epoch: one UTC day.
pub const EPOCH_SECS: u64 = 86_400;
/// Blob TTL in epochs (spec §7.3: 7 days). Clients poll this many epochs.
pub const TTL_EPOCHS: u32 = 7;
/// Accepted clock skew on read requests, in seconds.
pub const READ_SKEW_SECS: u64 = 600;

/// Epoch containing `now_unix_secs`.
pub fn epoch_of(now_unix_secs: u64) -> u32 {
    u32::try_from(now_unix_secs / EPOCH_SECS).unwrap_or(u32::MAX)
}

/// Epochs a client must poll: the current one and the previous ones still
/// within the TTL, newest first (7 in steady state).
pub fn epochs_to_poll(now_unix_secs: u64) -> Vec<u32> {
    let cur = epoch_of(now_unix_secs);
    (0..TTL_EPOCHS).filter_map(|i| cur.checked_sub(i)).collect()
}

/// Mailbox identifier from the two per-epoch public keys.
pub fn mailbox_id(write_pub: &[u8; 32], read_pub: &[u8; 32]) -> [u8; 32] {
    h_domain(domain::MBX_ID, &[write_pub, read_pub])
}

/// Per-epoch keys of one directional mailbox.
#[derive(Debug, Clone)]
pub struct MailboxKeys {
    /// Epoch these keys belong to.
    pub epoch: u32,
    /// Write key (held by the sender only).
    pub write: SigningKey,
    /// Read key (held by the recipient only).
    pub read: SigningKey,
}

impl MailboxKeys {
    /// HKDF-SHA256(ikm = pair_secret, info = `MBX_KEYS || epoch_be`) → 64
    /// bytes: write seed, then read seed.
    pub fn derive(pair_secret: &[u8; 32], epoch: u32) -> Self {
        let hk = Hkdf::<Sha256>::new(None, pair_secret);
        let mut info = domain::MBX_KEYS.as_bytes().to_vec();
        info.extend_from_slice(&epoch.to_be_bytes());
        let mut okm = Zeroizing::new([0u8; 64]);
        hk.expand(&info, okm.as_mut())
            .expect("64 bytes is a valid HKDF-SHA256 output length");
        let mut w = Zeroizing::new([0u8; 32]);
        let mut r = Zeroizing::new([0u8; 32]);
        w.copy_from_slice(&okm[..32]);
        r.copy_from_slice(&okm[32..]);
        Self {
            epoch,
            write: SigningKey::from_seed(&w),
            read: SigningKey::from_seed(&r),
        }
    }

    /// Identifier of this mailbox.
    pub fn mailbox_id(&self) -> [u8; 32] {
        mailbox_id(&self.write.public(), &self.read.public())
    }
}

/// Authorisation carried by a PUT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteAuth {
    /// Per-epoch write public key.
    #[serde(with = "serde_bytes")]
    pub write_pub: [u8; 32],
    /// Per-epoch read public key (needed to recompute the mailbox id).
    #[serde(with = "serde_bytes")]
    pub read_pub: [u8; 32],
    /// Random nonce (replay cache key on the mailbox node).
    #[serde(with = "serde_bytes")]
    pub nonce: [u8; 16],
    /// Signature by the write key.
    #[serde(with = "serde_bytes")]
    pub sig: [u8; 64],
}

pub(crate) fn put_message(mailbox_id: &[u8; 32], nonce: &[u8; 16], blob: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(80);
    m.extend_from_slice(mailbox_id);
    m.extend_from_slice(nonce);
    m.extend_from_slice(&h(&[blob]));
    m
}

/// Sign a PUT of `blob`: signature over `mailbox_id || nonce || H(blob)`.
pub fn sign_put(keys: &MailboxKeys, blob: &[u8], nonce: [u8; 16]) -> WriteAuth {
    let msg = put_message(&keys.mailbox_id(), &nonce, blob);
    WriteAuth {
        write_pub: keys.write.public(),
        read_pub: keys.read.public(),
        nonce,
        sig: keys.write.sign(domain::PUT, &msg),
    }
}

/// Check a PUT. `Unauthorized` if the keys do not belong to `mailbox_id`.
pub fn verify_put(mailbox_id: &[u8; 32], blob: &[u8], auth: &WriteAuth) -> Result<()> {
    if self::mailbox_id(&auth.write_pub, &auth.read_pub) != *mailbox_id {
        return Err(CoreError::Unauthorized);
    }
    let msg = put_message(mailbox_id, &auth.nonce, blob);
    verify(&auth.write_pub, domain::PUT, &msg, &auth.sig)
}

/// Read-side operations. The signed `bound` data is, per op:
/// FETCH = `max_be16 || concat(surbs)`, ACK = `concat(blob_ids)`,
/// SUBSCRIBE = `until_be64 || concat(surbs)` (see `envelope::read_bound`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReadOp {
    /// FETCH (envelope type 0x02).
    Fetch = 0x02,
    /// ACK (envelope type 0x03).
    Ack = 0x03,
    /// SUBSCRIBE (envelope type 0x06).
    Subscribe = 0x06,
}

/// Authorisation carried by FETCH / ACK / SUBSCRIBE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadAuth {
    /// Per-epoch write public key (needed to recompute the mailbox id).
    #[serde(with = "serde_bytes")]
    pub write_pub: [u8; 32],
    /// Per-epoch read public key.
    #[serde(with = "serde_bytes")]
    pub read_pub: [u8; 32],
    /// Client timestamp (unix seconds), checked within ±[`READ_SKEW_SECS`].
    pub ts: u64,
    /// Random nonce (replay cache key on the mailbox node).
    #[serde(with = "serde_bytes")]
    pub nonce: [u8; 16],
    /// Signature by the read key.
    #[serde(with = "serde_bytes")]
    pub sig: [u8; 64],
}

fn read_message(
    op: ReadOp,
    mailbox_id: &[u8; 32],
    ts: u64,
    nonce: &[u8; 16],
    bound: &[u8],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(89);
    m.push(op as u8);
    m.extend_from_slice(mailbox_id);
    m.extend_from_slice(&ts.to_be_bytes());
    m.extend_from_slice(nonce);
    m.extend_from_slice(&h(&[bound]));
    m
}

/// Sign a read-side request: `op || mailbox_id || ts_be || nonce || H(bound)`.
pub fn sign_read(
    keys: &MailboxKeys,
    op: ReadOp,
    bound: &[u8],
    ts: u64,
    nonce: [u8; 16],
) -> ReadAuth {
    let msg = read_message(op, &keys.mailbox_id(), ts, &nonce, bound);
    ReadAuth {
        write_pub: keys.write.public(),
        read_pub: keys.read.public(),
        ts,
        nonce,
        sig: keys.read.sign(domain::READ, &msg),
    }
}

/// Check a read-side request. Nonce replay caching is the server's job.
pub fn verify_read(
    mailbox_id: &[u8; 32],
    op: ReadOp,
    bound: &[u8],
    auth: &ReadAuth,
    now_unix_secs: u64,
) -> Result<()> {
    if self::mailbox_id(&auth.write_pub, &auth.read_pub) != *mailbox_id {
        return Err(CoreError::Unauthorized);
    }
    if auth.ts.saturating_add(READ_SKEW_SECS) < now_unix_secs {
        return Err(CoreError::Expired);
    }
    if auth.ts > now_unix_secs.saturating_add(READ_SKEW_SECS) {
        return Err(CoreError::NotYetValid);
    }
    let msg = read_message(op, mailbox_id, auth.ts, &auth.nonce, bound);
    verify(&auth.read_pub, domain::READ, &msg, &auth.sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoreError;

    const SECRET: [u8; 32] = [0x11; 32];
    const NOW: u64 = 86_400 * 20_000 + 3_600;

    #[test]
    fn derive_is_deterministic() {
        let a = MailboxKeys::derive(&SECRET, 20_000);
        let b = MailboxKeys::derive(&SECRET, 20_000);
        assert_eq!(a.mailbox_id(), b.mailbox_id());
        assert_eq!(a.write.public(), b.write.public());
        assert_ne!(a.write.public(), a.read.public());
    }

    #[test]
    fn epochs_rotate_ids() {
        let a = MailboxKeys::derive(&SECRET, 20_000);
        let b = MailboxKeys::derive(&SECRET, 20_001);
        assert_ne!(a.mailbox_id(), b.mailbox_id());
    }

    #[test]
    fn mailbox_id_matches_free_function() {
        let k = MailboxKeys::derive(&SECRET, 1);
        assert_eq!(
            k.mailbox_id(),
            mailbox_id(&k.write.public(), &k.read.public())
        );
    }

    #[test]
    fn epoch_of_boundaries() {
        assert_eq!(epoch_of(86_400 * 5 - 1), 4);
        assert_eq!(epoch_of(86_400 * 5), 5);
    }

    #[test]
    fn epoch_boundary_is_covered() {
        let written = epoch_of(86_400 * 20_000 - 1);
        let poll = epochs_to_poll(86_400 * 20_006 + 5);
        assert_eq!(poll.len(), 7);
        assert_eq!(poll[0], 20_006);
        assert!(!poll.contains(&written)); // 19_999 is 8 epochs back
        assert!(epochs_to_poll(86_400 * 20_000 + 5).contains(&written));
        assert!(epochs_to_poll(86_400 * 20_005 + 5).contains(&written));
        assert!(!epochs_to_poll(86_400 * 20_007).contains(&20_000));
        assert!(epochs_to_poll(86_400 * 20_006).contains(&20_000));
    }

    #[test]
    fn epochs_to_poll_near_zero() {
        assert_eq!(epochs_to_poll(10), vec![0]);
    }

    #[test]
    fn put_auth_roundtrip() {
        let k = MailboxKeys::derive(&SECRET, 20_000);
        let auth = sign_put(&k, b"blob", [0x22; 16]);
        assert_eq!(verify_put(&k.mailbox_id(), b"blob", &auth), Ok(()));
    }

    #[test]
    fn put_auth_rejects_other_blob() {
        let k = MailboxKeys::derive(&SECRET, 20_000);
        let auth = sign_put(&k, b"blob", [0x22; 16]);
        assert_eq!(
            verify_put(&k.mailbox_id(), b"blob2", &auth),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn put_auth_rejects_foreign_mailbox() {
        let a = MailboxKeys::derive(&SECRET, 20_000);
        let b = MailboxKeys::derive(&[0x12; 32], 20_000);
        let auth = sign_put(&a, b"blob", [0x22; 16]);
        assert_eq!(
            verify_put(&b.mailbox_id(), b"blob", &auth),
            Err(CoreError::Unauthorized)
        );
    }

    #[test]
    fn put_auth_rejects_read_key_signature() {
        let k = MailboxKeys::derive(&SECRET, 20_000);
        let mut auth = sign_put(&k, b"blob", [0x22; 16]);
        // Re-sign the same message with the read key: must fail.
        let id = k.mailbox_id();
        let msg = put_message(&id, &auth.nonce, b"blob");
        auth.sig = k.read.sign(crate::domain::PUT, &msg);
        assert_eq!(
            verify_put(&id, b"blob", &auth),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn read_auth_roundtrip() {
        let k = MailboxKeys::derive(&SECRET, 20_000);
        let auth = sign_read(&k, ReadOp::Fetch, b"bound", NOW, [1; 16]);
        assert_eq!(
            verify_read(&k.mailbox_id(), ReadOp::Fetch, b"bound", &auth, NOW),
            Ok(())
        );
    }

    #[test]
    fn read_auth_rejects_writer_key() {
        let k = MailboxKeys::derive(&SECRET, 20_000);
        let forged = MailboxKeys {
            epoch: k.epoch,
            write: k.write.clone(),
            read: k.write.clone(),
        };
        let mut auth = sign_read(&forged, ReadOp::Fetch, b"b", NOW, [1; 16]);
        auth.read_pub = k.read.public();
        auth.write_pub = k.write.public();
        assert_eq!(
            verify_read(&k.mailbox_id(), ReadOp::Fetch, b"b", &auth, NOW),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn read_auth_skew() {
        let k = MailboxKeys::derive(&SECRET, 20_000);
        let id = k.mailbox_id();
        let old = sign_read(&k, ReadOp::Ack, b"b", NOW - 601, [1; 16]);
        assert_eq!(
            verify_read(&id, ReadOp::Ack, b"b", &old, NOW),
            Err(CoreError::Expired)
        );
        let future = sign_read(&k, ReadOp::Ack, b"b", NOW + 601, [1; 16]);
        assert_eq!(
            verify_read(&id, ReadOp::Ack, b"b", &future, NOW),
            Err(CoreError::NotYetValid)
        );
        let edge = sign_read(&k, ReadOp::Ack, b"b", NOW - 600, [1; 16]);
        assert_eq!(verify_read(&id, ReadOp::Ack, b"b", &edge, NOW), Ok(()));
    }

    #[test]
    fn read_auth_bound_to_op() {
        let k = MailboxKeys::derive(&SECRET, 20_000);
        let auth = sign_read(&k, ReadOp::Fetch, b"b", NOW, [1; 16]);
        assert_eq!(
            verify_read(&k.mailbox_id(), ReadOp::Ack, b"b", &auth, NOW),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn read_auth_bound_to_data() {
        let k = MailboxKeys::derive(&SECRET, 20_000);
        let auth = sign_read(&k, ReadOp::Subscribe, b"b1", NOW, [1; 16]);
        assert_eq!(
            verify_read(&k.mailbox_id(), ReadOp::Subscribe, b"b2", &auth, NOW),
            Err(CoreError::BadSignature)
        );
    }
}
