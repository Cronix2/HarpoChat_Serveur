// SPDX-License-Identifier: Apache-2.0
//! Noise XX link handshake with Ed25519 identity binding (design §5.1, E4).
//!
//! Pattern `Noise_XX_25519_ChaChaPoly_BLAKE2s`. Noise authenticates X25519
//! static keys; a node additionally proves that its static key belongs to its
//! Ed25519 identity by sending `NodeAuth { id_pub, sig }` with
//! `sig = Ed25519(id, "harpochat/v1/noise-static", noise_static_pub)` inside
//! its (encrypted) handshake payload: message 2 for the responder, message 3
//! for the initiator. A phone has no identity: it uses a fresh static key per
//! connection and sends an empty payload.
//!
//! Pure state machine: the caller moves the bytes (WebSocket binary frames).

use serde::{Deserialize, Serialize};

use crate::keys::{verify, SigningKey, X25519Secret};
use crate::link::SizeClass;
use crate::{cbor, domain, CoreError, Result};

/// Noise protocol name.
pub const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
/// Largest accepted handshake message.
pub const MAX_HANDSHAKE_MSG: usize = 1024;

/// Proof that a Noise static key belongs to an Ed25519 node identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAuth {
    /// Node identity.
    #[serde(with = "serde_bytes")]
    pub id_pub: [u8; 32],
    /// `Ed25519(id, NOISE_STATIC, noise_static_pub)`.
    #[serde(with = "serde_bytes")]
    pub sig: [u8; 64],
}

/// What the handshake established about the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// Peer's Noise static key.
    pub noise_static: [u8; 32],
    /// Peer's node identity, if it proved one (phones never do).
    pub node_id: Option<[u8; 32]>,
}

/// An in-progress XX handshake.
pub struct Handshake {
    hs: snow::HandshakeState,
    initiator: bool,
    step: u8,
    auth: Option<NodeAuth>,
    peer_node: Option<[u8; 32]>,
    #[cfg(test)]
    pub(crate) auth_override: Option<NodeAuth>,
}

impl core::fmt::Debug for Handshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Handshake")
            .field("initiator", &self.initiator)
            .field("step", &self.step)
            .finish_non_exhaustive()
    }
}

impl Handshake {
    fn build(
        local_static: &X25519Secret,
        identity: Option<&SigningKey>,
        initiator: bool,
    ) -> Result<Self> {
        let params = PATTERN.parse().map_err(|_| CoreError::Malformed)?;
        let key = local_static.to_bytes();
        let builder = snow::Builder::new(params)
            .local_private_key(key.as_ref())
            .map_err(|_| CoreError::Malformed)?;
        let hs = if initiator {
            builder.build_initiator()
        } else {
            builder.build_responder()
        }
        .map_err(|_| CoreError::Malformed)?;
        let auth = identity.map(|id| NodeAuth {
            id_pub: id.public(),
            sig: id.sign(domain::NOISE_STATIC, &local_static.public()),
        });
        Ok(Self {
            hs,
            initiator,
            step: 0,
            auth,
            peer_node: None,
            #[cfg(test)]
            auth_override: None,
        })
    }

    /// Start as initiator (phone, or node dialing a node).
    pub fn initiator(local_static: &X25519Secret, identity: Option<&SigningKey>) -> Result<Self> {
        Self::build(local_static, identity, true)
    }

    /// Start as responder (node accepting a connection).
    pub fn responder(local_static: &X25519Secret, identity: Option<&SigningKey>) -> Result<Self> {
        Self::build(local_static, identity, false)
    }

    fn our_auth_turn(&self) -> bool {
        (self.initiator && self.step == 2) || (!self.initiator && self.step == 1)
    }

    /// Produce the next handshake message.
    pub fn write_message(&mut self) -> Result<Vec<u8>> {
        let payload = if self.our_auth_turn() {
            #[cfg(test)]
            let auth = self.auth_override.as_ref().or(self.auth.as_ref());
            #[cfg(not(test))]
            let auth = self.auth.as_ref();
            auth.map(cbor::to_vec).unwrap_or_default()
        } else {
            Vec::new()
        };
        let mut buf = vec![0u8; MAX_HANDSHAKE_MSG];
        let n = self
            .hs
            .write_message(&payload, &mut buf)
            .map_err(|_| CoreError::Malformed)?;
        buf.truncate(n);
        self.step += 1;
        Ok(buf)
    }

    /// Consume the peer's next handshake message.
    pub fn read_message(&mut self, msg: &[u8]) -> Result<()> {
        if msg.len() > MAX_HANDSHAKE_MSG {
            return Err(CoreError::TooLarge);
        }
        let mut buf = vec![0u8; MAX_HANDSHAKE_MSG];
        let n = self
            .hs
            .read_message(msg, &mut buf)
            .map_err(|_| CoreError::Malformed)?;
        self.step += 1;
        if n == 0 {
            return Ok(());
        }
        // Only the message carrying the peer's static key may carry NodeAuth.
        let carries_static =
            (self.initiator && self.step == 2) || (!self.initiator && self.step == 3);
        if !carries_static {
            return Err(CoreError::Malformed);
        }
        let auth: NodeAuth = cbor::from_slice(&buf[..n], MAX_HANDSHAKE_MSG)?;
        let remote: [u8; 32] = self
            .hs
            .get_remote_static()
            .and_then(|k| k.try_into().ok())
            .ok_or(CoreError::Malformed)?;
        verify(&auth.id_pub, domain::NOISE_STATIC, &remote, &auth.sig)?;
        self.peer_node = Some(auth.id_pub);
        Ok(())
    }

    /// All three messages exchanged.
    pub fn is_finished(&self) -> bool {
        self.hs.is_handshake_finished()
    }

    /// Switch to transport mode.
    pub fn into_transport(self) -> Result<(Transport, Peer)> {
        if !self.is_finished() {
            return Err(CoreError::Malformed);
        }
        let noise_static: [u8; 32] = self
            .hs
            .get_remote_static()
            .and_then(|k| k.try_into().ok())
            .ok_or(CoreError::Malformed)?;
        let ts = self
            .hs
            .into_transport_mode()
            .map_err(|_| CoreError::Malformed)?;
        Ok((
            Transport { ts },
            Peer {
                noise_static,
                node_id: self.peer_node,
            },
        ))
    }
}

fn class_of_plaintext(len: usize) -> Option<SizeClass> {
    [SizeClass::Small, SizeClass::Large]
        .into_iter()
        .find(|c| c.plaintext_len() == len)
}

fn class_of_ciphertext(len: usize) -> Option<SizeClass> {
    [SizeClass::Small, SizeClass::Large]
        .into_iter()
        .find(|c| c.ciphertext_len() == len)
}

/// Established Noise session; every message has a fixed class size.
pub struct Transport {
    ts: snow::TransportState,
}

impl core::fmt::Debug for Transport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Transport(..)")
    }
}

impl Transport {
    /// Encrypt one link frame (exactly a class `plaintext_len`).
    pub fn encrypt(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        let class = class_of_plaintext(frame.len()).ok_or(CoreError::Malformed)?;
        let mut out = vec![0u8; class.ciphertext_len()];
        let n = self
            .ts
            .write_message(frame, &mut out)
            .map_err(|_| CoreError::Malformed)?;
        debug_assert_eq!(n, out.len());
        Ok(out)
    }

    /// Decrypt one message (exactly a class `ciphertext_len`).
    pub fn decrypt(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        let class = class_of_ciphertext(msg.len()).ok_or(CoreError::Malformed)?;
        let mut out = vec![0u8; class.plaintext_len()];
        let n = self
            .ts
            .read_message(msg, &mut out)
            .map_err(|_| CoreError::BadSignature)?;
        out.truncate(n);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{SigningKey, X25519Secret};
    use crate::link::SizeClass;
    use crate::CoreError;

    fn run(mut i: Handshake, mut r: Handshake) -> ((Transport, Peer), (Transport, Peer)) {
        let m1 = i.write_message().unwrap();
        r.read_message(&m1).unwrap();
        let m2 = r.write_message().unwrap();
        i.read_message(&m2).unwrap();
        let m3 = i.write_message().unwrap();
        r.read_message(&m3).unwrap();
        assert!(i.is_finished() && r.is_finished());
        (i.into_transport().unwrap(), r.into_transport().unwrap())
    }

    fn node() -> (X25519Secret, SigningKey) {
        (X25519Secret::generate(), SigningKey::generate())
    }

    #[test]
    fn anonymous_initiator_authenticates_node() {
        let (ns, nid) = node();
        let phone = X25519Secret::generate();
        let i = Handshake::initiator(&phone, None).unwrap();
        let r = Handshake::responder(&ns, Some(&nid)).unwrap();
        let ((_, peer_seen_by_phone), (_, peer_seen_by_node)) = run(i, r);
        assert_eq!(peer_seen_by_phone.node_id, Some(nid.public()));
        assert_eq!(peer_seen_by_phone.noise_static, ns.public());
        assert_eq!(peer_seen_by_node.node_id, None);
        assert_eq!(peer_seen_by_node.noise_static, phone.public());
    }

    #[test]
    fn node_to_node_mutual_identity() {
        let (a_s, a_id) = node();
        let (b_s, b_id) = node();
        let i = Handshake::initiator(&a_s, Some(&a_id)).unwrap();
        let r = Handshake::responder(&b_s, Some(&b_id)).unwrap();
        let ((_, seen_by_a), (_, seen_by_b)) = run(i, r);
        assert_eq!(seen_by_a.node_id, Some(b_id.public()));
        assert_eq!(seen_by_b.node_id, Some(a_id.public()));
    }

    #[test]
    fn forged_node_auth_fails() {
        // The responder signs a static key that is not the one it uses.
        let (ns, nid) = node();
        let other = X25519Secret::generate();
        let mut r = Handshake::responder(&ns, Some(&nid)).unwrap();
        r.auth_override = Some(NodeAuth {
            id_pub: nid.public(),
            sig: nid.sign(crate::domain::NOISE_STATIC, &other.public()),
        });
        let mut i = Handshake::initiator(&X25519Secret::generate(), None).unwrap();
        let m1 = i.write_message().unwrap();
        r.read_message(&m1).unwrap();
        let m2 = r.write_message().unwrap();
        assert_eq!(i.read_message(&m2), Err(CoreError::BadSignature));
    }

    #[test]
    fn transport_roundtrip_both_classes() {
        let (ns, nid) = node();
        let i = Handshake::initiator(&X25519Secret::generate(), None).unwrap();
        let r = Handshake::responder(&ns, Some(&nid)).unwrap();
        let ((mut ti, _), (mut tr, _)) = run(i, r);
        for class in [SizeClass::Small, SizeClass::Large] {
            let frame = vec![7u8; class.plaintext_len()];
            let ct = ti.encrypt(&frame).unwrap();
            assert_eq!(ct.len(), class.ciphertext_len());
            assert_eq!(tr.decrypt(&ct).unwrap(), frame);
            let back = tr.encrypt(&frame).unwrap();
            assert_eq!(ti.decrypt(&back).unwrap(), frame);
        }
    }

    #[test]
    fn transport_rejects_wrong_sizes() {
        let (ns, nid) = node();
        let i = Handshake::initiator(&X25519Secret::generate(), None).unwrap();
        let r = Handshake::responder(&ns, Some(&nid)).unwrap();
        let ((mut ti, _), (mut tr, _)) = run(i, r);
        assert_eq!(ti.encrypt(&[0; 100]).err(), Some(CoreError::Malformed));
        assert_eq!(tr.decrypt(&[0; 100]).err(), Some(CoreError::Malformed));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (ns, nid) = node();
        let i = Handshake::initiator(&X25519Secret::generate(), None).unwrap();
        let r = Handshake::responder(&ns, Some(&nid)).unwrap();
        let ((mut ti, _), (mut tr, _)) = run(i, r);
        let mut ct = ti
            .encrypt(&vec![1; SizeClass::Small.plaintext_len()])
            .unwrap();
        ct[100] ^= 1;
        assert_eq!(tr.decrypt(&ct).err(), Some(CoreError::BadSignature));
    }

    #[test]
    fn oversized_handshake_message_rejected() {
        let (ns, nid) = node();
        let mut r = Handshake::responder(&ns, Some(&nid)).unwrap();
        assert_eq!(
            r.read_message(&vec![0; MAX_HANDSHAKE_MSG + 1]),
            Err(CoreError::TooLarge)
        );
    }
}
