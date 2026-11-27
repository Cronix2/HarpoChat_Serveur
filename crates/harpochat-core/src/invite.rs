// SPDX-License-Identifier: Apache-2.0
//! Node invite tokens (`hcn1-…`) and the join proof (spec §4.3).
//!
//! A sponsor runs `harpochat-server invite-node` and gets a token to paste on
//! the new machine. The token is `hcn1-` + Crockford Base32 of a CBOR
//! `Signed<NodeInvite>`. It contains a one-time secret: it must travel over a
//! trusted channel and never be logged. The new node sends it back inside its
//! [`JoinRequest`]; the sponsor checks its own signature, then burns it.

use core::fmt;

use data_encoding::{Encoding, Specification};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::bootstrap::RootEntry;
use crate::descriptor::{validate_endpoint, NodeDescriptor};
use crate::directory::Vouch;
use crate::keys::Hex;
use crate::signed::{Signed, SignedPayload};
use crate::{cbor, domain, CoreError, Result};

/// Token prefix, carrying the token format version.
pub const TOKEN_PREFIX: &str = "hcn1-";
/// Default token validity: 48 hours.
pub const INVITE_TTL_SECS: u64 = 48 * 3600;
/// Crockford Base32 alphabet (no I, L, O, U).
pub const CROCKFORD: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Largest accepted token payload, in bytes.
pub const MAX_TOKEN_BYTES: usize = 1024;

/// Invitation for a new node, signed by its sponsor.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct NodeInvite {
    /// Format version.
    pub v: u8,
    /// Sponsor identity (signer).
    #[serde(with = "serde_bytes")]
    pub sponsor_id: [u8; 32],
    /// Where the new node reaches the sponsor.
    pub sponsor_endpoints: Vec<String>,
    /// One-time secret proving possession of the token.
    #[serde(with = "serde_bytes")]
    pub secret: [u8; 32],
    /// Expiry, unix seconds.
    pub expires: u64,
}

impl fmt::Debug for NodeInvite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeInvite")
            .field("v", &self.v)
            .field("sponsor_id", &Hex(&self.sponsor_id))
            .field("sponsor_endpoints", &self.sponsor_endpoints)
            .field("secret", &"<redacted>")
            .field("expires", &self.expires)
            .finish()
    }
}

impl SignedPayload for NodeInvite {
    const DOMAIN: &'static str = domain::NODE_INVITE;
    fn signer(&self) -> [u8; 32] {
        self.sponsor_id
    }
}

fn crockford() -> Encoding {
    let mut spec = Specification::new();
    spec.symbols.push_str(CROCKFORD);
    spec.encoding()
        .expect("valid Crockford Base32 specification")
}

/// Render a signed invite as a `hcn1-…` token.
pub fn encode_token(invite: &Signed<NodeInvite>) -> String {
    format!(
        "{TOKEN_PREFIX}{}",
        crockford().encode(&cbor::to_vec(invite))
    )
}

/// Parse a pasted token: tolerant to whitespace, line breaks, `-` separators,
/// lowercase, and the Crockford look-alikes `O`→`0`, `I`/`L`→`1`. Verifies the
/// sponsor's signature and the expiry.
pub fn decode_token(text: &str, now_unix_secs: u64) -> Result<NodeInvite> {
    decode_signed_token(text, now_unix_secs)?.verify()
}

/// Like [`decode_token`], keeping the signed form (sent back to the sponsor
/// in [`JoinRequest`]).
pub fn decode_signed_token(text: &str, now_unix_secs: u64) -> Result<Signed<NodeInvite>> {
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let lower = compact.to_ascii_lowercase();
    if !lower.starts_with(TOKEN_PREFIX) {
        return Err(if lower.starts_with("hcn") {
            CoreError::UnsupportedVersion
        } else {
            CoreError::Malformed
        });
    }
    let body: String = compact[TOKEN_PREFIX.len()..]
        .chars()
        .filter(|c| *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect();
    if body.len() > MAX_TOKEN_BYTES * 2 {
        return Err(CoreError::TooLarge);
    }
    let bytes = crockford()
        .decode(body.as_bytes())
        .map_err(|_| CoreError::Malformed)?;
    let signed: Signed<NodeInvite> = cbor::from_slice(&bytes, MAX_TOKEN_BYTES)?;
    let invite = signed.verify()?;
    if invite.v != 1 {
        return Err(CoreError::UnsupportedVersion);
    }
    if invite.sponsor_endpoints.is_empty() {
        return Err(CoreError::Malformed);
    }
    invite
        .sponsor_endpoints
        .iter()
        .try_for_each(|e| validate_endpoint(e))?;
    if invite.expires <= now_unix_secs {
        return Err(CoreError::Expired);
    }
    Ok(signed)
}

/// First message of the `join` protocol, sent by the new node to its sponsor
/// over Noise. It carries the invite itself, so the sponsor needs no state to
/// recognise its own tokens: it checks its signature, then burns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    /// The invite, as pasted (signed by the sponsor).
    pub invite: Signed<NodeInvite>,
    /// The new node's self-signed descriptor.
    pub descriptor: Signed<NodeDescriptor>,
    /// `HMAC-SHA256(secret, descriptor.body)`.
    #[serde(with = "serde_bytes")]
    pub proof: [u8; 32],
}

/// The sponsor's answer. A refusal is uniform (`vouch: None`, nothing else)
/// and never says why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinResponse {
    /// Format version.
    pub v: u8,
    /// Vouch for the new node, signed by the sponsor.
    pub vouch: Option<Signed<Vouch>>,
    /// The sponsor's own chain up to a root (empty if it is a root).
    pub chain: Vec<Signed<Vouch>>,
    /// Roots the sponsor trusts: the new node's trust anchors.
    pub roots: Vec<RootEntry>,
}

impl JoinResponse {
    /// The uniform refusal.
    pub fn refusal() -> Self {
        Self {
            v: 1,
            vouch: None,
            chain: Vec::new(),
            roots: Vec::new(),
        }
    }
}

fn mac(secret: &[u8; 32]) -> Hmac<Sha256> {
    <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("HMAC accepts any key length")
}

/// Proof that the joiner holds the token secret, bound to its descriptor.
pub fn join_proof(secret: &[u8; 32], descriptor: &Signed<NodeDescriptor>) -> [u8; 32] {
    let mut m = mac(secret);
    m.update(&descriptor.body);
    m.finalize().into_bytes().into()
}

/// Constant-time check of a join proof.
pub fn verify_join_proof(secret: &[u8; 32], req: &JoinRequest) -> Result<()> {
    let mut m = mac(secret);
    m.update(&req.descriptor.body);
    m.verify_slice(&req.proof)
        .map_err(|_| CoreError::Unauthorized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::{NodeDescriptor, Role};
    use crate::keys::SigningKey;
    use crate::signed::Signed;
    use crate::CoreError;

    const NOW: u64 = 1_800_000_000;

    fn invite(sponsor: &SigningKey) -> NodeInvite {
        NodeInvite {
            v: 1,
            sponsor_id: sponsor.public(),
            sponsor_endpoints: vec!["wss://sponsor.example:443".into()],
            secret: [0x5A; 32],
            expires: NOW + INVITE_TTL_SECS,
        }
    }

    fn descriptor(k: &SigningKey) -> Signed<NodeDescriptor> {
        Signed::sign(
            k,
            &NodeDescriptor {
                v: 1,
                id_pub: k.public(),
                noise_pub: [2; 32],
                sphinx_pub: [3; 32],
                sphinx_key_epoch: 1,
                roles: vec![Role::Mix],
                endpoints: vec!["wss://new.example".into()],
                layer: 0,
                valid_until: NOW + 3_600,
            },
        )
    }

    #[test]
    fn token_roundtrip() {
        let s = SigningKey::from_seed(&[1; 32]);
        let token = encode_token(&Signed::sign(&s, &invite(&s)));
        assert_eq!(decode_token(&token, NOW), Ok(invite(&s)));
    }

    #[test]
    fn signed_token_roundtrip() {
        let s = SigningKey::from_seed(&[1; 32]);
        let signed = Signed::sign(&s, &invite(&s));
        let back = decode_signed_token(&encode_token(&signed), NOW).unwrap();
        assert_eq!(back, signed);
        assert_eq!(
            decode_signed_token(&encode_token(&signed), NOW + INVITE_TTL_SECS),
            Err(CoreError::Expired)
        );
    }

    #[test]
    fn join_response_roundtrip() {
        let s = SigningKey::from_seed(&[1; 32]);
        let n = SigningKey::from_seed(&[7; 32]);
        let r = JoinResponse {
            v: 1,
            vouch: Some(Signed::sign(
                &s,
                &Vouch {
                    v: 1,
                    node_id: n.public(),
                    sponsor_id: s.public(),
                    issued: NOW,
                },
            )),
            chain: vec![],
            roots: vec![RootEntry {
                id_pub: s.public(),
                endpoints: vec!["wss://r.example".into()],
            }],
        };
        let bytes = cbor::to_vec(&r);
        assert_eq!(cbor::from_slice::<JoinResponse>(&bytes, 4096), Ok(r));
        let refusal = cbor::to_vec(&JoinResponse::refusal());
        assert_eq!(
            cbor::from_slice::<JoinResponse>(&refusal, 4096)
                .unwrap()
                .vouch,
            None
        );
    }

    #[test]
    fn token_has_prefix_and_reasonable_length() {
        let s = SigningKey::from_seed(&[1; 32]);
        let token = encode_token(&Signed::sign(&s, &invite(&s)));
        assert!(token.starts_with(TOKEN_PREFIX));
        assert!(token.len() < 400, "token is {} chars", token.len());
        let body = &token[TOKEN_PREFIX.len()..];
        assert!(body.chars().all(|c| CROCKFORD.contains(c)));
    }

    #[test]
    fn token_tolerates_copy_paste_noise() {
        let s = SigningKey::from_seed(&[1; 32]);
        let token = encode_token(&Signed::sign(&s, &invite(&s)));
        let body = &token[TOKEN_PREFIX.len()..];
        let mut noisy = String::from("  HCN1-\n");
        for (i, c) in body.chars().enumerate() {
            if i > 0 && i % 8 == 0 {
                noisy.push_str(if i % 16 == 0 { "-" } else { " \r\n " });
            }
            noisy.push(match c {
                '0' => 'O',
                '1' => 'l',
                other => other.to_ascii_lowercase(),
            });
        }
        noisy.push('\n');
        assert_eq!(decode_token(&noisy, NOW), Ok(invite(&s)));
    }

    #[test]
    fn expired_token_rejected() {
        let s = SigningKey::from_seed(&[1; 32]);
        let token = encode_token(&Signed::sign(&s, &invite(&s)));
        assert_eq!(
            decode_token(&token, NOW + INVITE_TTL_SECS),
            Err(CoreError::Expired)
        );
    }

    #[test]
    fn wrong_prefix_rejected() {
        let s = SigningKey::from_seed(&[1; 32]);
        let token = encode_token(&Signed::sign(&s, &invite(&s)));
        let other = token.replacen("hcn1-", "hcn2-", 1);
        assert_eq!(
            decode_token(&other, NOW),
            Err(CoreError::UnsupportedVersion)
        );
    }

    #[test]
    fn tampered_token_rejected() {
        let s = SigningKey::from_seed(&[1; 32]);
        let token = encode_token(&Signed::sign(&s, &invite(&s)));
        let mut chars: Vec<char> = token.chars().collect();
        let i = chars.len() / 2;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(decode_token(&tampered, NOW).is_err());
    }

    #[test]
    fn token_signed_by_non_sponsor_rejected() {
        let s = SigningKey::from_seed(&[1; 32]);
        let other = SigningKey::from_seed(&[2; 32]);
        let token = encode_token(&Signed::sign(&other, &invite(&s)));
        assert_eq!(decode_token(&token, NOW), Err(CoreError::BadSignature));
    }

    #[test]
    fn join_proof_roundtrip() {
        let n = SigningKey::from_seed(&[7; 32]);
        let d = descriptor(&n);
        let s = SigningKey::from_seed(&[1; 32]);
        let req = JoinRequest {
            invite: Signed::sign(&s, &invite(&s)),
            proof: join_proof(&[0x5A; 32], &d),
            descriptor: d,
        };
        assert_eq!(verify_join_proof(&[0x5A; 32], &req), Ok(()));
        assert_eq!(
            verify_join_proof(&[0x5B; 32], &req),
            Err(CoreError::Unauthorized)
        );
    }

    #[test]
    fn join_proof_rejects_other_descriptor() {
        let d1 = descriptor(&SigningKey::from_seed(&[7; 32]));
        let d2 = descriptor(&SigningKey::from_seed(&[8; 32]));
        let s = SigningKey::from_seed(&[1; 32]);
        let req = JoinRequest {
            invite: Signed::sign(&s, &invite(&s)),
            proof: join_proof(&[0x5A; 32], &d1),
            descriptor: d2,
        };
        assert_eq!(
            verify_join_proof(&[0x5A; 32], &req),
            Err(CoreError::Unauthorized)
        );
    }

    #[test]
    fn debug_redacts_invite_secret() {
        let s = SigningKey::from_seed(&[1; 32]);
        let dbg = format!("{:?}", invite(&s));
        assert!(!dbg.contains("90,")); // 0x5A as decimal array element
        assert!(!dbg.to_lowercase().contains("5a5a"));
    }

    #[test]
    fn debug_of_signed_invite_redacts_secret() {
        let s = SigningKey::from_seed(&[1; 32]);
        let dbg = format!("{:?}", Signed::sign(&s, &invite(&s)));
        assert!(!dbg.to_lowercase().contains("5a5a5a5a"), "{dbg}");
    }
}
