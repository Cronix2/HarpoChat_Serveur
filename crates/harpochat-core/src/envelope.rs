// SPDX-License-Identifier: Apache-2.0
//! Application messages: the final Sphinx payload (spec §8).
//!
//! Wire format: CBOR `Envelope { v: 1, type: u8, body: bstr }` where `body`
//! is the CBOR encoding of the variant's fields. `DIRECTORY_REQUEST` /
//! `DIRECTORY` (spec types 0x20/0x21) are **not** envelopes: they are link
//! frames (design deviation E1, see `crate::link`).

use serde::{Deserialize, Serialize};

use crate::mailbox::{ReadAuth, ReadOp, WriteAuth};
use crate::{cbor, CoreError, Result};

/// Envelope format version.
pub const VERSION: u8 = 1;
/// Upper bound on an encoded envelope (largest size class payload).
pub const MAX_ENVELOPE_LEN: usize = 32 * 1024;
/// Maximum SURBs in one FETCH or SUBSCRIBE.
pub const MAX_SURBS: usize = 16;
/// Maximum blob ids in one ACK.
pub const MAX_IDS: usize = 64;
/// Maximum blobs in one FETCH_RESPONSE or PUSH.
pub const MAX_BLOBS: usize = 64;

/// A blob held by a mailbox, as returned to its owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredBlob {
    /// Server-assigned identifier (used by ACK).
    #[serde(with = "serde_bytes")]
    pub id: [u8; 16],
    /// End-to-end encrypted content, opaque to the server.
    #[serde(with = "serde_bytes")]
    pub blob: Vec<u8>,
}

/// Every application message of spec §8 (except the directory, see E1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// 0x01 — deposit an E2EE blob.
    Put {
        /// Target mailbox.
        mailbox_id: [u8; 32],
        /// Write authorisation.
        write_auth: WriteAuth,
        /// Opaque E2EE blob.
        blob: Vec<u8>,
    },
    /// 0x02 — fetch pending blobs, answered through `surbs`.
    Fetch {
        /// Target mailbox.
        mailbox_id: [u8; 32],
        /// Read authorisation.
        read_auth: ReadAuth,
        /// Maximum blobs to return.
        max: u16,
        /// Serialized SURBs for the answer.
        surbs: Vec<Vec<u8>>,
    },
    /// 0x03 — delete blobs after reception.
    Ack {
        /// Target mailbox.
        mailbox_id: [u8; 32],
        /// Read authorisation.
        read_auth: ReadAuth,
        /// Blobs to delete.
        blob_ids: Vec<[u8; 16]>,
    },
    /// 0x04 — cover traffic, discarded on arrival.
    Drop,
    /// 0x05 — cover traffic that returns to its sender.
    Loop,
    /// 0x06 — real-time subscription with a stock of SURBs (spec §7.5).
    Subscribe {
        /// Target mailbox.
        mailbox_id: [u8; 32],
        /// Read authorisation.
        read_auth: ReadAuth,
        /// Serialized SURBs for pushes.
        surbs: Vec<Vec<u8>>,
        /// Subscription end (unix seconds).
        until: u64,
    },
    /// 0x10 — answer to FETCH, sent through a SURB.
    FetchResponse {
        /// Returned blobs.
        blobs: Vec<StoredBlob>,
        /// More blobs are waiting.
        more: bool,
    },
    /// 0x11 — pushed through a subscription SURB.
    Push {
        /// Mailbox the blobs come from.
        mailbox_id: [u8; 32],
        /// Pushed blobs.
        blobs: Vec<StoredBlob>,
    },
    /// 0x12 — "mail is waiting", when the blob is too large for a PUSH.
    Notify {
        /// Mailbox with pending mail.
        mailbox_id: [u8; 32],
        /// Number of pending blobs.
        pending: u16,
    },
}

impl Message {
    /// Spec §8 type code.
    pub fn type_code(&self) -> u8 {
        match self {
            Message::Put { .. } => 0x01,
            Message::Fetch { .. } => 0x02,
            Message::Ack { .. } => 0x03,
            Message::Drop => 0x04,
            Message::Loop => 0x05,
            Message::Subscribe { .. } => 0x06,
            Message::FetchResponse { .. } => 0x10,
            Message::Push { .. } => 0x11,
            Message::Notify { .. } => 0x12,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    v: u8,
    #[serde(rename = "type")]
    ty: u8,
    #[serde(with = "serde_bytes")]
    body: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PutBody {
    #[serde(with = "serde_bytes")]
    mailbox_id: [u8; 32],
    write_auth: WriteAuth,
    #[serde(with = "serde_bytes")]
    blob: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchBody {
    #[serde(with = "serde_bytes")]
    mailbox_id: [u8; 32],
    read_auth: ReadAuth,
    max: u16,
    #[serde(with = "cbor::vec_bytes")]
    surbs: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AckBody {
    #[serde(with = "serde_bytes")]
    mailbox_id: [u8; 32],
    read_auth: ReadAuth,
    #[serde(with = "cbor::vec_array")]
    blob_ids: Vec<[u8; 16]>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyBody {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubscribeBody {
    #[serde(with = "serde_bytes")]
    mailbox_id: [u8; 32],
    read_auth: ReadAuth,
    #[serde(with = "cbor::vec_bytes")]
    surbs: Vec<Vec<u8>>,
    until: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchResponseBody {
    blobs: Vec<StoredBlob>,
    more: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PushBody {
    #[serde(with = "serde_bytes")]
    mailbox_id: [u8; 32],
    blobs: Vec<StoredBlob>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NotifyBody {
    #[serde(with = "serde_bytes")]
    mailbox_id: [u8; 32],
    pending: u16,
}

/// Encode a message as an envelope.
pub fn encode(msg: &Message) -> Vec<u8> {
    let body = match msg.clone() {
        Message::Put {
            mailbox_id,
            write_auth,
            blob,
        } => cbor::to_vec(&PutBody {
            mailbox_id,
            write_auth,
            blob,
        }),
        Message::Fetch {
            mailbox_id,
            read_auth,
            max,
            surbs,
        } => cbor::to_vec(&FetchBody {
            mailbox_id,
            read_auth,
            max,
            surbs,
        }),
        Message::Ack {
            mailbox_id,
            read_auth,
            blob_ids,
        } => cbor::to_vec(&AckBody {
            mailbox_id,
            read_auth,
            blob_ids,
        }),
        Message::Drop | Message::Loop => cbor::to_vec(&EmptyBody {}),
        Message::Subscribe {
            mailbox_id,
            read_auth,
            surbs,
            until,
        } => cbor::to_vec(&SubscribeBody {
            mailbox_id,
            read_auth,
            surbs,
            until,
        }),
        Message::FetchResponse { blobs, more } => cbor::to_vec(&FetchResponseBody { blobs, more }),
        Message::Push { mailbox_id, blobs } => cbor::to_vec(&PushBody { mailbox_id, blobs }),
        Message::Notify {
            mailbox_id,
            pending,
        } => cbor::to_vec(&NotifyBody {
            mailbox_id,
            pending,
        }),
    };
    cbor::to_vec(&Envelope {
        v: VERSION,
        ty: msg.type_code(),
        body,
    })
}

fn limit(n: usize, max: usize) -> Result<()> {
    if n > max {
        Err(CoreError::TooLarge)
    } else {
        Ok(())
    }
}

/// Decode an envelope. Unknown version → `UnsupportedVersion`; unknown type
/// or bad body → `Malformed`; list limits exceeded → `TooLarge`.
pub fn decode(bytes: &[u8]) -> Result<Message> {
    let env: Envelope = cbor::from_slice(bytes, MAX_ENVELOPE_LEN)?;
    if env.v != VERSION {
        return Err(CoreError::UnsupportedVersion);
    }
    let b = &env.body;
    let max = MAX_ENVELOPE_LEN;
    let msg = match env.ty {
        0x01 => {
            let p: PutBody = cbor::from_slice(b, max)?;
            Message::Put {
                mailbox_id: p.mailbox_id,
                write_auth: p.write_auth,
                blob: p.blob,
            }
        }
        0x02 => {
            let p: FetchBody = cbor::from_slice(b, max)?;
            limit(p.surbs.len(), MAX_SURBS)?;
            Message::Fetch {
                mailbox_id: p.mailbox_id,
                read_auth: p.read_auth,
                max: p.max,
                surbs: p.surbs,
            }
        }
        0x03 => {
            let p: AckBody = cbor::from_slice(b, max)?;
            limit(p.blob_ids.len(), MAX_IDS)?;
            Message::Ack {
                mailbox_id: p.mailbox_id,
                read_auth: p.read_auth,
                blob_ids: p.blob_ids,
            }
        }
        0x04 => {
            let _: EmptyBody = cbor::from_slice(b, max)?;
            Message::Drop
        }
        0x05 => {
            let _: EmptyBody = cbor::from_slice(b, max)?;
            Message::Loop
        }
        0x06 => {
            let p: SubscribeBody = cbor::from_slice(b, max)?;
            limit(p.surbs.len(), MAX_SURBS)?;
            Message::Subscribe {
                mailbox_id: p.mailbox_id,
                read_auth: p.read_auth,
                surbs: p.surbs,
                until: p.until,
            }
        }
        0x10 => {
            let p: FetchResponseBody = cbor::from_slice(b, max)?;
            limit(p.blobs.len(), MAX_BLOBS)?;
            Message::FetchResponse {
                blobs: p.blobs,
                more: p.more,
            }
        }
        0x11 => {
            let p: PushBody = cbor::from_slice(b, max)?;
            limit(p.blobs.len(), MAX_BLOBS)?;
            Message::Push {
                mailbox_id: p.mailbox_id,
                blobs: p.blobs,
            }
        }
        0x12 => {
            let p: NotifyBody = cbor::from_slice(b, max)?;
            Message::Notify {
                mailbox_id: p.mailbox_id,
                pending: p.pending,
            }
        }
        _ => return Err(CoreError::Malformed),
    };
    Ok(msg)
}

/// The data a read authorisation is bound to (see [`ReadOp`]), or `None`
/// for messages that carry no read authorisation.
pub fn read_bound(msg: &Message) -> Option<(ReadOp, Vec<u8>)> {
    match msg {
        Message::Fetch { max, surbs, .. } => {
            let mut b = max.to_be_bytes().to_vec();
            surbs.iter().for_each(|s| b.extend_from_slice(s));
            Some((ReadOp::Fetch, b))
        }
        Message::Ack { blob_ids, .. } => Some((ReadOp::Ack, blob_ids.concat())),
        Message::Subscribe { surbs, until, .. } => {
            let mut b = until.to_be_bytes().to_vec();
            surbs.iter().for_each(|s| b.extend_from_slice(s));
            Some((ReadOp::Subscribe, b))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor;
    use crate::mailbox::{sign_put, sign_read, MailboxKeys, ReadOp};
    use crate::CoreError;
    use proptest::prelude::*;
    use serde::Serialize;

    fn keys() -> MailboxKeys {
        MailboxKeys::derive(&[0x11; 32], 20_000)
    }

    fn rt(m: Message) {
        let bytes = encode(&m);
        assert_eq!(decode(&bytes), Ok(m));
    }

    #[test]
    fn roundtrip_put() {
        let k = keys();
        rt(Message::Put {
            mailbox_id: k.mailbox_id(),
            write_auth: sign_put(&k, b"x", [2; 16]),
            blob: b"x".to_vec(),
        });
    }

    #[test]
    fn roundtrip_fetch() {
        let k = keys();
        rt(Message::Fetch {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(&k, ReadOp::Fetch, b"", 1, [3; 16]),
            max: 5,
            surbs: vec![vec![1; 10], vec![2; 10]],
        });
    }

    #[test]
    fn roundtrip_ack() {
        let k = keys();
        rt(Message::Ack {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(&k, ReadOp::Ack, b"", 1, [3; 16]),
            blob_ids: vec![[9; 16], [8; 16]],
        });
    }

    #[test]
    fn roundtrip_drop_and_loop() {
        rt(Message::Drop);
        rt(Message::Loop);
    }

    #[test]
    fn roundtrip_subscribe() {
        let k = keys();
        rt(Message::Subscribe {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(&k, ReadOp::Subscribe, b"", 1, [3; 16]),
            surbs: vec![vec![4; 20]],
            until: 99,
        });
    }

    #[test]
    fn roundtrip_fetch_response() {
        rt(Message::FetchResponse {
            blobs: vec![StoredBlob {
                id: [1; 16],
                blob: b"ct".to_vec(),
            }],
            more: true,
        });
    }

    #[test]
    fn roundtrip_push() {
        rt(Message::Push {
            mailbox_id: [5; 32],
            blobs: vec![StoredBlob {
                id: [1; 16],
                blob: b"ct".to_vec(),
            }],
        });
    }

    #[test]
    fn roundtrip_notify() {
        rt(Message::Notify {
            mailbox_id: [5; 32],
            pending: 3,
        });
    }

    #[test]
    fn type_codes_match_spec() {
        let k = keys();
        let id = k.mailbox_id();
        let ra = sign_read(&k, ReadOp::Fetch, b"", 1, [3; 16]);
        let cases: [(Message, u8); 9] = [
            (
                Message::Put {
                    mailbox_id: id,
                    write_auth: sign_put(&k, b"", [0; 16]),
                    blob: vec![],
                },
                0x01,
            ),
            (
                Message::Fetch {
                    mailbox_id: id,
                    read_auth: ra.clone(),
                    max: 1,
                    surbs: vec![],
                },
                0x02,
            ),
            (
                Message::Ack {
                    mailbox_id: id,
                    read_auth: ra.clone(),
                    blob_ids: vec![],
                },
                0x03,
            ),
            (Message::Drop, 0x04),
            (Message::Loop, 0x05),
            (
                Message::Subscribe {
                    mailbox_id: id,
                    read_auth: ra,
                    surbs: vec![],
                    until: 0,
                },
                0x06,
            ),
            (
                Message::FetchResponse {
                    blobs: vec![],
                    more: false,
                },
                0x10,
            ),
            (
                Message::Push {
                    mailbox_id: id,
                    blobs: vec![],
                },
                0x11,
            ),
            (
                Message::Notify {
                    mailbox_id: id,
                    pending: 0,
                },
                0x12,
            ),
        ];
        for (m, code) in cases {
            assert_eq!(m.type_code(), code);
        }
    }

    #[derive(Serialize)]
    struct RawEnvelope {
        v: u8,
        #[serde(rename = "type")]
        ty: u8,
        #[serde(with = "serde_bytes")]
        body: Vec<u8>,
    }

    #[test]
    fn unknown_type_rejected() {
        let raw = cbor::to_vec(&RawEnvelope {
            v: 1,
            ty: 0x07,
            body: cbor::to_vec(&()),
        });
        assert_eq!(decode(&raw), Err(CoreError::Malformed));
    }

    #[test]
    fn wrong_version_rejected() {
        let mut env: RawEnvelope = RawEnvelope {
            v: 2,
            ty: 0x04,
            body: vec![],
        };
        let raw = cbor::to_vec(&env);
        assert_eq!(decode(&raw), Err(CoreError::UnsupportedVersion));
        env.v = 1;
        env.body = encode(&Message::Drop)[..1].to_vec(); // garbage body
        assert_eq!(decode(&cbor::to_vec(&env)), Err(CoreError::Malformed));
    }

    #[test]
    fn too_many_surbs_rejected() {
        let k = keys();
        let m = Message::Fetch {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(&k, ReadOp::Fetch, b"", 1, [3; 16]),
            max: 1,
            surbs: vec![vec![0; 4]; MAX_SURBS + 1],
        };
        assert_eq!(decode(&encode(&m)), Err(CoreError::TooLarge));
    }

    #[test]
    fn too_many_blob_ids_rejected() {
        let k = keys();
        let m = Message::Ack {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(&k, ReadOp::Ack, b"", 1, [3; 16]),
            blob_ids: vec![[0; 16]; MAX_IDS + 1],
        };
        assert_eq!(decode(&encode(&m)), Err(CoreError::TooLarge));
    }

    #[test]
    fn read_bound_matches_definition() {
        let k = keys();
        let fetch = Message::Fetch {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(&k, ReadOp::Fetch, b"", 1, [3; 16]),
            max: 5,
            surbs: vec![vec![0xA1, 0xA2], vec![0xB1]],
        };
        assert_eq!(
            read_bound(&fetch),
            Some((ReadOp::Fetch, vec![0x00, 0x05, 0xA1, 0xA2, 0xB1]))
        );
        let ack = Message::Ack {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(&k, ReadOp::Ack, b"", 1, [3; 16]),
            blob_ids: vec![[1; 16], [2; 16]],
        };
        let mut expected = vec![1u8; 16];
        expected.extend_from_slice(&[2; 16]);
        assert_eq!(read_bound(&ack), Some((ReadOp::Ack, expected)));
        let sub = Message::Subscribe {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(&k, ReadOp::Subscribe, b"", 1, [3; 16]),
            surbs: vec![vec![7]],
            until: 0x0102,
        };
        assert_eq!(
            read_bound(&sub),
            Some((ReadOp::Subscribe, vec![0, 0, 0, 0, 0, 0, 1, 2, 7]))
        );
        assert_eq!(read_bound(&Message::Drop), None);
    }

    proptest! {
        #[test]
        fn decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = decode(&bytes);
        }
    }
}
