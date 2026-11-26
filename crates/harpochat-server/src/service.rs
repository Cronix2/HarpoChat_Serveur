// SPDX-License-Identifier: Apache-2.0
//! Mailbox semantics over `envelope::Message` (spec §7.2–7.4).
//!
//! Every failure is **silent**: a request with a bad signature, a replayed
//! nonce, an expired timestamp or a full mailbox gets no answer at all, so a
//! stranger cannot probe whether a mailbox exists (spec §8).

use harpochat_core::envelope::{self, Message, StoredBlob};
use harpochat_core::hash::h;
use harpochat_core::link::SizeClass;
use harpochat_core::mailbox::{verify_put, verify_read, READ_SKEW_SECS};
use harpochat_core::sphinx::max_message_len;

use crate::config::Limits;
use crate::store::{MailboxStore, SeenCache};

/// How long PUT nonces are remembered (PUT carries no timestamp; Sphinx
/// replay tags cover older replays).
pub const PUT_NONCE_WINDOW_SECS: u64 = 86_400;
const NONCE_CACHE_ENTRIES: usize = 200_000;

/// A reply to send back through a SURB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// Serialized SURB to use.
    pub surb: Vec<u8>,
    /// Encoded envelope to send.
    pub message: Vec<u8>,
}

/// The mailbox role of a node.
pub struct MailboxService {
    store: MailboxStore,
    put_nonces: SeenCache,
    read_nonces: SeenCache,
}

impl MailboxService {
    /// Empty service.
    pub fn new(limits: &Limits) -> Self {
        Self {
            store: MailboxStore::new(limits),
            put_nonces: SeenCache::new(PUT_NONCE_WINDOW_SECS, NONCE_CACHE_ENTRIES),
            read_nonces: SeenCache::new(2 * READ_SKEW_SECS, NONCE_CACHE_ENTRIES),
        }
    }

    /// Access to the store (sweeping, counters).
    pub fn store_mut(&mut self) -> &mut MailboxStore {
        &mut self.store
    }

    /// Process one decoded message; returns the replies to send.
    pub fn handle(&mut self, msg: Message, now: u64) -> Vec<Reply> {
        let bound = envelope::read_bound(&msg);
        match msg {
            Message::Put {
                mailbox_id,
                write_auth,
                blob,
            } => {
                if verify_put(&mailbox_id, &blob, &write_auth).is_ok()
                    && self
                        .put_nonces
                        .insert_new(h(&[&mailbox_id, &write_auth.nonce]), now)
                {
                    let _ = self.store.put(mailbox_id, blob, now);
                }
                Vec::new()
            }
            Message::Fetch {
                mailbox_id,
                read_auth,
                max,
                surbs,
            } => {
                let Some((op, bound)) = bound else {
                    return Vec::new();
                };
                if verify_read(&mailbox_id, op, &bound, &read_auth, now).is_err()
                    || !self
                        .read_nonces
                        .insert_new(h(&[&mailbox_id, &read_auth.nonce]), now)
                {
                    return Vec::new();
                }
                self.fetch_replies(&mailbox_id, max as usize, surbs, now)
            }
            Message::Ack {
                mailbox_id,
                read_auth,
                blob_ids,
            } => {
                if let Some((op, bound)) = bound {
                    if verify_read(&mailbox_id, op, &bound, &read_auth, now).is_ok()
                        && self
                            .read_nonces
                            .insert_new(h(&[&mailbox_id, &read_auth.nonce]), now)
                    {
                        self.store.ack(&mailbox_id, &blob_ids);
                    }
                }
                Vec::new()
            }
            // Cover traffic is discarded; SUBSCRIBE arrives in P6; replies
            // (FETCH_RESPONSE, PUSH, NOTIFY) are never addressed to a mailbox.
            _ => Vec::new(),
        }
    }

    fn fetch_replies(
        &self,
        mailbox_id: &[u8; 32],
        max: usize,
        surbs: Vec<Vec<u8>>,
        now: u64,
    ) -> Vec<Reply> {
        let limit = max_message_len(SizeClass::Small);
        let fits = |blobs: &[StoredBlob]| {
            envelope::encode(&Message::FetchResponse {
                blobs: blobs.to_vec(),
                more: true,
            })
            .len()
                <= limit
        };
        let mut queue = self
            .store
            .fetch(mailbox_id, max, now)
            .into_iter()
            .peekable();
        let mut replies = Vec::new();
        for surb in surbs {
            let mut batch: Vec<StoredBlob> = Vec::new();
            while let Some(next) = queue.peek() {
                if !fits(std::slice::from_ref(next)) {
                    // Too large for a Small reply: left for a Large-class fetch (P6).
                    queue.next();
                    continue;
                }
                batch.push(next.clone());
                if !fits(&batch) {
                    batch.pop();
                    break;
                }
                queue.next();
            }
            let more = queue.peek().is_some();
            replies.push(Reply {
                surb,
                message: envelope::encode(&Message::FetchResponse { blobs: batch, more }),
            });
            if !more {
                break;
            }
        }
        replies
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harpochat_core::mailbox::{sign_put, sign_read, MailboxKeys, ReadOp};

    const NOW: u64 = 1_800_000_000;

    fn keys() -> MailboxKeys {
        MailboxKeys::derive(&[0x11; 32], harpochat_core::mailbox::epoch_of(NOW))
    }

    fn put(k: &MailboxKeys, blob: &[u8], nonce: u8) -> Message {
        Message::Put {
            mailbox_id: k.mailbox_id(),
            write_auth: sign_put(k, blob, [nonce; 16]),
            blob: blob.to_vec(),
        }
    }

    fn fetch(k: &MailboxKeys, signer: &MailboxKeys, surbs: usize, nonce: u8, ts: u64) -> Message {
        let unsigned = Message::Fetch {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(signer, ReadOp::Fetch, b"", ts, [0; 16]),
            max: 64,
            surbs: vec![vec![0x5C; 8]; surbs],
        };
        let (op, bound) = envelope::read_bound(&unsigned).unwrap();
        let Message::Fetch {
            mailbox_id,
            max,
            surbs,
            ..
        } = unsigned
        else {
            unreachable!()
        };
        let mut read_auth = sign_read(signer, op, &bound, ts, [nonce; 16]);
        // Keep the requested mailbox's public keys so the id matches; only the
        // signature (by `signer`) is under test.
        read_auth.write_pub = k.write.public();
        read_auth.read_pub = k.read.public();
        Message::Fetch {
            mailbox_id,
            read_auth,
            max,
            surbs,
        }
    }

    fn blobs_of(r: &Reply) -> (Vec<Vec<u8>>, bool) {
        match envelope::decode(&r.message).unwrap() {
            Message::FetchResponse { blobs, more } => {
                (blobs.into_iter().map(|b| b.blob).collect(), more)
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn put_then_fetch_returns_blob() {
        let mut s = MailboxService::new(&Limits::default());
        let k = keys();
        assert!(s.handle(put(&k, b"ct", 1), NOW).is_empty());
        let r = s.handle(fetch(&k, &k, 1, 2, NOW), NOW);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].surb, vec![0x5C; 8]);
        assert_eq!(blobs_of(&r[0]), (vec![b"ct".to_vec()], false));
    }

    #[test]
    fn fetch_with_wrong_read_key_is_silent() {
        let mut s = MailboxService::new(&Limits::default());
        let k = keys();
        s.handle(put(&k, b"ct", 1), NOW);
        let stranger = MailboxKeys::derive(&[0x99; 32], 1);
        assert!(s.handle(fetch(&k, &stranger, 1, 2, NOW), NOW).is_empty());
    }

    #[test]
    fn put_with_foreign_write_key_is_silent() {
        let mut s = MailboxService::new(&Limits::default());
        let k = keys();
        let other = MailboxKeys::derive(&[0x22; 32], 1);
        let Message::Put { write_auth, .. } = put(&other, b"spam", 1) else {
            unreachable!()
        };
        s.handle(
            Message::Put {
                mailbox_id: k.mailbox_id(),
                write_auth,
                blob: b"spam".to_vec(),
            },
            NOW,
        );
        let r = s.handle(fetch(&k, &k, 1, 2, NOW), NOW);
        assert_eq!(blobs_of(&r[0]).0.len(), 0);
    }

    #[test]
    fn replayed_put_stored_once() {
        let mut s = MailboxService::new(&Limits::default());
        let k = keys();
        let p = put(&k, b"ct", 1);
        s.handle(p.clone(), NOW);
        s.handle(p, NOW + 5);
        let r = s.handle(fetch(&k, &k, 1, 2, NOW), NOW);
        assert_eq!(blobs_of(&r[0]).0.len(), 1);
    }

    #[test]
    fn replayed_fetch_is_silent() {
        let mut s = MailboxService::new(&Limits::default());
        let k = keys();
        s.handle(put(&k, b"ct", 1), NOW);
        let f = fetch(&k, &k, 1, 2, NOW);
        assert_eq!(s.handle(f.clone(), NOW).len(), 1);
        assert!(s.handle(f, NOW + 1).is_empty());
    }

    #[test]
    fn fetch_splits_across_surbs() {
        let mut s = MailboxService::new(&Limits::default());
        let k = keys();
        for i in 0..3u8 {
            s.handle(put(&k, &[i; 700], 10 + i), NOW);
        }
        let r = s.handle(fetch(&k, &k, 2, 2, NOW), NOW);
        assert_eq!(r.len(), 2);
        let (first, more1) = blobs_of(&r[0]);
        let (second, more2) = blobs_of(&r[1]);
        assert!(more1);
        assert_eq!(first.len() + second.len(), 3);
        assert!(!more2);
        for reply in &r {
            assert!(reply.message.len() <= max_message_len(SizeClass::Small));
        }
    }

    #[test]
    fn more_set_when_surbs_run_out() {
        let mut s = MailboxService::new(&Limits::default());
        let k = keys();
        for i in 0..3u8 {
            s.handle(put(&k, &[i; 700], 10 + i), NOW);
        }
        let r = s.handle(fetch(&k, &k, 1, 2, NOW), NOW);
        assert_eq!(r.len(), 1);
        assert!(blobs_of(&r[0]).1);
    }

    #[test]
    fn ack_removes() {
        let mut s = MailboxService::new(&Limits::default());
        let k = keys();
        s.handle(put(&k, b"ct", 1), NOW);
        let r = s.handle(fetch(&k, &k, 1, 2, NOW), NOW);
        let Message::FetchResponse { blobs, .. } = envelope::decode(&r[0].message).unwrap() else {
            unreachable!()
        };
        let unsigned = Message::Ack {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(&k, ReadOp::Ack, b"", NOW, [0; 16]),
            blob_ids: vec![blobs[0].id],
        };
        let (op, bound) = envelope::read_bound(&unsigned).unwrap();
        s.handle(
            Message::Ack {
                mailbox_id: k.mailbox_id(),
                read_auth: sign_read(&k, op, &bound, NOW, [3; 16]),
                blob_ids: vec![blobs[0].id],
            },
            NOW,
        );
        let r = s.handle(fetch(&k, &k, 1, 4, NOW), NOW);
        assert!(blobs_of(&r[0]).0.is_empty());
    }

    #[test]
    fn expired_read_auth_is_silent() {
        let mut s = MailboxService::new(&Limits::default());
        let k = keys();
        s.handle(put(&k, b"ct", 1), NOW);
        assert!(s.handle(fetch(&k, &k, 1, 2, NOW - 3_600), NOW).is_empty());
    }
}
