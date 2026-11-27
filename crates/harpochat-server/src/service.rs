// SPDX-License-Identifier: Apache-2.0
//! Mailbox semantics over `envelope::Message` (spec §7.2–7.5).
//!
//! Real time (spec §7.5): a `SUBSCRIBE` deposits SURBs for a mailbox. Each
//! accepted `PUT` then consumes one to push the blob (`PUSH`), or a
//! `NOTIFY{pending}` when the blob does not fit a Small reply. The blob stays
//! stored until it is acknowledged: a lost push costs nothing but latency.
//!
//! Every failure is **silent**: a request with a bad signature, a replayed
//! nonce, an expired timestamp or a full mailbox gets no answer at all, so a
//! stranger cannot probe whether a mailbox exists (spec §8).

use std::collections::{HashMap, VecDeque};

use harpochat_core::envelope::{self, Message, StoredBlob};
use harpochat_core::hash::h;
use harpochat_core::link::SizeClass;
use harpochat_core::mailbox::{verify_put, verify_read, READ_SKEW_SECS};
use harpochat_core::sphinx::{max_message_len, surb_len};

use crate::config::Limits;
use crate::store::{MailboxStore, SeenCache};

/// How long PUT nonces are remembered (PUT carries no timestamp; Sphinx
/// replay tags cover older replays).
pub const PUT_NONCE_WINDOW_SECS: u64 = 86_400;
const NONCE_CACHE_ENTRIES: usize = 200_000;
/// Subscription SURBs kept per mailbox (spec §13: a stock of ~10).
pub const MAX_SURBS_PER_BOX: usize = 32;
/// Subscription SURBs kept by the node (≈ 40 MiB at most).
pub const MAX_SURBS_TOTAL: usize = 100_000;
/// Longest subscription; the phone renews it.
pub const MAX_SUBSCRIBE_SECS: u64 = 86_400;

/// SURB stocks deposited by SUBSCRIBE, oldest first.
#[derive(Default)]
struct Subscriptions {
    by_box: HashMap<[u8; 32], VecDeque<(Vec<u8>, u64)>>,
    total: usize,
}

impl Subscriptions {
    /// Add SURBs up to the caps; the excess is dropped silently.
    fn add(&mut self, mailbox_id: [u8; 32], surbs: Vec<Vec<u8>>, until: u64) {
        let q = self.by_box.entry(mailbox_id).or_default();
        for surb in surbs {
            if q.len() >= MAX_SURBS_PER_BOX || self.total >= MAX_SURBS_TOTAL {
                break;
            }
            q.push_back((surb, until));
            self.total += 1;
        }
        if q.is_empty() {
            self.by_box.remove(&mailbox_id);
        }
    }

    fn remove(&mut self, mailbox_id: &[u8; 32]) {
        if let Some(q) = self.by_box.remove(mailbox_id) {
            self.total -= q.len();
        }
    }

    fn has(&self, mailbox_id: &[u8; 32]) -> bool {
        self.by_box.contains_key(mailbox_id)
    }

    /// Oldest SURB still valid at `now`, if any.
    fn take(&mut self, mailbox_id: &[u8; 32], now: u64) -> Option<Vec<u8>> {
        let q = self.by_box.get_mut(mailbox_id)?;
        let mut found = None;
        while let Some((surb, until)) = q.pop_front() {
            self.total -= 1;
            if until > now {
                found = Some(surb);
                break;
            }
        }
        if q.is_empty() {
            self.by_box.remove(mailbox_id);
        }
        found
    }

    fn sweep(&mut self, now: u64) {
        let mut removed = 0;
        self.by_box.retain(|_, q| {
            let before = q.len();
            q.retain(|(_, until)| *until > now);
            removed += before - q.len();
            !q.is_empty()
        });
        self.total -= removed;
    }

    fn count(&self, mailbox_id: &[u8; 32]) -> usize {
        self.by_box.get(mailbox_id).map_or(0, VecDeque::len)
    }
}

/// A reply to send back through a SURB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// Serialized SURB to use.
    pub surb: Vec<u8>,
    /// Encoded envelope to send.
    pub message: Vec<u8>,
    /// Sent through a subscription (PUSH or NOTIFY), not a FETCH.
    pub push: bool,
}

/// The mailbox role of a node.
pub struct MailboxService {
    store: MailboxStore,
    put_nonces: SeenCache,
    read_nonces: SeenCache,
    subs: Subscriptions,
}

impl MailboxService {
    /// Empty service.
    pub fn new(limits: &Limits) -> Self {
        Self {
            store: MailboxStore::new(limits),
            put_nonces: SeenCache::new(PUT_NONCE_WINDOW_SECS, NONCE_CACHE_ENTRIES),
            read_nonces: SeenCache::new(2 * READ_SKEW_SECS, NONCE_CACHE_ENTRIES),
            subs: Subscriptions::default(),
        }
    }

    /// Drop expired blobs and expired subscription SURBs.
    pub fn sweep(&mut self, now: u64) {
        self.store.sweep(now);
        self.subs.sweep(now);
    }

    /// Subscription SURBs held for `mailbox_id` (tests, status).
    pub fn subscribed_surbs(&self, mailbox_id: &[u8; 32]) -> usize {
        self.subs.count(mailbox_id)
    }

    fn authorised_read(
        &mut self,
        mailbox_id: &[u8; 32],
        bound: Option<(harpochat_core::mailbox::ReadOp, Vec<u8>)>,
        read_auth: &harpochat_core::mailbox::ReadAuth,
        now: u64,
    ) -> bool {
        let Some((op, bound)) = bound else {
            return false;
        };
        verify_read(mailbox_id, op, &bound, read_auth, now).is_ok()
            && self
                .read_nonces
                .insert_new(h(&[mailbox_id, &read_auth.nonce]), now)
    }

    /// PUSH the new blob, or NOTIFY when it does not fit a Small reply.
    fn push(&mut self, mailbox_id: [u8; 32], stored: StoredBlob, now: u64) -> Vec<Reply> {
        let Some(surb) = self.subs.take(&mailbox_id, now) else {
            return Vec::new();
        };
        let push = envelope::encode(&Message::Push {
            mailbox_id,
            blobs: vec![stored],
        });
        let message = if push.len() <= max_message_len(SizeClass::Small) {
            push
        } else {
            let pending = self.store.pending(&mailbox_id, now);
            envelope::encode(&Message::Notify {
                mailbox_id,
                pending: u16::try_from(pending).unwrap_or(u16::MAX),
            })
        };
        vec![Reply {
            surb,
            message,
            push: true,
        }]
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
                if verify_put(&mailbox_id, &blob, &write_auth).is_err()
                    || !self
                        .put_nonces
                        .insert_new(h(&[&mailbox_id, &write_auth.nonce]), now)
                {
                    return Vec::new();
                }
                let copy = self.subs.has(&mailbox_id).then(|| blob.clone());
                match (self.store.put(mailbox_id, blob, now), copy) {
                    (Ok(id), Some(blob)) => self.push(mailbox_id, StoredBlob { id, blob }, now),
                    _ => Vec::new(),
                }
            }
            Message::Fetch {
                mailbox_id,
                read_auth,
                max,
                surbs,
            } => {
                if !self.authorised_read(&mailbox_id, bound, &read_auth, now) {
                    return Vec::new();
                }
                self.fetch_replies(&mailbox_id, max as usize, surbs, now)
            }
            Message::Ack {
                mailbox_id,
                read_auth,
                blob_ids,
            } => {
                if self.authorised_read(&mailbox_id, bound, &read_auth, now) {
                    self.store.ack(&mailbox_id, &blob_ids);
                }
                Vec::new()
            }
            Message::Subscribe {
                mailbox_id,
                read_auth,
                surbs,
                until,
            } => {
                if !self.authorised_read(&mailbox_id, bound, &read_auth, now) {
                    return Vec::new();
                }
                if until <= now {
                    self.subs.remove(&mailbox_id);
                } else if surbs.iter().all(|s| s.len() == surb_len()) {
                    let until = until.min(now.saturating_add(MAX_SUBSCRIBE_SECS));
                    self.subs.add(mailbox_id, surbs, until);
                }
                Vec::new()
            }
            // Cover traffic is discarded; replies (FETCH_RESPONSE, PUSH,
            // NOTIFY) are never addressed to a mailbox.
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
                push: false,
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

    fn subscribe(
        k: &MailboxKeys,
        signer: &MailboxKeys,
        surbs: Vec<Vec<u8>>,
        until: u64,
        nonce: u8,
    ) -> Message {
        let unsigned = Message::Subscribe {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(signer, ReadOp::Subscribe, b"", NOW, [0; 16]),
            surbs: surbs.clone(),
            until,
        };
        let (op, bound) = envelope::read_bound(&unsigned).unwrap();
        let mut read_auth = sign_read(signer, op, &bound, NOW, [nonce; 16]);
        read_auth.write_pub = k.write.public();
        read_auth.read_pub = k.read.public();
        Message::Subscribe {
            mailbox_id: k.mailbox_id(),
            read_auth,
            surbs,
            until,
        }
    }

    fn surbs(n: usize, tag: u8) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| vec![tag.wrapping_add(i as u8); surb_len()])
            .collect()
    }

    #[test]
    fn subscribe_then_put_pushes() {
        let mut s = MailboxService::new(&Limits::default());
        let k = keys();
        assert!(s
            .handle(subscribe(&k, &k, surbs(1, 0x40), NOW + 600, 9), NOW)
            .is_empty());
        let r = s.handle(put(&k, b"hello", 1), NOW);
        assert_eq!(r.len(), 1);
        assert!(r[0].push);
        assert_eq!(r[0].surb, vec![0x40; surb_len()]);
        let Message::Push { mailbox_id, blobs } = envelope::decode(&r[0].message).unwrap() else {
            panic!("expected PUSH")
        };
        assert_eq!(mailbox_id, k.mailbox_id());
        assert_eq!(blobs[0].blob, b"hello");
        assert!(r[0].message.len() <= max_message_len(SizeClass::Small));
        // The blob stays until acknowledged: a FETCH still returns it, with the same id.
        let f = s.handle(fetch(&k, &k, 1, 2, NOW), NOW);
        let Message::FetchResponse { blobs: fetched, .. } =
            envelope::decode(&f[0].message).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(fetched[0].id, blobs[0].id);
    }

    #[test]
    fn push_consumes_one_surb_each() {
        let mut s = MailboxService::new(&Limits::default());
        let k = keys();
        s.handle(subscribe(&k, &k, surbs(2, 0x40), NOW + 600, 9), NOW);
        assert_eq!(s.subscribed_surbs(&k.mailbox_id()), 2);
        let used: Vec<Vec<u8>> = (0..3u8)
            .flat_map(|i| s.handle(put(&k, b"m", 20 + i), NOW))
            .map(|r| r.surb)
            .collect();
        assert_eq!(used, surbs(2, 0x40));
        assert_eq!(s.subscribed_surbs(&k.mailbox_id()), 0);
    }

    #[test]
    fn large_blob_notifies() {
        let mut s = MailboxService::new(&Limits::default());
        let k = keys();
        s.handle(subscribe(&k, &k, surbs(1, 0x40), NOW + 600, 9), NOW);
        let big = vec![7u8; max_message_len(SizeClass::Small)];
        let r = s.handle(put(&k, &big, 1), NOW);
        assert_eq!(r.len(), 1);
        assert_eq!(
            envelope::decode(&r[0].message).unwrap(),
            Message::Notify {
                mailbox_id: k.mailbox_id(),
                pending: 1
            }
        );
    }

    #[test]
    fn subscribe_rejections_are_silent() {
        let mut s = MailboxService::new(&Limits::default());
        let k = keys();
        let stranger = MailboxKeys::derive(&[0x99; 32], 1);
        // Wrong read key.
        s.handle(subscribe(&k, &stranger, surbs(1, 1), NOW + 600, 1), NOW);
        assert_eq!(s.subscribed_surbs(&k.mailbox_id()), 0);
        // Replay of an accepted SUBSCRIBE adds nothing.
        let sub = subscribe(&k, &k, surbs(1, 2), NOW + 600, 2);
        s.handle(sub.clone(), NOW);
        s.handle(sub, NOW + 1);
        assert_eq!(s.subscribed_surbs(&k.mailbox_id()), 1);
        // SURBs of the wrong size are refused as a whole.
        s.handle(subscribe(&k, &k, vec![vec![0; 8]], NOW + 600, 3), NOW);
        assert_eq!(s.subscribed_surbs(&k.mailbox_id()), 1);
        // The stock is capped.
        for i in 0..20u8 {
            s.handle(subscribe(&k, &k, surbs(3, i), NOW + 600, 10 + i), NOW);
        }
        assert_eq!(s.subscribed_surbs(&k.mailbox_id()), MAX_SURBS_PER_BOX);
    }

    #[test]
    fn unsubscribe_with_past_until() {
        let mut s = MailboxService::new(&Limits::default());
        let k = keys();
        s.handle(subscribe(&k, &k, surbs(3, 1), NOW + 600, 1), NOW);
        s.handle(subscribe(&k, &k, vec![], NOW, 2), NOW);
        assert_eq!(s.subscribed_surbs(&k.mailbox_id()), 0);
        assert!(s.handle(put(&k, b"m", 3), NOW).is_empty());
    }

    #[test]
    fn expired_surbs_swept_and_never_used() {
        let mut s = MailboxService::new(&Limits::default());
        let k = keys();
        // `until` is clamped to one day.
        s.handle(subscribe(&k, &k, surbs(1, 1), u64::MAX, 1), NOW);
        assert!(s
            .handle(put(&k, b"late", 2), NOW + MAX_SUBSCRIBE_SECS + 1)
            .is_empty());
        s.handle(subscribe(&k, &k, surbs(2, 5), NOW + 10, 3), NOW);
        s.sweep(NOW + 11);
        assert_eq!(s.subscribed_surbs(&k.mailbox_id()), 0);
    }

    #[test]
    fn rejected_put_pushes_nothing() {
        let mut s = MailboxService::new(&Limits::default());
        let k = keys();
        s.handle(subscribe(&k, &k, surbs(2, 1), NOW + 600, 1), NOW);
        let p = put(&k, b"m", 7);
        assert_eq!(s.handle(p.clone(), NOW).len(), 1);
        // Replayed PUT: not stored again, no push, SURB kept.
        assert!(s.handle(p, NOW).is_empty());
        assert_eq!(s.subscribed_surbs(&k.mailbox_id()), 1);
    }
}
