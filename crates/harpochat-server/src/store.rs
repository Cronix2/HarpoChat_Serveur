// SPDX-License-Identifier: Apache-2.0
//! RAM-only mailbox store and "seen" caches (spec §7.3, design §5.5–5.6).
//!
//! Nothing here ever touches the disk. Quotas reject new blobs rather than
//! evicting old ones (spec §7.3: "pas d'éviction silencieuse").

use std::collections::{HashMap, HashSet, VecDeque};

use harpochat_core::envelope::StoredBlob;
use harpochat_core::keys::random_bytes;

use crate::config::Limits;

/// Accounting overhead charged per stored blob, in bytes.
pub const BLOB_OVERHEAD: u64 = 64;

/// Why a PUT was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejected {
    /// This mailbox is at its blob or byte quota.
    MailboxFull,
    /// The node is at its global RAM cap.
    NodeFull,
}

struct Entry {
    id: [u8; 16],
    blob: Vec<u8>,
    expires: u64,
}

impl Entry {
    fn cost(&self) -> u64 {
        self.blob.len() as u64 + BLOB_OVERHEAD
    }
}

#[derive(Default)]
struct Mailbox {
    entries: VecDeque<Entry>,
    bytes: u64,
}

/// All mailboxes of this node, in RAM.
pub struct MailboxStore {
    boxes: HashMap<[u8; 32], Mailbox>,
    ram: u64,
    max_blobs: usize,
    max_box_bytes: u64,
    max_ram: u64,
    ttl: u64,
}

impl MailboxStore {
    /// Empty store with the configured limits.
    pub fn new(limits: &Limits) -> Self {
        Self {
            boxes: HashMap::new(),
            ram: 0,
            max_blobs: limits.mailbox_max_blobs as usize,
            max_box_bytes: limits.mailbox_max_bytes,
            max_ram: limits.global_ram_bytes,
            ttl: limits.blob_ttl_secs,
        }
    }

    /// Store a blob; returns its identifier.
    pub fn put(
        &mut self,
        mailbox_id: [u8; 32],
        blob: Vec<u8>,
        now: u64,
    ) -> Result<[u8; 16], Rejected> {
        let entry = Entry {
            id: random_bytes(),
            blob,
            expires: now.saturating_add(self.ttl),
        };
        let cost = entry.cost();
        if self.ram.saturating_add(cost) > self.max_ram {
            return Err(Rejected::NodeFull);
        }
        let b = self.boxes.entry(mailbox_id).or_default();
        if b.entries.len() >= self.max_blobs || b.bytes.saturating_add(cost) > self.max_box_bytes {
            if b.entries.is_empty() {
                self.boxes.remove(&mailbox_id);
            }
            return Err(Rejected::MailboxFull);
        }
        let id = entry.id;
        b.bytes += cost;
        b.entries.push_back(entry);
        self.ram += cost;
        Ok(id)
    }

    /// Up to `max` non-expired blobs, oldest first. Non-destructive.
    pub fn fetch(&self, mailbox_id: &[u8; 32], max: usize, now: u64) -> Vec<StoredBlob> {
        self.boxes
            .get(mailbox_id)
            .map(|b| {
                b.entries
                    .iter()
                    .filter(|e| e.expires > now)
                    .take(max)
                    .map(|e| StoredBlob {
                        id: e.id,
                        blob: e.blob.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Number of non-expired blobs waiting in a mailbox.
    pub fn pending(&self, mailbox_id: &[u8; 32], now: u64) -> usize {
        self.boxes
            .get(mailbox_id)
            .map(|b| b.entries.iter().filter(|e| e.expires > now).count())
            .unwrap_or(0)
    }

    /// Delete acknowledged blobs; returns how many were removed.
    pub fn ack(&mut self, mailbox_id: &[u8; 32], ids: &[[u8; 16]]) -> usize {
        let Some(b) = self.boxes.get_mut(mailbox_id) else {
            return 0;
        };
        let before = b.entries.len();
        let mut freed = 0;
        b.entries.retain(|e| {
            let keep = !ids.contains(&e.id);
            if !keep {
                freed += e.cost();
            }
            keep
        });
        b.bytes -= freed;
        self.ram -= freed;
        let removed = before - b.entries.len();
        if b.entries.is_empty() {
            self.boxes.remove(mailbox_id);
        }
        removed
    }

    /// Drop expired blobs and empty mailboxes; returns blobs removed.
    pub fn sweep(&mut self, now: u64) -> usize {
        let mut removed = 0;
        let mut freed = 0;
        self.boxes.retain(|_, b| {
            b.entries.retain(|e| {
                let keep = e.expires > now;
                if !keep {
                    removed += 1;
                    freed += e.cost();
                    b.bytes -= e.cost();
                }
                keep
            });
            !b.entries.is_empty()
        });
        self.ram -= freed;
        removed
    }

    /// Bytes currently accounted.
    pub fn ram_bytes(&self) -> u64 {
        self.ram
    }

    /// Number of non-empty mailboxes.
    pub fn boxes(&self) -> usize {
        self.boxes.len()
    }
}

/// Two-generation set of recently seen 32-byte keys (auth nonces, Sphinx
/// replay tags). Memory is bounded by `2 * max_entries`; an entry is
/// remembered for at least `window_secs` unless the cache fills first.
pub struct SeenCache {
    current: HashSet<[u8; 32]>,
    previous: HashSet<[u8; 32]>,
    started: Option<u64>,
    window: u64,
    max: usize,
}

impl SeenCache {
    /// Empty cache.
    pub fn new(window_secs: u64, max_entries: usize) -> Self {
        Self {
            current: HashSet::new(),
            previous: HashSet::new(),
            started: None,
            window: window_secs,
            max: max_entries.max(1),
        }
    }

    fn rotate_if_needed(&mut self, now: u64) {
        let start = *self.started.get_or_insert(now);
        if now.saturating_sub(start) > self.window || self.current.len() >= self.max {
            self.previous = std::mem::take(&mut self.current);
            self.started = Some(now);
        }
    }

    /// Record `key`; `false` if it was already seen.
    pub fn insert_new(&mut self, key: [u8; 32], now: u64) -> bool {
        self.rotate_if_needed(now);
        if self.previous.contains(&key) || self.current.contains(&key) {
            return false;
        }
        self.current.insert(key);
        true
    }

    /// Entries currently held.
    pub fn len(&self) -> usize {
        self.current.len() + self.previous.len()
    }

    /// Whether the cache holds nothing.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Limits;

    const T0: u64 = 1_800_000_000;
    const BOX: [u8; 32] = [1; 32];

    fn store() -> MailboxStore {
        MailboxStore::new(&Limits::default())
    }

    #[test]
    fn put_fetch_ack_roundtrip() {
        let mut s = store();
        let id = s.put(BOX, b"ct".to_vec(), T0).unwrap();
        let got = s.fetch(&BOX, 10, T0);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, id);
        assert_eq!(got[0].blob, b"ct");
        assert_eq!(s.ack(&BOX, &[id]), 1);
        assert!(s.fetch(&BOX, 10, T0).is_empty());
        assert_eq!(s.ram_bytes(), 0);
        assert_eq!(s.boxes(), 0);
    }

    #[test]
    fn fetch_respects_max_and_order() {
        let mut s = store();
        let ids: Vec<_> = (0..5u8)
            .map(|i| s.put(BOX, vec![i], T0 + i as u64).unwrap())
            .collect();
        let got = s.fetch(&BOX, 3, T0 + 10);
        assert_eq!(
            got.iter().map(|b| b.id).collect::<Vec<_>>(),
            ids[..3].to_vec()
        );
        assert_eq!(s.pending(&BOX, T0 + 10), 5);
    }

    #[test]
    fn blob_expires_after_ttl() {
        let mut s = store();
        let ttl = Limits::default().blob_ttl_secs;
        s.put(BOX, b"x".to_vec(), T0).unwrap();
        assert_eq!(s.fetch(&BOX, 10, T0 + ttl - 1).len(), 1);
        assert!(s.fetch(&BOX, 10, T0 + ttl).is_empty());
        assert_eq!(s.sweep(T0 + ttl), 1);
        assert_eq!(s.boxes(), 0);
        assert_eq!(s.ram_bytes(), 0);
    }

    #[test]
    fn quota_rejects_without_eviction() {
        let limits = Limits {
            mailbox_max_blobs: 2,
            ..Limits::default()
        };
        let mut s = MailboxStore::new(&limits);
        s.put(BOX, b"a".to_vec(), T0).unwrap();
        s.put(BOX, b"b".to_vec(), T0).unwrap();
        assert_eq!(s.put(BOX, b"c".to_vec(), T0), Err(Rejected::MailboxFull));
        let blobs: Vec<_> = s.fetch(&BOX, 10, T0).into_iter().map(|b| b.blob).collect();
        assert_eq!(blobs, vec![b"a".to_vec(), b"b".to_vec()]);
        // Another mailbox is unaffected.
        assert!(s.put([2; 32], b"c".to_vec(), T0).is_ok());
    }

    #[test]
    fn byte_quota() {
        let limits = Limits {
            mailbox_max_bytes: 100,
            ..Limits::default()
        };
        let mut s = MailboxStore::new(&limits);
        assert_eq!(s.put(BOX, vec![0; 37], T0), Err(Rejected::MailboxFull));
        assert!(s.put(BOX, vec![0; 36], T0).is_ok());
    }

    #[test]
    fn global_cap_rejects() {
        let limits = Limits {
            global_ram_bytes: 200,
            ..Limits::default()
        };
        let mut s = MailboxStore::new(&limits);
        assert!(s.put([1; 32], vec![0; 50], T0).is_ok());
        assert_eq!(s.put([2; 32], vec![0; 100], T0), Err(Rejected::NodeFull));
        assert_eq!(s.ram_bytes(), 50 + BLOB_OVERHEAD);
    }

    #[test]
    fn ack_unknown_ids_is_noop() {
        let mut s = store();
        s.put(BOX, b"a".to_vec(), T0).unwrap();
        assert_eq!(s.ack(&BOX, &[[9; 16]]), 0);
        assert_eq!(s.ack(&[7; 32], &[[9; 16]]), 0);
        assert_eq!(s.fetch(&BOX, 10, T0).len(), 1);
    }

    #[test]
    fn blob_ids_are_unique() {
        let mut s = store();
        let a = s.put(BOX, b"a".to_vec(), T0).unwrap();
        let b = s.put(BOX, b"a".to_vec(), T0).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn seen_cache_detects_duplicates() {
        let mut c = SeenCache::new(60, 1000);
        assert!(c.insert_new([1; 32], T0));
        assert!(!c.insert_new([1; 32], T0 + 1));
        assert!(c.insert_new([2; 32], T0 + 1));
    }

    #[test]
    fn seen_cache_forgets_after_two_windows() {
        let mut c = SeenCache::new(60, 1000);
        assert!(c.insert_new([1; 32], T0));
        assert!(!c.insert_new([1; 32], T0 + 61)); // still in the previous generation
        assert!(c.insert_new([1; 32], T0 + 200));
    }

    #[test]
    fn seen_cache_bounded() {
        let mut c = SeenCache::new(3600, 10);
        for i in 0..100u8 {
            c.insert_new([i; 32], T0);
        }
        assert!(c.len() <= 20);
    }
}
