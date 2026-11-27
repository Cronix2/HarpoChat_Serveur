# P4 — Lien WSS + Noise, boîte aux lettres en RAM, un saut (M1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A running node that phones reach over WSS + Noise, holding E2EE blobs in RAM mailboxes: two test clients exchange a blob through one node (PUT, then FETCH answered through a SURB, then ACK), and a restart wipes everything (spec §15, M1).

**Architecture:** `harpochat-core` gains a pure Noise XX state machine with identity binding (`noise.rs`, design E4) and a `Deliver` link frame. `harpochat-server` gains: `store` (RAM mailboxes, quotas, TTL, nonce/replay caches), `service` (mailbox semantics over `envelope::Message`), `router` (Sphinx processing, delays, local delivery), `net` (TLS in-RAM self-signed cert, WebSocket, Noise link, per-link rate limit), `server` (accept loop, shared state, sweeper). In M1 every route is the single local node; forwarding to other nodes comes in P5.

**Tech Stack:** `snow` 0.10 (`Noise_XX_25519_ChaChaPoly_BLAKE2s`), `rustls` 0.23 + `tokio-rustls` 0.26 with the **`ring`** provider (no aws-lc: no CMake/NASM on Windows), `rcgen` 0.14 (`ring`), `tokio-tungstenite` 0.30 (`handshake` only), `futures-util`.

**Spec:** `docs/SERVER_SPEC.md` §5, §7, §8, §10, §11; design §5.1–5.6.

## Global Constraints

- Wire: WS **binary** messages only; each is one Noise message. Handshake messages are free-size (≤ 1 KiB); after the handshake every message is exactly `SizeClass::ciphertext_len()` (2 048 or 32 768). Anything else closes the link.
- No per-packet logging, no IP logging, no `mailbox_id` in logs (spec §10). Aggregated counters only.
- Mailbox rejects are **silent** (no response), so a stranger learns nothing (spec §8 "pas d'oracle").
- RAM only. TLS certificate and key are generated in RAM at each start (Noise is the real authentication).
- Times come from one `Clock` (`now_unix_secs()`), injectable in tests.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; branch `feat/p4-link-mailbox`.

## Review Focus

1. **A client that sends a frame of the wrong size, a text WS message, or garbage after the handshake** → link closed, node unaffected (Task 6, `wrong_size_frame_closes_link`).
2. **The same PUT packet replayed** (network duplicate or attacker) → stored once (Task 3 `replayed_put_stored_once` via auth nonce; Task 5 `replayed_packet_dropped` via Sphinx tag).
3. **A mailbox at quota, or the node at its global RAM cap** → PUT rejected silently, nothing evicted (Task 2, `quota_rejects_without_eviction`, `global_cap_rejects`).
4. **A FETCH for more blobs than fit in one reply packet** → several reply packets, one SURB each, `more = true` while blobs remain (Task 3, `fetch_splits_across_surbs`).
5. **Phone disconnects before its reply arrives** → reply dropped, no panic, inbox entry removed (Task 5, `deliver_to_gone_inbox_is_dropped`).

---

### Task 1: Core — Noise XX with identity binding, `Deliver` frame

**Files:** Create `crates/harpochat-core/src/noise.rs`; modify `src/link.rs`, `src/domain.rs`, `src/lib.rs`, core `Cargo.toml` (`snow`).

**Interfaces — Produces:**
- `domain::NOISE_STATIC = "harpochat/v1/noise-static"`; `noise::PATTERN = "Noise_XX_25519_ChaChaPoly_BLAKE2s"`; `noise::MAX_HANDSHAKE_MSG = 1024`.
- `pub struct NodeAuth { id_pub: [u8; 32], sig: [u8; 64] }` (CBOR) — `sig = Ed25519(id, NOISE_STATIC, noise_static_pub)`.
- `pub struct Handshake` with `initiator(local_static: &X25519Secret, identity: Option<&SigningKey>) -> Result<Self>`, `responder(…same…)`, `write_message(&mut self) -> Result<Vec<u8>>`, `read_message(&mut self, msg: &[u8]) -> Result<()>`, `is_finished(&self) -> bool`, `into_transport(self) -> Result<(Transport, Peer)>`. Message 2 carries the responder's `NodeAuth` (if identity), message 3 the initiator's (if identity), otherwise an empty payload.
- `pub struct Peer { pub noise_static: [u8; 32], pub node_id: Option<[u8; 32]> }` — `node_id` is `Some` only if the peer sent a `NodeAuth` whose signature verifies over the peer's **actual** Noise static key; an invalid `NodeAuth` fails the handshake (`BadSignature`).
- `pub struct Transport` with `encrypt(&mut self, frame: &[u8]) -> Result<Vec<u8>>` (input must be a class `plaintext_len`, else `Malformed`) and `decrypt(&mut self, msg: &[u8]) -> Result<Vec<u8>>` (input must be a class `ciphertext_len`; AEAD failure → `BadSignature`).
- `FrameKind::Deliver = 0x08` — body `surb_id[16] || final_payload`, gateway → phone.

- [ ] Tests (`noise.rs`): `anonymous_initiator_authenticates_node` (peer.node_id == node's id on the initiator side, None on the responder side), `node_to_node_mutual_identity`, `forged_node_auth_fails` (responder signs a different static key → initiator `read_message` errs), `transport_roundtrip_both_classes`, `transport_rejects_wrong_sizes`, `tampered_ciphertext_rejected`. Link: `deliver_kind_code` (0x08).
- [ ] RED → implement → GREEN → clippy → commit `feat(core): Noise XX handshake with Ed25519 identity binding; Deliver frame`.

### Task 2: RAM mailbox store and caches

**Files:** Create `crates/harpochat-server/src/store.rs`.

**Interfaces — Produces:**
- `pub struct MailboxStore` — `new(limits: &Limits) -> Self`; `put(&mut self, mailbox_id: [u8; 32], blob: Vec<u8>, now: u64) -> Result<[u8; 16], Rejected>`; `fetch(&self, mailbox_id: &[u8; 32], max: usize, now: u64) -> Vec<StoredBlob>` (oldest first, non-expired); `pending(&self, id) -> usize`; `ack(&mut self, mailbox_id: &[u8; 32], ids: &[[u8; 16]]) -> usize`; `sweep(&mut self, now: u64) -> usize` (removes expired blobs and empty boxes); `ram_bytes(&self) -> u64`; `boxes(&self) -> usize`.
- `pub enum Rejected { MailboxFull, NodeFull }`. Accounting: a blob costs `blob.len() + 64` bytes.
- `pub struct SeenCache` — two-generation `HashSet<[u8; 32]>`: `new(window_secs: u64, max_entries: usize)`, `insert_new(&mut self, key: [u8; 32], now: u64) -> bool` (false if already seen in either generation); rotates when the current generation is older than `window_secs` or holds `max_entries`.

- [ ] Tests: `put_fetch_ack_roundtrip`, `fetch_respects_max_and_order`, `blob_expires_after_ttl` (sweep at `put + ttl` removes it, `fetch` already hides it), `quota_rejects_without_eviction` (`mailbox_max_blobs = 2`: third PUT → `MailboxFull`, first two still there), `byte_quota`, `global_cap_rejects` (`NodeFull`), `ack_unknown_ids_is_noop`, `seen_cache_detects_duplicates`, `seen_cache_forgets_after_two_windows`, `seen_cache_bounded`.
- [ ] RED → GREEN → commit `feat(server): RAM mailbox store with quotas, TTL and seen-caches`.

### Task 3: Mailbox service

**Files:** Create `crates/harpochat-server/src/service.rs`.

**Interfaces:**
- Consumes: `MailboxStore`, `SeenCache`, `harpochat_core::{envelope, mailbox, sphinx}`.
- Produces: `pub struct MailboxService { store, nonces: SeenCache }` with `new(limits)`, `handle(&mut self, msg: Message, now: u64) -> Vec<Reply>`; `pub struct Reply { pub surb: Vec<u8>, pub message: Vec<u8> /* encoded envelope */ }`.
- Semantics: `Put` → `verify_put`, nonce unseen (key = `H(mailbox_id ‖ nonce)`), store; no reply. `Fetch` → `read_bound` + `verify_read`, nonce unseen; pack non-expired blobs into `FetchResponse`s that each fit `sphinx::max_message_len(SizeClass::Small)` (a single blob larger than that is skipped and left for a Large-class fetch in P6), one reply per SURB, `more = true` if blobs remain; at most `max` blobs. `Ack` → verify, ack. `Drop`/`Loop`/others → nothing (`Subscribe` arrives in P6). Any failure → empty `Vec` (silent).

- [ ] Tests: `put_then_fetch_returns_blob`, `fetch_with_wrong_read_key_is_silent`, `put_with_foreign_write_key_is_silent`, `replayed_put_stored_once`, `fetch_splits_across_surbs` (3 blobs of 700 o, 2 SURBs → 2 replies, first `more = true`), `ack_removes`, `expired_read_auth_is_silent`.
- [ ] RED → GREEN → commit `feat(server): mailbox service (PUT/FETCH/ACK, silent rejects)`.

### Task 4: TLS + WebSocket + Noise link

**Files:** Create `crates/harpochat-server/src/net.rs`; workspace deps (`rustls`, `tokio-rustls`, `rcgen`, `tokio-tungstenite`, `futures-util`).

**Interfaces — Produces:**
- `pub fn tls_acceptor() -> Result<TlsAcceptor, NetError>` — fresh self-signed cert (rcgen, CN `harpochat`), TLS 1.3 only, ring provider.
- `pub struct Link { … }` with `pub async fn accept(stream: TcpStream, tls: &TlsAcceptor, keys: &NodeKeys) -> Result<(Link, Peer), NetError>` (TLS → WS → Noise responder with identity; 10 s timeout), `pub async fn recv(&mut self) -> Result<(SizeClass, LinkFrame), NetError>`, `pub async fn send(&mut self, frame: &LinkFrame, class: SizeClass) -> Result<(), NetError>`, `split(self) -> (LinkReader, LinkWriter)` (same `recv`/`send`).
- `pub struct RateLimit` token bucket `new(rate_per_sec: u32, burst: u32)`, `allow(&mut self, now: Instant) -> bool`; defaults 50/s, burst 200.
- Test-only client in `tests/common/client.rs` (Task 6) mirrors this with the initiator side and an accept-any-certificate verifier.

- [ ] Tests (`net.rs`, loopback TCP): `handshake_over_tls_ws` (client gets `node_id`), `frames_roundtrip`, `rate_limit_bucket`.
- [ ] RED → GREEN → commit `feat(server): TLS 1.3 + WebSocket + Noise link`.

### Task 5: Router and inbox registry

**Files:** Create `crates/harpochat-server/src/router.rs`.

**Interfaces — Produces:**
- `pub struct Inboxes` — `register(token: [u8; 32], tx: mpsc::Sender<LinkFrame>)`, `unregister(token)`, `deliver(token, frame) -> bool` (`try_send`; false if gone or full).
- `pub struct Router { sphinx: X25519Secret, own_addr: [u8; 32], replay: SeenCache, inboxes: Arc<Inboxes>, service: Mutex<MailboxService> }` with `pub async fn handle_packet(self: &Arc<Self>, packet: Vec<u8>, now: u64)`:
  - `sphinx::process`; replay tag seen → drop; `Forward` to `own_addr` → spawn after `delay_ms` and recurse; `Forward` elsewhere → drop (P5); `Final` with `LOCAL_DELIVERY` → `open_forward_payload` → `envelope::decode` → `service.handle` → for each reply `use_surb(Small)` → `handle_packet` on the result (first hop is local in M1; non-local → drop); `Final` with another destination → `inboxes.deliver(dest, Deliver(surb_id ‖ payload))`.
- Counters (aggregated, `AtomicU64`): packets_in, packets_dropped, blobs_stored.

- [ ] Tests: `single_hop_put_and_fetch_via_surb` (in-process, no network: build packets with `sphinx`, feed `handle_packet`, receive `Deliver` on an inbox channel, `recover_reply` → blob), `replayed_packet_dropped`, `deliver_to_gone_inbox_is_dropped`, `delay_is_applied` (delay 200 ms → not delivered at 50 ms, delivered by 1 s; tokio paused time).
- [ ] RED → GREEN → commit `feat(server): Sphinx router, delays and inbox delivery`.

### Task 6: Server loop, `run`, end-to-end M1 test

**Files:** Create `crates/harpochat-server/src/server.rs`, `crates/harpochat-server/tests/common/client.rs`, `crates/harpochat-server/tests/m1_single_hop.rs`; modify `cli.rs` (`run` starts the server).

**Interfaces — Produces:**
- `pub async fn serve(node: Node, listener: TcpListener, shutdown: impl Future<Output = ()>) -> Result<(), NetError>` — accept loop; per connection: `Link::accept`, then read loop dispatching `RegisterInbox` (32-byte body; one token per link, replaces previous), `Sphinx` (`router.handle_packet`), `DirectoryReq` (reply `Directory` in `Large`: signed by the node, entries = itself with empty chain if root, else none until P7), others ignored; writer task drains the link's mpsc; on disconnect unregister the inbox. Sweeper every 60 s. Link closed on rate-limit excess or bad frame.
- `run` (CLI) binds `config.listen.addr` and calls `serve` with `ctrl_c` shutdown; logs listen address once at startup (operator's own address, not a client's).

- [ ] Tests (`m1_single_hop.rs`, server on `127.0.0.1:0`, two clients A and B): `two_clients_exchange_a_blob` (A PUTs into box A→B, B FETCHes with a SURB `[node]`→ its inbox, recovers the blob, ACKs, FETCH again → empty `FetchResponse`), `restart_wipes_mailboxes` (new server instance with the same keys → FETCH returns nothing), `client_authenticates_node_identity` (`peer.node_id == node id`), `wrong_size_frame_closes_link`, `directory_request_returns_signed_self` (root: verifies with `verify_directory` against `[node id]`).
- [ ] RED → GREEN → commit `feat(server): accept loop and end-to-end single-hop M1`.

### Task 7: Docs

- [ ] `docs/android/core-integration.md`: section « Connexion à un nœud » — TLS (accepter tout certificat), WS binaire, Noise XX pattern + `NodeAuth` vérifié contre l'`id_pub` attendu, tailles fixes, `RegisterInbox` (nouveau jeton par connexion), `Deliver` (`surb_id ‖ payload`), `DirectoryReq`. `docs/android/spec-deltas.md`: E11 `Deliver` frame, E12 certificat TLS en RAM régénéré à chaque démarrage. `docs/architecture.md` + README: P4 terminé. Commit `docs: P4 link protocol for Android, status`.
