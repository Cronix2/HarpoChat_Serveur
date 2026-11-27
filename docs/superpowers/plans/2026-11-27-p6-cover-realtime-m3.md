# P6 — Trafic de couverture et temps réel (M3 + M3b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** (M3) A node's links emit frames at instants that do not depend on whether real traffic flows. Nodes emit their own Sphinx loops and drops, and they measure losses per neighbour with their loops. (M3b) A phone deposits SURBs with `SUBSCRIBE`; on each accepted `PUT` the mailbox pushes the blob (`PUSH`), or a `NOTIFY` when the blob does not fit, through one SURB. A pushed message arrives in < 2 s on a 5-node mesh.

**Architecture:**
- `harpochat-server::cover` (new):
  - `shape()` is a Poisson-slot link writer. At each slot drawn from Exp(λ) it sends the next queued real frame, or a `Padding` frame if none is queued. The slot instants come only from the RNG, so the frames emitted on an idle link and on a loaded link are the same in number and time, as long as the load stays below λ.
  - A `LoopTracker` keeps the loops sent and returned, and the losses per node.
  - The node cover task emits loops and drops as Poisson events.
- `harpochat-core::path`: `loop_route` / `drop_route` for routes chosen by a node.
- `service`: subscriptions in RAM, plus `PUSH`/`NOTIFY` on `PUT`.
- `link`: new frame `CoverRate` (0x09), phone → gateway, which sets the phone's downlink rate. The client decides the battery/anonymity trade-off (spec §6.3).

**Spec:** §5 (trafic de couverture sur chaque lien), §6.3, §7.5, §11 (pertes via loops), §13 (λ, stock de SURB ~10); design §5.4.

## Global Constraints

- **No FIFO without delay; no slot that depends on content.** In `shape()`, the slot instants are drawn independently of the queue. Exception: a backlog ≥ `burst` is drained without waiting, to bound latency under overload. This is documented: past λ, a link reveals that it is overloaded.
- **Padding size.** Padding is always Small. A real Large frame stays distinguishable by its size class (spec §13: two classes, assumed).
- **Real frames get no priority over padding inside a slot.** One frame per slot, whatever it is.
- **Node cover uses only the node's own view:** its descriptor plus those of its peers. Loops never reveal anything about users.
- **Losses stay local.** They are noted locally and published nowhere (spec §11). A *suspect* peer is avoided in the node's own drops and still crossed by loops, so it can be re-measured.
- **Subscriptions in RAM.**
  - ≤ 32 SURBs per mailbox and ≤ 100 000 in total. Overflow → silent reject of the new SURBs.
  - `until` is clamped to `now + 86 400`; `until <= now` → unsubscribe.
  - Expired entries are removed by the sweeper.
- **Failures stay silent** (no answer to SUBSCRIBE, as before).
- **Push is best-effort.** The blob stays stored until the ACK.
- **No logs per packet.** Counters only.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; branch `feat/p6-p8` (single PR for P6–P8).

## Review Focus

1. **Same RNG seed, one link idle and one carrying 0.5·λ of real traffic** → identical emission instants (`shaped_instants_do_not_depend_on_traffic`).
2. **SUBSCRIBE replayed, expired, signed by the wrong key, or past 32 SURBs** → no effect (`subscribe_rejections_are_silent`).
3. **Blob that does not fit a Small reply** → `NOTIFY{pending}` instead of `PUSH` (`large_blob_notifies`).
4. **Dead peer** → its loops are lost, it becomes suspect, and the others stay healthy (`dead_peer_becomes_suspect`).
5. **`CoverRate` outside `[min, max]`, or malformed** → clamped, or link closed (`cover_rate_clamped`).

---

### Task 1: Core — `CoverRate` frame, cover routes

**Files:** `crates/harpochat-core/src/link.rs`, `src/path.rs`.

- `FrameKind::CoverRate = 0x09`. Body: `u32` big-endian, in mHz (millihertz). Helpers:
  - `pub fn cover_rate_body(mhz: u32) -> Vec<u8>`
  - `pub fn parse_cover_rate(body: &[u8]) -> Result<u32>` (exactly 4 bytes)
- `pub fn loop_route(nodes, own: &[u8;32], pick, uniform, mean_ms) -> Result<Route>`. Hops: `mix… → other → own`.
  - `mix_count` mixes, excluding `own`.
  - Then one more node, distinct from them.
  - Mixes and the "other" node delay; `own` does not. In a 2-node mesh: `[other, own]`.
  - `Malformed` if there is no other node.
- `pub fn drop_route(…same…) -> Result<Route>`: `mix… → mailbox` (role `Mailbox`), excluding `own`.
- [ ] Tests:
  - `cover_rate_roundtrip`
  - `loop_route_returns_home_without_repeats` (200 draws over 5 nodes)
  - `loop_route_small_mesh`
  - `drop_route_never_targets_self`
- [ ] Commit `feat(core): CoverRate frame and node cover routes`.

### Task 2: Server — link shaping

**Files:** create `crates/harpochat-server/src/cover.rs`; modify `config.rs`, `peers.rs`, `server.rs`.

- `[cover]` in `Config`:

  | Key | Default |
  |---|---|
  | `node_link_rate` | 10.0 |
  | `phone_link_rate` | 1.0 |
  | `phone_link_rate_min` | 0.05 |
  | `phone_link_rate_max` | 10.0 |
  | `loop_rate` | 0.2 |
  | `drop_rate` | 0.2 |
  | `mean_delay_ms` | 100 |

  Validation: rates finite and in `[0, 1000]`; `min ≤ phone_link_rate ≤ max`. A rate of 0 means no shaping and no cover (dev only, documented). `Config` loses `Eq` (f64).
- `pub struct Rate(AtomicU32 /* mHz */)`.
- `pub async fn shape<S, Fut>(rx: mpsc::Receiver<LinkFrame>, rate: Arc<Rate>, burst: usize, rng: impl FnMut() -> f64, sleep: impl FnMut(Duration) -> Fut, send: S)`
  - Loop: `wait = exp(rate)` → sleep → `try_recv()`, which yields a real frame, `Padding`, or ends when the queue is closed and empty.
  - Afterwards, while `rx.len() >= burst`, send without waiting.
  - Rate 0 → `rx.recv().await` with direct sends.
- Peers: the dialler pump goes through `shape` at `node_link_rate` (burst 256).
- Phone links: the writer goes through `shape` at `phone_link_rate` (burst 16). A `CoverRate` frame received from a phone sets the rate, clamped to `[min, max]`. On a node link the frame is ignored.
- Counters: `padding_sent`.
- [ ] Tests:
  - `shaped_instants_do_not_depend_on_traffic` (mocked sleep/send clock, same seed, idle vs. load 0.5·λ: identical instant sequences; every real frame delivered)
  - `shape_mean_rate` (10 000 slots, mean within 5 %)
  - `backlog_bursts`
  - `zero_rate_passthrough`
  - `cover_config_validated`
  - `cover_rate_clamped` (server test: a phone requests 1 000 Hz → max)

### Task 3: Server — node loops, drops, loss measurement

**Files:** `cover.rs`, `router.rs`, `server.rs`.

- `LoopTracker`:
  - `start(token, hops: Vec<[u8;32]>, deadline: Instant)`.
  - `complete(&token) -> bool`.
  - `expire(now)`: each node of an expired loop gets +1 lost; each node of a returned loop gets +1 ok.
  - `suspects(min_samples=10, max_loss=0.5) -> Vec<[u8;32]>`, with stats decayed ×0.5 every 10 minutes.
- Router: `Final{destination}` with `destination ≠ LOCAL_DELIVERY` → first `loops.complete`, else the inbox.
- Cover task (spawned in `Server::run`):
  - Poisson events at `loop_rate + drop_rate`.
  - Candidates: own descriptor plus the peers' descriptors.
  - A loop is `build_forward(Loop, route.hops, token, delays)`, sent to `hops[0]` via `router.forward`. Deadline = Σ delays + 10 s.
  - A drop is `build_forward(Drop, …, LOCAL_DELIVERY)` to a mailbox that is not suspect.
  - Counters: `loops_sent`, `loops_returned`, `loops_lost`, `drops_sent`.
- [ ] Tests:
  - `tracker_counts_and_suspects`
  - `loop_returns_through_router` (unit: 1 router + loopback forward)
- [ ] Commit `feat(server): link shaping, node loops and drops, loss measurement`.

### Task 4: Server — SUBSCRIBE / PUSH / NOTIFY

**Files:** `service.rs`, `server.rs` (the sweeper calls `service.sweep`).

- `Subscriptions { by_box: HashMap<[u8;32], VecDeque<(Vec<u8> /*surb*/, u64 /*until*/)>>, total }`.
- `handle(Subscribe)`:
  - Verify `read_auth` (`ReadOp::Subscribe`, bound = `read_bound`) and the nonce.
  - `until <= now` → remove the subscription.
  - Otherwise clamp `until` and append the SURBs within the caps.
- `handle(Put)`:
  - If the PUT is stored and a valid SURB exists, pop it.
  - If `encode(Push{mailbox_id, blobs:[{id, blob}]})` ≤ `max_message_len(Small)`, the reply is that PUSH; otherwise it is `Notify{mailbox_id, pending}`.
- `sweep(now)` = store sweep + expired SURBs.
- [ ] Tests:
  - `subscribe_then_put_pushes`
  - `push_consumes_one_surb_each`
  - `large_blob_notifies`
  - `subscribe_rejections_are_silent` (wrong key, replay, expired, > 32)
  - `unsubscribe_with_past_until`
  - `expired_surbs_swept`
- [ ] Commit `feat(server): SURB subscriptions with PUSH and NOTIFY`.

### Task 5: Integration test M3/M3b

**Files:**
- Move `start_mesh` / `directory` into `tests/common/mesh.rs` (configurable `Cover`).
- The test client skips `Padding` (`recv_real`).
- Create `tests/m3_cover_realtime.rs`.

- [ ] Tests:
  - `push_arrives_under_two_seconds`: 5 nodes, cover on at test rates (node links 50 Hz, phones 20 Hz). B subscribes to the replicas outside both gateways; A PUTs; B receives the PUSH in < 2 s (measured).
  - `idle_phone_link_carries_padding`: frames received over 2 s ≈ λ·T ± 40 %.
  - `loops_return_in_healthy_mesh`: after 5 s, `loops_returned > 0` on every node and no node is suspect.
  - `dead_peer_becomes_suspect`: one node stopped; the others see it in `suspects()` after the deadline.
- [ ] Re-run m1, m2 and FFI with cover active (helpers skip padding).
- [ ] Commit `test(server): M3 cover traffic and M3b real-time push`.

### Task 6: FFI and docs

- [ ] FFI:
  - `FfiFrameKind::CoverRate`
  - `cover_rate_body(hz: f64) -> Vec<u8>`
  - `phone_flow.rs` subscribes and receives a PUSH.
- [ ] `docs/android/core-integration.md` §8 "Temps réel et couverture":
  - ignore `Padding`;
  - choose the downlink rate (open app vs. background);
  - SUBSCRIBE stock (3 SURBs per Small SUBSCRIBE, ≤ 32 per mailbox, replenish after each PUSH);
  - dedup the pushes from the replicas;
  - uplink cover on the client side (Poisson λ, drops/loops).
- [ ] `spec-deltas.md`:
  - E15: CoverRate frame and downlink shaping.
  - E16: subscription caps and `until` ≤ 24 h, NOTIFY when the blob does not fit.
  - E17: node loops target a 32-byte token instead of LOCAL_DELIVERY.
- [ ] Operators: `[cover]`, bandwidth cost (≈ λ × 2 KiB/s per link). Architecture + README.
- [ ] Commit `feat(ffi): CoverRate; docs: P6 cover and real-time`.
