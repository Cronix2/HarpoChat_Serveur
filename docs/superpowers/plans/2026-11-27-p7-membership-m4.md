# P7 — Parrainage, gossip, révocation (M4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new node joins the mesh with a single copy-paste. The sponsor runs `harpochat-server invite-node`; the new machine runs `harpochat-server join <token> --endpoint wss://…`. The node then appears, with its sponsorship chain, in every node's directory within a few seconds. Revoking it (`harpochat-server revoke <id>`) removes it, along with the nodes it sponsored after the revocation (spec §4.3, M4).

**Architecture:**
- **Core.**
  - `invite`: `JoinRequest` also carries the signed invite. The token is then self-verifying: `invite-node` works offline with `node.key` and needs no coordination with the running process.
  - New type `JoinResponse { v, vouch: Option<Signed<Vouch>>, chain, roots }`. A refusal is uniform (`vouch: None`).
  - `directory`: `verify_entries` returns the raw entries that verify (for relaying). It also enforces the sponsorship limit: ≤ 3 vouches per sponsor for any 30-day window of `issued`, applied by every verifier, servers and phones alike.
- **Server.**
  - `membership`: the node's view, with entries indexed by id and verified revocations.
    - `merge` of a received directory.
    - `directory()` signed and capped to a Large frame.
    - Peers added or removed accordingly.
  - Gossip is a periodic pull: each outbound node link sends `DirectoryReq` every 5 s.
  - `Peers` becomes dynamic (`add` / `remove`).
  - `sponsor`: handles a `JoinRequest` received on a non-node link and persists the vouched list.
- **Persistence (config only, no user data):**
  - `[node] chain` (hex of the `Signed<Vouch>` up to the root);
  - `[sponsor] limit` and `[[sponsor.vouched]]` (used invites, vouched nodes);
  - top-level `revocations`.

  Atomic write (temporary file + rename).

**Spec:** §4.1–4.3, §11; design §5.5.

## Global Constraints

- **The token is a secret.** It is never logged. It is printed only by `invite-node`.
- **Uniform refusal.** It reveals nothing about the reason: expired token, already used, limit reached, bad proof, or Noise identity ≠ descriptor.
- **Sponsor checks before vouching.**
  - The invite is signed by itself, `v == 1` and not expired.
  - The invite hash is not burned.
  - The HMAC proof is valid.
  - The descriptor is valid, and its `id_pub` equals the identity proved in Noise.
  - The node has not already been vouched by this sponsor.
  - Fewer than `limit` vouches in the last 30 days, with `limit` ≤ 3 (spec constant, verified by everyone).
  - The sponsor itself is a member (root, or valid chain).
- **The joiner checks the response** before writing anything: `verify_entry(own descriptor, [vouch] + chain, roots received)`. On failure, no file is written.
- **A directory always fits in a Large frame.** Entries are dropped from the end, never our own. Documented limit: about 50 nodes per directory. Pagination is left for later.
- **Revocations stay local.** A node may only publish the revocations it has *received and verified*, plus those it signed. The core rule applies: direct sponsor or root.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; branch `feat/p6-p8`.

## Review Focus

1. **The same token presented twice, including after a restart.** Refused, because the burned list is persisted in the config (`token_is_single_use`, `burned_list_survives_restart`).
2. **A compromised sponsor issuing 10 vouches the same day.** Only the first 3 (in `issued` order, then `node_id`) are accepted by verifiers (`sponsor_limit_enforced_by_verifiers`).
3. **A joiner presenting another node's descriptor.** Refused: the Noise identity does not match (`join_requires_noise_identity`).
4. **A node revoked by its sponsor.** It disappears from every directory, its links stop being "node" links, and its post-revocation vouches are void (`revoked_node_disappears`).
5. **An oversized directory (> 32 KiB).** Capped, our own entry kept (`directory_fits_a_large_frame`).

---

### Task 1: Core

- [ ] `JoinRequest { invite: Signed<NodeInvite>, descriptor, proof }`
- [ ] `decode_signed_token(text, now) -> Result<Signed<NodeInvite>>` (`decode_token` relies on it)
- [ ] `JoinResponse` + `refusal()`
- [ ] `directory::{SPONSOR_LIMIT = 3, SPONSOR_PERIOD_SECS = 30 d}`
- [ ] `verify_entries(entries, revocations, roots, now) -> Vec<(DirectoryEntry, VerifiedNode)>`, with the limit applied; `verify_directory` relies on it.
- [ ] Tests:
  - `sponsor_limit_enforced_by_verifiers`
  - `limit_window_slides`
  - `rejected_vouch_voids_descendants`
  - `join_response_roundtrip`
  - `signed_token_roundtrip`
- [ ] Commit `feat(core): self-verifying join request, join response, sponsorship limit`.

### Task 2: Config and persistence

- [ ] `NodeSection.chain: Vec<String>`, `Sponsor { limit: u8 (1..=3), vouched: Vec<Vouched { node_id, invite, issued }> }`, `Config.revocations: Vec<String>`, all validated (hex, CBOR, signature).
- [ ] `Config::save(dir)` atomic.
- [ ] `Node { dir: Option<PathBuf> }`, plus:
  - `own_entry(now) -> DirectoryEntry`;
  - `chain()`;
  - `revocations()`;
  - `is_member(now)`.
- [ ] Tests:
  - `chain_and_revocations_validated`
  - `save_is_atomic_and_roundtrips`
  - `non_root_member_needs_chain_to_roots`

### Task 3: Membership, gossip, dynamic peers

- [ ] `membership.rs`:
  - `Membership::new(node)`;
  - `merge(&Signed<Directory>, now) -> Changes { added, removed }`;
  - `insert(entry, now)`;
  - `revoke(Signed<Revoke>, now)`;
  - `nodes(now) -> Vec<VerifiedNode>`;
  - `directory(node, now) -> Signed<Directory>` (fit to Large).
- [ ] `Peers`:
  - `RwLock` map;
  - `add(id, host_port)` (no duplicate, never self);
  - `remove(id)` (aborts the dialler);
  - the dialler forwards `Directory` frames to a gossip channel and resends `DirectoryReq` every `GOSSIP_EVERY = 5 s`.
- [ ] Server:
  - a gossip task merges the directories and applies the `Changes` to the peers;
  - `DirectoryReq` is answered by `membership.directory`;
  - node cover takes its candidates from `membership.nodes`.
- [ ] Initial peers = `[[peers]]` ∪ `[[roots]]`.
- [ ] Tests:
  - `merge_keeps_valid_newest`
  - `merge_drops_revoked`
  - `directory_fits_a_large_frame`
  - `peers_add_remove`

### Task 4: Join and CLI

- [ ] `sponsor.rs`:
  - `create_invite(node, now, ttl) -> Signed<NodeInvite>`;
  - `Sponsor::handle_join(node, membership, req, noise_id, now) -> (JoinResponse, Option<DirectoryEntry>)`;
  - persistence of `vouched`.
- [ ] Server: `FrameKind::JoinRequest` on a non-node link → `JoinResponse`, then insertion into membership and peers.
- [ ] `cli`:
  - `invite-node [--hours N]`;
  - `join <token> [--endpoint …]` — async core `join_mesh(dir, token, endpoints, now)`;
  - `revoke <id>` — adds to `revocations`, asks for a restart.
- [ ] Tests (`sponsor.rs`):
  - `token_is_single_use`
  - `expired_or_foreign_invite_refused`
  - `bad_proof_refused`
  - `join_requires_noise_identity`
  - `local_limit_refused`
  - `burned_list_survives_restart`
- [ ] Commit `feat(server): membership by sponsorship — gossip, join, revoke (M4)`.

### Task 5: Integration test M4 and docs

- [ ] `tests/m4_membership.rs`:
  - `node_joins_with_one_paste`: root R, then J joins via R; a phone asking R, then J, sees 2 nodes.
  - `chain_of_two_joins`: K joins via J; R's directory lists K with a 2-link chain.
  - `revoked_node_disappears`
  - `phone_routes_through_joined_nodes` (PUT/FETCH through a mesh R+J+K)
- [ ] `tests/cli.rs`:
  - `invite_node_prints_token`
  - `join_with_bad_token_fails_cleanly` (exit 2, no file)
  - `revoke_writes_config`
- [ ] Docs:
  - operators: join, invite and revoke flow; replaces manual `[[roots]]` / `[[peers]]`;
  - android: nothing to change (directories now carry chains);
  - `spec-deltas` E19–E22.
- [ ] Commit `test+docs: M4 membership`.
