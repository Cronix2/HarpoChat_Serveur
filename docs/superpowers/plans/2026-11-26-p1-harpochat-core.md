# P1 — `harpochat-core` v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the legacy JSON relay with a pure-Rust protocol core (`harpochat-core`) holding every wire format shared by the server and the Android app, with frozen test vectors, ready to tag `core-v0.1.0`.

**Architecture:** A single library crate with no I/O, no async, no implicit clock (time is always a parameter) and no `unsafe`. Each module owns one format: CBOR helpers, signed objects, envelopes (§8), link frames, descriptors/vouches/directory, node invites, bootstrap, mailbox derivation/auth, and a Sphinx façade over `sphinx-packet`. Randomness enters only through explicit parameters or `getrandom`, so every format can be pinned by deterministic test vectors.

**Tech Stack:** Rust stable (pinned), `ciborium` + `serde` + `serde_bytes`, `ed25519-dalek` 3, `x25519-dalek` 3, `sphinx-packet` 0.8, `blake2` 0.11, `hkdf` 0.13 + `sha2` 0.11, `hmac` 0.13, `data-encoding`, `zeroize`, `getrandom`, `thiserror`; dev: `serde_json`, `hex`, `proptest`.

**Spec:** [`docs/SERVER_SPEC.md`](../../SERVER_SPEC.md) v0.2 (contract) and [`docs/superpowers/specs/2026-11-26-harpochat-core-design.md`](../specs/2026-11-26-harpochat-core-design.md) (design). Read both before starting.

## Global Constraints

- `harpochat-core` has **no** dependency on `tokio`, any network/file API, or `std::time::SystemTime::now()`. Time is passed as `now_unix_secs: u64`.
- `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]` at the crate root.
- Every secret key type derives/implements `Zeroize` + `ZeroizeOnDrop`; no secret is printed by `Debug` (redact).
- Every signature is Ed25519 over `len(domain) as u8 || domain || message`, with the domain constants of Task 2. No domain is reused across purposes.
- `H(x)` = BLAKE2b-256. Mailbox epoch = `floor(unix_secs / 86_400)`, encoded `u32` big-endian. TTL = 7 days → clients poll 7 epochs (spec §7.3).
- Size classes (design §5.9): Noise ciphertext 2 048 o (`Small`) and 32 768 o (`Large`); Noise tag 16 o.
- Decoders never panic on any input and return one opaque `CoreError` variant per category (no oracle detail on the wire).
- Unknown envelope `type`, unknown `v`, unknown CBOR fields, or trailing bytes → reject.
- Commits: conventional style, ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Work on branch `feat/p1-core`.
- Docs are in French; code, identifiers and comments in English.

## Review Focus

1. **Operator pastes a node token with line breaks, spaces, lowercase or Crockford look-alikes (`O`/`I`/`L`)** → it must decode identically (Task 8, `token_tolerates_copy_paste_noise`).
2. **A message PUT at 23:59:59 UTC, fetched after midnight, or up to 7 days later** → `epochs_to_poll(now)` must include the writer's epoch (Task 4, `epoch_boundary_is_covered`).
3. **Hostile bytes into any decoder (truncated, oversized, random)** → error, never panic, never allocate beyond the input bound (Tasks 3, 5, 9, `decoders_never_panic`).
4. **A vouch chain that loops, is absurdly deep, or passes through a revoked sponsor** → rejected without hang (Task 7, `chain_cycle_rejected`, `chain_depth_capped`, `vouch_after_revocation_rejected`).
5. **A blob exactly at the maximum envelope size and one byte over** → first fits a `Small` Sphinx packet, second fails cleanly (Task 10, `put_at_max_blob_fits_small_class`).

---

### Task 0: Toolchain and workspace reset

**Files:**
- Delete: `crates/harpo-proto/`, `crates/harpo-crypto/`, `crates/harpo-server/`, `Dockerfile`, `.dockerignore`
- Modify: `Cargo.toml` (workspace), `README.md`, `.gitignore`
- Create: `rust-toolchain.toml`, `crates/harpochat-core/Cargo.toml`, `crates/harpochat-core/src/lib.rs`

**Interfaces:**
- Produces: crate `harpochat_core` that compiles and has an empty test suite passing.

- [ ] **Step 1: Install Rust** — `winget install Rustlang.Rustup` (or rustup-init), then `rustup default stable`; record `rustc --version` output.
- [ ] **Step 2: Delete the legacy crates and Docker files** listed above (they violate P1/P2/§10; Docker returns in P3).
- [ ] **Step 3: Write `rust-toolchain.toml`** pinning `channel = "<exact version from Step 1>"`, `components = ["rustfmt", "clippy"]`.
- [ ] **Step 4: Rewrite workspace `Cargo.toml`** — `members = ["crates/harpochat-core"]`, `[workspace.package]` with `rust-version` = pinned version, `license = "MIT"`, `repository = "https://github.com/Cronix2/HarpoChat_Serveur"`; `[workspace.dependencies]` with the Tech Stack crates; `[profile.release] panic = "abort"`, `debug = false`, `strip = true`, `lto = true`, `codegen-units = 1`.
- [ ] **Step 5: Create `crates/harpochat-core`** with `lib.rs` holding the two crate attributes from Global Constraints and a crate doc comment pointing at `docs/SERVER_SPEC.md`.
- [ ] **Step 6: Verify** — `cargo build -p harpochat-core && cargo test -p harpochat-core` → success, 0 tests. `cargo tree -d -p harpochat-core` → note any duplicate `x25519-dalek`/`curve25519-dalek`; there must be none (if `ed25519-dalek` 3 and `sphinx-packet` disagree on `curve25519-dalek`, pin compatible versions before continuing).
- [ ] **Step 7: Update `README.md`** — short French description of the new architecture (link to spec + design), build/test commands, status "P1 en cours". Remove the old endpoint/handshake sections.
- [ ] **Step 8: Commit** — `chore: reset workspace around harpochat-core`.

### Task 1: CI

**Files:**
- Create: `.github/workflows/ci.yml`, `deny.toml`

- [ ] **Step 1: Write `ci.yml`** — on `push` and `pull_request`: jobs on `ubuntu-latest` and `windows-latest` running `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`; a separate Linux job running `cargo deny check` (via `EmbarkStudios/cargo-deny-action`).
- [ ] **Step 2: Write `deny.toml`** — allowed licenses: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib, CC0-1.0; `advisories` deny on vulnerability; `bans` warn on multiple versions.
- [ ] **Step 3: Verify locally** — `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings` pass; `cargo install cargo-deny --locked && cargo deny check` passes.
- [ ] **Step 4: Commit** — `ci: fmt, clippy, tests on Linux/Windows, cargo-deny`.

### Task 2: Errors, domains and key primitives

**Files:**
- Create: `crates/harpochat-core/src/error.rs`, `src/domain.rs`, `src/keys.rs`, `src/hash.rs`
- Test: inline `#[cfg(test)]` modules

**Interfaces:**
- Produces:
  - `pub enum CoreError { Malformed, TooLarge, UnsupportedVersion, BadSignature, Expired, NotYetValid, Unauthorized, Untrusted, Sphinx }` (`thiserror`, messages generic).
  - `pub type Result<T> = core::result::Result<T, CoreError>;`
  - `domain.rs`: `pub const DESCRIPTOR, VOUCH, REVOKE, DIRECTORY, NODE_INVITE, PUT, READ: &str` = `"harpochat/v1/descriptor"`, `"harpochat/v1/vouch"`, `"harpochat/v1/revoke"`, `"harpochat/v1/directory"`, `"harpochat/v1/node-invite"`, `"harpochat/v1/put"`, `"harpochat/v1/read"`; KDF labels `MBX_KEYS = "harpo-mbx-keys"`, `MBX_ID = "harpo-mbx-id"`, `NODE_ADDR = "harpo-node-addr"`.
  - `keys.rs`: `pub struct SigningKey` (wraps `ed25519_dalek::SigningKey`, zeroized, redacted Debug) with `from_seed(&[u8; 32]) -> Self`, `generate() -> Self` (getrandom), `public(&self) -> [u8; 32]`, `seed(&self) -> Zeroizing<[u8; 32]>`, `sign(&self, domain: &str, msg: &[u8]) -> [u8; 64]`; free fn `verify(public: &[u8; 32], domain: &str, msg: &[u8], sig: &[u8; 64]) -> Result<()>` (uses `verify_strict`). `pub struct X25519Secret` similarly with `from_bytes`, `generate`, `public() -> [u8; 32]`.
  - `hash.rs`: `pub fn h(parts: &[&[u8]]) -> [u8; 32]` (BLAKE2b-256 over concatenation), `pub fn h_domain(label: &str, parts: &[&[u8]]) -> [u8; 32]` (prefixes `len(label) as u8 || label`).
  - `pub fn random_bytes<const N: usize>() -> [u8; N]` in `keys.rs`.

- [ ] **Step 1: Write failing tests** — `sign_verify_roundtrip`; `verify_rejects_other_domain` (sign with `VOUCH`, verify with `REVOKE` → `Err(BadSignature)`); `verify_rejects_flipped_bit`; `debug_redacts_secret` (`format!("{:?}", key)` does not contain the hex of the seed); `h_domain_differs_by_label` (`h_domain("a", &[b"bc"]) != h_domain("ab", &[b"c"])`).
- [ ] **Step 2: Run** `cargo test -p harpochat-core` → FAIL (items not defined).
- [ ] **Step 3: Implement** the items above; `lib.rs` declares the modules and re-exports `CoreError`, `Result`.
- [ ] **Step 4: Run** tests → PASS; clippy clean.
- [ ] **Step 5: Commit** — `feat(core): error type, signature domains, key and hash primitives`.

### Task 3: Strict CBOR and signed objects

**Files:**
- Create: `src/cbor.rs`, `src/signed.rs`

**Interfaces:**
- Consumes: Task 2.
- Produces:
  - `pub fn to_vec<T: Serialize>(v: &T) -> Vec<u8>` (panics never: serialization of our types is infallible; return `Vec`).
  - `pub fn from_slice<T: DeserializeOwned>(bytes: &[u8], max_len: usize) -> Result<T>` — `TooLarge` if `bytes.len() > max_len`, `Malformed` on any decode error or trailing bytes.
  - `pub trait SignedPayload: Serialize + DeserializeOwned { const DOMAIN: &'static str; fn signer(&self) -> [u8; 32]; }`
  - `pub struct Signed<T> { pub body: Vec<u8>, pub sig: [u8; 64], _t: PhantomData<T> }` serialized as CBOR map `{ "body": bstr, "sig": bstr(64) }`, with `Signed::<T>::sign(key: &SigningKey, value: &T) -> Self`, `verify(&self) -> Result<T>` (decode body, check `signer()` signature over the **exact body bytes**), `peek(&self) -> Result<T>` (decode without verifying, for diagnostics only).
- Struct conventions for all later tasks: `#[serde(deny_unknown_fields)]`, short field names exactly as in the spec, fixed byte arrays via `serde_bytes::ByteArray<N>` (or a local `#[serde(with)]` helper) so they encode as CBOR byte strings, never integer arrays.

- [ ] **Step 1: Write failing tests** — `trailing_bytes_rejected`; `oversize_rejected` (`from_slice::<u8>(&[0; 10], 5)` → `TooLarge`); `byte_array_encodes_as_bstr` (CBOR of a struct with a `[u8; 32]` field contains major type 2 header `0x58 0x20`); `signed_roundtrip`; `signed_rejects_tampered_body`; `decoders_never_panic` (proptest: arbitrary `Vec<u8>` up to 4 KiB into `from_slice::<Signed<TestPayload>>` returns `Err` or `Ok`, never panics).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** `cbor.rs` and `signed.rs` (the body bytes are what is signed, so no canonicalisation is needed on verify — note this in the module doc as design deviation E6).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(core): strict CBOR helpers and Signed<T> wrapper`.

### Task 4: Mailbox derivation and access control (design §5.4)

**Files:**
- Create: `src/mailbox.rs`

**Interfaces:**
- Consumes: Task 2 (`SigningKey`, `verify`, `h_domain`, domains).
- Produces:
  - `pub const EPOCH_SECS: u64 = 86_400; pub const TTL_EPOCHS: u32 = 7; pub const READ_SKEW_SECS: u64 = 600;`
  - `pub fn epoch_of(now_unix_secs: u64) -> u32`; `pub fn epochs_to_poll(now_unix_secs: u64) -> Vec<u32>` (current and the 6 previous, newest first — 7 total).
  - `pub struct MailboxKeys { pub epoch: u32, pub write: SigningKey, pub read: SigningKey }` with `pub fn derive(pair_secret: &[u8; 32], epoch: u32) -> Self` — HKDF-SHA256(ikm = pair_secret, salt = none, info = `MBX_KEYS || epoch_be`) → 64 bytes: `write seed || read seed`; `pub fn mailbox_id(&self) -> [u8; 32]`.
  - `pub fn mailbox_id(write_pub: &[u8; 32], read_pub: &[u8; 32]) -> [u8; 32]` = `h_domain(MBX_ID, &[write_pub, read_pub])`.
  - `pub struct WriteAuth { write_pub: [u8; 32], read_pub: [u8; 32], nonce: [u8; 16], sig: [u8; 64] }` (serde, fields `pub`); `pub fn sign_put(keys: &MailboxKeys, blob: &[u8], nonce: [u8; 16]) -> WriteAuth` — signs `mailbox_id || nonce || H(blob)` under `PUT`; `pub fn verify_put(mailbox_id: &[u8; 32], blob: &[u8], auth: &WriteAuth) -> Result<()>` — recomputes `mailbox_id` from the two public keys (`Unauthorized` if different), then checks the signature with `write_pub`.
  - `#[repr(u8)] pub enum ReadOp { Fetch = 0x02, Ack = 0x03, Subscribe = 0x06 }`.
  - `pub struct ReadAuth { write_pub, read_pub, ts: u64, nonce: [u8; 16], sig: [u8; 64] }`; `pub fn sign_read(keys: &MailboxKeys, op: ReadOp, bound: &[u8], ts: u64, nonce: [u8; 16]) -> ReadAuth` — signs `op || mailbox_id || ts_be || nonce || H(bound)` under `READ`; `pub fn verify_read(mailbox_id: &[u8; 32], op: ReadOp, bound: &[u8], auth: &ReadAuth, now_unix_secs: u64) -> Result<()>` — `Expired`/`NotYetValid` if `|now - ts| > READ_SKEW_SECS`. Nonce replay caching is the server's job (doc comment).
  - `bound` data per op (documented on `ReadOp`): FETCH = `max_be16 || concat(surbs)`, ACK = `concat(blob_ids)`, SUBSCRIBE = `until_be64 || concat(surbs)` (computed from a `Message` by `envelope::read_bound`, Task 5).

- [ ] **Step 1: Write failing tests** — `derive_is_deterministic`; `epochs_rotate_ids` (epoch e and e+1 give different `mailbox_id`); `epoch_boundary_is_covered` (write at `86_400 * 20_000 - 1`, poll at `86_400 * 20_006 + 5` → writer epoch ∈ `epochs_to_poll`; poll at `86_400 * 20_007` → not included); `put_auth_roundtrip`; `put_auth_rejects_other_blob`; `put_auth_rejects_foreign_mailbox` (valid auth for box A presented for box B → `Unauthorized`); `read_auth_rejects_writer_key` (signed with the write key → `BadSignature`); `read_auth_skew` (ts = now − 601 → `Expired`, now + 601 → `NotYetValid`); `read_auth_bound_to_op` (FETCH auth presented as ACK → `BadSignature`).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(core): mailbox id derivation and stateless PUT/read authorisation`.

### Task 5: Envelopes (spec §8)

**Files:**
- Create: `src/envelope.rs`

**Interfaces:**
- Consumes: Tasks 2–3; `WriteAuth`, `ReadAuth`, `ReadOp` from Task 4.
- Produces:
  - `pub struct StoredBlob { pub id: [u8; 16], pub blob: Vec<u8> }`
  - `pub enum Message { Put { mailbox_id: [u8; 32], write_auth: WriteAuth, blob: Vec<u8> }, Fetch { mailbox_id: [u8; 32], read_auth: ReadAuth, max: u16, surbs: Vec<Vec<u8>> }, Ack { mailbox_id: [u8; 32], read_auth: ReadAuth, blob_ids: Vec<[u8; 16]> }, Drop, Loop, Subscribe { mailbox_id: [u8; 32], read_auth: ReadAuth, surbs: Vec<Vec<u8>>, until: u64 }, FetchResponse { blobs: Vec<StoredBlob>, more: bool }, Push { mailbox_id: [u8; 32], blobs: Vec<StoredBlob> }, Notify { mailbox_id: [u8; 32], pending: u16 } }`
  - `impl Message { pub fn type_code(&self) -> u8 }` with codes 0x01 PUT, 0x02 FETCH, 0x03 ACK, 0x04 DROP, 0x05 LOOP, 0x06 SUBSCRIBE, 0x10 FETCH_RESPONSE, 0x11 PUSH, 0x12 NOTIFY.
  - `pub fn encode(msg: &Message) -> Vec<u8>` → CBOR `Envelope { v: 1, type: u8, body: bstr(CBOR of the variant's fields) }`.
  - `pub fn decode(bytes: &[u8]) -> Result<Message>` — `UnsupportedVersion` if `v != 1`, `Malformed` for unknown `type` or bad body. `max_len` = `sphinx::max_message_len(SizeClass::Large)` (Task 10; until then a local constant `MAX_ENVELOPE_LEN = 32 * 1024`).
  - `pub fn read_bound(msg: &Message) -> Option<(ReadOp, Vec<u8>)>` — the `bound` bytes defined on `ReadOp` (Task 4) for FETCH/ACK/SUBSCRIBE, `None` otherwise.
  - Limits: `surbs.len() <= 16`, `blob_ids.len() <= 64`, `blobs.len() <= 64` → else `TooLarge`.

- [ ] **Step 1: Write failing tests** — one `roundtrip_<variant>` per variant; `type_codes_match_spec` (table of the 9 codes); `unknown_type_rejected` (type 0x07 → `Malformed`); `wrong_version_rejected` (v = 2 → `UnsupportedVersion`); `too_many_surbs_rejected` (17 → `TooLarge`); `decoders_never_panic` (proptest on `decode`); `read_bound_matches_definition` (FETCH with max 5 and two SURBs → `00 05 || surb1 || surb2`).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.** Note in the module doc that `DIRECTORY_REQUEST`/`DIRECTORY` (0x20/0x21) are link frames per design E1, not envelopes.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(core): CBOR envelopes for spec §8 messages`.

### Task 6: Node descriptors

**Files:**
- Create: `src/descriptor.rs`

**Interfaces:**
- Consumes: Tasks 2–3.
- Produces:
  - `#[serde(rename_all = "lowercase")] pub enum Role { Gateway, Mix, Mailbox }`
  - `pub struct NodeDescriptor { pub v: u8, pub id_pub: [u8; 32], pub noise_pub: [u8; 32], pub sphinx_pub: [u8; 32], pub sphinx_key_epoch: u32, pub roles: Vec<Role>, pub endpoints: Vec<String>, pub layer: u8, pub valid_until: u64 }` — `impl SignedPayload` (`DOMAIN = DESCRIPTOR`, signer = `id_pub`). `noise_pub` is design deviation E5.
  - `pub fn validate(d: &NodeDescriptor, now_unix_secs: u64) -> Result<()>` — `v == 1`, `1..=3` distinct roles, `1..=4` endpoints each starting with `wss://` and ≤ 255 bytes, `layer <= 2`, `valid_until > now` (`Expired`), `valid_until <= now + 30 days` (`Malformed`).
  - `pub fn node_address(id_pub: &[u8; 32]) -> [u8; 32]` = `h_domain(NODE_ADDR, &[id_pub])` (design §5.7).

- [ ] **Step 1: Write failing tests** — `descriptor_sign_verify`; `descriptor_signed_by_other_key_rejected`; `validate_rejects_expired`; `validate_rejects_far_future`; `validate_rejects_non_wss_endpoint`; `validate_rejects_duplicate_roles`; `node_address_is_stable` (fixed `id_pub` = `[7; 32]` → assert against the hex value the implementation produces, frozen in the test after first run and cross-checked by the vector file of Task 11).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(core): signed node descriptors`.

### Task 7: Vouches, revocations, directory and chain verification (spec §4.2–4.3)

**Files:**
- Create: `src/directory.rs`

**Interfaces:**
- Consumes: Tasks 3, 6.
- Produces:
  - `pub struct Vouch { pub v: u8, pub node_id: [u8; 32], pub sponsor_id: [u8; 32], pub issued: u64 }` (`DOMAIN = VOUCH`, signer = `sponsor_id`).
  - `pub struct Revoke { pub v: u8, pub node_id: [u8; 32], pub sponsor_id: [u8; 32], pub revoked_at: u64 }` (`DOMAIN = REVOKE`, signer = `sponsor_id`).
  - `pub struct DirectoryEntry { pub descriptor: Signed<NodeDescriptor>, pub chain: Vec<Signed<Vouch>> }` — `chain[0]` vouches for the node, `chain[i+1]` vouches for `chain[i].sponsor_id`, the last sponsor is a root; empty chain ⇔ the node is itself a root.
  - `pub struct Directory { pub v: u8, pub issuer: [u8; 32], pub issued: u64, pub entries: Vec<DirectoryEntry>, pub revocations: Vec<Signed<Revoke>> }` (`DOMAIN = DIRECTORY`, signer = `issuer`).
  - `pub const MAX_CHAIN_DEPTH: usize = 8; pub const MAX_DIRECTORY_ENTRIES: usize = 512;`
  - `pub struct VerifiedNode { pub descriptor: NodeDescriptor, pub sponsor: Option<[u8; 32]> }` (`sponsor` = direct sponsor, used later for path diversity).
  - `pub fn verify_entry(entry: &DirectoryEntry, roots: &[[u8; 32]], revocations: &[Revoke], now_unix_secs: u64) -> Result<VerifiedNode>` — rules: descriptor signature + `validate`; each link signature valid and correctly chained; depth ≤ `MAX_CHAIN_DEPTH`; no `node_id` repeated (cycle); terminates at a root (`Untrusted` otherwise); rejected (`Untrusted`) if any node on the chain is revoked, or if any vouch was **issued** by a sponsor at or after that sponsor's `revoked_at`; a `Revoke` counts only if signed by the revoked node's own sponsor in the chain or by a root.
  - `pub fn verify_directory(d: &Signed<Directory>, roots: &[[u8; 32]], now_unix_secs: u64) -> Result<Vec<VerifiedNode>>` — verifies the issuer signature, drops (does not fail on) invalid entries, `TooLarge` above `MAX_DIRECTORY_ENTRIES`.
  - `pub fn intersect(views: &[Vec<VerifiedNode>]) -> Vec<VerifiedNode>` — nodes (by `id_pub` and identical `sphinx_pub`) present in every view (spec §4.2 multi-node view).

- [ ] **Step 1: Write failing tests** — helpers build a root R, nodes A (vouched by R), B (vouched by A). Tests: `root_accepted_with_empty_chain`; `two_level_chain_accepted`; `unknown_root_rejected`; `broken_link_rejected` (chain[1] vouches for a different node than chain[0].sponsor_id); `chain_cycle_rejected` (A vouches B, B vouches A); `chain_depth_capped` (depth 9 → `Untrusted`); `revoked_node_rejected`; `vouch_after_revocation_rejected` (A revoked at t, B vouched by A at t+1 → rejected; C vouched by A at t−1 → accepted); `revoke_by_stranger_ignored`; `directory_drops_bad_entries_keeps_good`; `intersect_keeps_common_only` (also drops a node whose `sphinx_pub` differs between views).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(core): vouch chains, revocation and signed directory`.

### Task 8: Node invite tokens and join proof (spec §4.3)

**Files:**
- Create: `src/invite.rs`

**Interfaces:**
- Consumes: Tasks 2, 3, 6.
- Produces:
  - `pub struct NodeInvite { pub v: u8, pub sponsor_id: [u8; 32], pub sponsor_endpoints: Vec<String>, pub secret: [u8; 32], pub expires: u64 }` (`DOMAIN = NODE_INVITE`, signer = `sponsor_id`; `Debug` redacts `secret`; zeroize on drop).
  - `pub const TOKEN_PREFIX: &str = "hcn1-"; pub const INVITE_TTL_SECS: u64 = 48 * 3600;`
  - `pub fn encode_token(invite: &Signed<NodeInvite>) -> String` — `TOKEN_PREFIX` + Crockford Base32 (alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, no padding, uppercase) of the CBOR bytes.
  - `pub fn decode_token(text: &str, now_unix_secs: u64) -> Result<NodeInvite>` — strip all ASCII whitespace and `-` after the prefix, case-insensitive prefix, uppercase, map `O→0`, `I→1`, `L→1`, decode, verify signature, `Expired` if `expires <= now`.
  - `pub struct JoinRequest { pub descriptor: Signed<NodeDescriptor>, pub proof: [u8; 32] }`
  - `pub fn join_proof(secret: &[u8; 32], descriptor: &Signed<NodeDescriptor>) -> [u8; 32]` = HMAC-SHA256(secret, `descriptor.body`); `pub fn verify_join_proof(secret: &[u8; 32], req: &JoinRequest) -> Result<()>` (constant-time compare, `Unauthorized`).
  - Single-use burning is the server's job (doc comment).

- [ ] **Step 1: Write failing tests** — `token_roundtrip`; `token_has_prefix_and_reasonable_length` (one wss endpoint → `len() < 400`; record the actual length in the doc of Task 11); `token_tolerates_copy_paste_noise` (insert `"\n"`, spaces, `-` every 8 chars, lowercase everything, replace every `0` by `O` → same `NodeInvite`); `expired_token_rejected`; `tampered_token_rejected` (flip one character → `Malformed` or `BadSignature`); `join_proof_roundtrip`; `join_proof_rejects_other_descriptor`; `debug_redacts_invite_secret`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** (Crockford via `data_encoding::Specification` with the alphabet above).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(core): hcn1 node invite tokens and join proof`.

### Task 9: Bootstrap block and link frames

**Files:**
- Create: `src/bootstrap.rs`, `src/link.rs`

**Interfaces:**
- Consumes: Task 3.
- Produces:
  - `pub struct RootEntry { pub id_pub: [u8; 32], pub endpoints: Vec<String> }`, `pub struct Bootstrap { pub v: u8, pub roots: Vec<RootEntry> }` with `pub fn encode(&self) -> Vec<u8>`, `pub fn decode(bytes: &[u8]) -> Result<Self>` (`1..=8` roots, endpoints as in descriptor validation), `pub fn root_ids(&self) -> Vec<[u8; 32]>`. Unsigned: authenticity comes from being compiled into the APK; obfuscation is the app's job.
  - `pub enum SizeClass { Small, Large }` with `pub const fn ciphertext_len(self) -> usize` (2 048 / 32 768), `pub const fn plaintext_len(self) -> usize` (minus 16).
  - `#[repr(u8)] pub enum FrameKind { Padding = 0x00, Sphinx = 0x01, DirectoryReq = 0x02, Directory = 0x03, RegisterInbox = 0x04, JoinRequest = 0x05, JoinResponse = 0x06, Gossip = 0x07 }`
  - `pub const LINK_HEADER_LEN: usize = 3;` (`kind: u8 || body_len: u16 BE`)
  - `pub struct LinkFrame { pub kind: FrameKind, pub body: Vec<u8> }` with `pub fn encode(&self, class: SizeClass) -> Result<Vec<u8>>` → exactly `class.plaintext_len()` bytes, zero-padded, `TooLarge` if the body does not fit; `pub fn decode(bytes: &[u8]) -> Result<(SizeClass, LinkFrame)>` — length must equal one class's `plaintext_len`, unknown kind / `body_len` overflow / non-zero padding → `Malformed`; `pub fn padding(class: SizeClass) -> Vec<u8>` (a `Padding` frame).

- [ ] **Step 1: Write failing tests** — `bootstrap_roundtrip`; `bootstrap_rejects_zero_roots`; `frame_lengths_are_fixed` (encode a 1-byte and a max body in `Small` → both exactly 2 032 bytes); `frame_body_too_large` (`Small` body of 2 030 bytes → `TooLarge`); `frame_rejects_nonzero_padding`; `frame_rejects_unknown_kind`; `frame_rejects_odd_length` (2 031 bytes → `Malformed`); `decoders_never_panic` (proptest on `LinkFrame::decode` and `Bootstrap::decode`).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(core): bootstrap block and fixed-size link frames`.

### Task 10: Sphinx façade

**Files:**
- Create: `src/sphinx.rs`
- Test: `crates/harpochat-core/tests/sphinx_paths.rs`

**Interfaces:**
- Consumes: Tasks 2, 4, 6, 9; crate `sphinx-packet` 0.8 (`SphinxPacketBuilder::with_payload_size`, `with_initial_secret`, `SphinxHeader::compute_expanded_shared_secret`, `ExpandedSharedSecret::replay_tag`, `SphinxPacket::process_with_expanded_secret`, `SURBMaterial::new(.., SINGLE_SEED_SURB_VERSION).construct_recoverable_SURB()`, `SURB::use_surb`, `SurbReplyRecovery::recover_plaintext`, `Payload::recover_plaintext`, `header::HEADER_SIZE`, `constants::MAX_PATH_LENGTH`).
- Produces:
  - `pub const HEADER_LEN: usize` (= `HEADER_SIZE`); `pub const fn packet_len(c: SizeClass) -> usize` = `c.plaintext_len() - LINK_HEADER_LEN`; `pub const fn payload_len(c) -> usize` = `packet_len(c) - HEADER_LEN`; `pub const fn max_message_len(c) -> usize` = `payload_len(c) - PAYLOAD_OVERHEAD_SIZE`.
  - `pub const MAX_HOPS: usize = 5;` (= `MAX_PATH_LENGTH`), `pub const MIN_DISTINCT_NODES: usize = 3;`
  - `pub struct Hop { pub id_pub: [u8; 32], pub sphinx_pub: [u8; 32] }` (`From<&NodeDescriptor>`).
  - `pub const LOCAL_DELIVERY: [u8; 32] = [0; 32];` — destination meaning "deliver to the final node's own mailbox service".
  - `pub fn build_forward(message: &[u8], route: &[Hop], destination: [u8; 32], delays_ms: &[u64], class: SizeClass, initial_secret: Option<[u8; 32]>) -> Result<Vec<u8>>` — `Malformed` if `route.len()` ∉ `1..=MAX_HOPS` or `delays_ms.len() != route.len()`; `TooLarge` if `message.len() > max_message_len(class)`; output length == `packet_len(class)`.
  - `pub enum Processed { Forward { next_hop: [u8; 32], delay_ms: u64, packet: Vec<u8> }, Final { destination: [u8; 32], surb_id: [u8; 16], payload: Vec<u8> } }`
  - `pub fn process(packet: &[u8], sphinx_secret: &X25519Secret) -> Result<([u8; 32], Processed)>` — returns the 32-byte replay tag first; any failure → `CoreError::Sphinx`; input length must equal one class's `packet_len`.
  - `pub fn open_forward_payload(payload: &[u8]) -> Result<Vec<u8>>` (final node of a forward packet recovers the plaintext).
  - `pub struct SurbRecovery(Vec<u8>)` (zeroized, opaque, `to_bytes`/`from_bytes`).
  - `pub fn create_surb(route: &[Hop], destination: [u8; 32], surb_id: [u8; 16], delays_ms: &[u64]) -> Result<(Vec<u8>, SurbRecovery)>` — always `SINGLE_SEED_SURB_VERSION` (the SURB user can't precompute per-hop payloads; see the crate doc).
  - `pub fn use_surb(surb: &[u8], message: &[u8], class: SizeClass) -> Result<(Vec<u8>, [u8; 32])>` → packet + first-hop address.
  - `pub fn recover_reply(recovery: &SurbRecovery, payload: &[u8]) -> Result<Vec<u8>>`.
  - `pub fn surb_len(hops: usize) -> usize` and `pub fn max_surbs_per_subscribe(class: SizeClass) -> usize` (largest n such that a `Message::Subscribe` with n SURBs of `MAX_HOPS` hops plus a realistic `ReadAuth` encodes within `max_message_len(class)`).

- [ ] **Step 1: Write failing tests** (`tests/sphinx_paths.rs`, using real `X25519Secret`s for 5 nodes) — `forward_three_hops_reaches_mailbox` (gateway → mix → mailbox, delays `[0, 100, 0]`, each hop yields the expected `next_hop` = `node_address(next.id_pub)` and `delay_ms`, final yields `LOCAL_DELIVERY` and the original `Message::Put` decodes); `forward_five_hops`; `six_hops_rejected`; `packets_have_constant_length` (every hop's packet has `packet_len(Small)` bytes, for messages of 1 byte and `max_message_len`); `replay_tag_is_stable` (processing the same bytes twice yields the same tag); `wrong_key_fails` (→ `Sphinx`); `surb_reply_roundtrip` (mailbox → mix → gateway; gateway gets `Final { destination: inbox_token, surb_id }`; only `recover_reply` with the matching recovery yields the `FetchResponse`); `surb_reply_unreadable_by_hops` (`open_forward_payload` on the SURB final payload fails); `put_at_max_blob_fits_small_class` (largest blob such that the encoded `Put` == `max_message_len(Small)` builds; one more byte → `TooLarge`); `subscribe_capacity` (`max_surbs_per_subscribe(Small) >= 2` and `max_surbs_per_subscribe(Large) >= 10`; assert the encoded message at that capacity fits and at capacity+1 does not).
- [ ] **Step 2: Run** `cargo test -p harpochat-core --test sphinx_paths` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS. Record the actual values of `packet_len`, `payload_len`, `max_message_len` (both classes), `surb_len(5)` and `max_surbs_per_subscribe` (both classes) for Task 11's doc.
- [ ] **Step 5: Commit** — `feat(core): Sphinx façade with fixed size classes and single-seed SURBs`.

### Task 11: Test vectors and Android handoff documentation

**Files:**
- Create: `crates/harpochat-core/examples/gen_vectors.rs`, `crates/harpochat-core/test-vectors/v1.json`, `crates/harpochat-core/tests/vectors.rs`, `docs/android/core-integration.md`, `docs/android/spec-deltas.md`, `docs/decisions/0001-core-first.md`, `docs/architecture.md`
- Modify: `README.md`, `crates/harpochat-core/Cargo.toml` (version `0.1.0`)

**Interfaces:**
- Consumes: all previous tasks.
- Produces: `v1.json` = `{ "version": 1, "vectors": { "<name>": { "inputs": {…hex…}, "output": "<hex>" } } }` covering: `h_domain`, `node_address`, `mailbox_keys` (pair secret `[0x11; 32]`, epoch 20 000 → write_pub, read_pub, mailbox_id), `put_auth` (nonce `[0x22; 16]`, blob `"hello"`), `read_auth_fetch`, `envelope_put`, `envelope_subscribe`, `descriptor_signed` (seed `[0x01; 32]`), `vouch_signed`, `node_invite_token`, `bootstrap`, `link_frame_small`, `sphinx_forward_3hops` (fixed node seeds `[0x31..=0x33; 32]`, `initial_secret = [0x44; 32]`, delays `[0, 100, 0]`).

- [ ] **Step 1: Write `tests/vectors.rs`** — `vectors_match`: loads `test-vectors/v1.json` and, for each vector, recomputes the output from the inputs and asserts byte equality; also decodes each encoded output and asserts it re-encodes identically.
- [ ] **Step 2: Run** → FAIL (file missing).
- [ ] **Step 3: Write `examples/gen_vectors.rs`** producing `v1.json` deterministically (run twice → identical file); generate it with `cargo run -p harpochat-core --example gen_vectors > crates/harpochat-core/test-vectors/v1.json`.
- [ ] **Step 4: Run** `cargo test --workspace` → all PASS; `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo deny check` clean.
- [ ] **Step 5: Write the docs (French):**
  - `docs/android/core-integration.md` — what `harpochat-core` provides, module by module, with the exact sizes recorded in Task 10; how the app must use it (epochs to poll, directional pair secrets, `LOCAL_DELIVERY`, inbox token, SURB recovery storage in RAM only, `Subscribe` split across several packets when more SURBs than `max_surbs_per_subscribe` are needed); how to replay `v1.json`; that FFI bindings arrive in P2 (`core-v0.2.0`) and that `RelayWsTransport`/JSON protocol is gone.
  - `docs/android/spec-deltas.md` — E1–E6 (E6 = signed objects are `{ body, sig }` over exact body bytes) with the reason for each, plus the SUBSCRIBE capacity finding, phrased as proposed edits to `SERVER_SPEC.md` for the project owner.
  - `docs/decisions/0001-core-first.md` — ADR for approach A.
  - `docs/architecture.md` — overview for the jury: roles, trust model, crate layout, phase status.
- [ ] **Step 6: Bump** `harpochat-core` to `0.1.0`; README status → "P1 terminé, en attente de revue".
- [ ] **Step 7: Commit** — `feat(core): frozen v1 test vectors and Android integration docs`.
- [ ] **Step 8: Open the PR** `feat/p1-core` → `main` (after the owner approves pushing). The tag `core-v0.1.0` is created on `main` after the owner merges.
