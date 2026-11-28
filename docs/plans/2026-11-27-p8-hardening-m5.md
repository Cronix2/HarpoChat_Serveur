# P8 — Durcissement, exploitation, dossier jury (M5) Implementation Plan

**Goal:** The node resists hostile input and overload. It leaks nothing in its logs. Its release can be rebuilt bit for bit. It installs as a service on Linux and on Windows. The jury has a file that explains, proves and demonstrates (spec §10, §12, M5).

**Architecture:**
- **Fuzzing**:
  - `harpochat_server::fuzzing` holds one body per target: a function `&[u8] -> ()` that must never panic.
  - `fuzz/` (a cargo-fuzz crate outside the workspace) wraps each body in one line.
  - The bodies are also run on stable by a test (random inputs plus seeds).
  - CI (nightly, Linux):
    - on each PR: 60 s per target;
    - weekly: 5 h 45 min per target (GitHub caps a job at 6 h, so the 24 h are reached in several runs, or locally, see docs).
- **DoS**:
  - a semaphore of concurrent links (`limits.max_links`, 4 096);
  - a semaphore of handshakes in progress (256), so the accept loop never blocks;
  - a two-generation Bloom replay cache instead of the `HashSet`: ~7 MiB instead of ~100 MiB, false-positive rate ≈ 10⁻⁶.
- **Sphinx key rotation** (spec §13, 7 days):
  - current key + previous key;
  - the router tries both;
  - the published descriptor carries the current key;
  - the replay tags of a key die with it.
- **Logs**:
  - no ANSI when the output is not a terminal;
  - an aggregated counters line every 10 min;
  - a black-box test checks that a debug run reveals neither IP addresses nor client identifiers.
- **Reproducible builds**:
  - `codegen-units = 1`, `--remap-path-prefix`, `SOURCE_DATE_EPOCH`, `--locked`;
  - a CI job builds twice in two different paths and compares the hashes;
  - a script to verify a release.
- **Services**:
  - a hardened systemd unit (`StateDirectory`, `CAP_NET_BIND_SERVICE`, `MemorySwapMax=0`, `LimitCORE=0`, …);
  - Windows: `harpochat-server service install|uninstall`, plus a `windows-service` dispatcher (`run --service`).
- **Docs**: operators (services, verification), jury (`docs/jury/`), demo script.

## Review Focus

1. **Bodies on stable**: 10 000 random inputs per body, no panic (`fuzz_bodies_never_panic`).
2. **5 000 simultaneous connections**: beyond `max_links`, connections are closed at once and the node keeps serving the others (`link_cap_refuses_excess`).
3. **A packet replayed after one rotation**: refused (`replay_after_rotation_refused`). The same packet after two rotations: undecryptable.
4. **Logs**: a run at `HARPOCHAT_LOG=debug` with a phone that PUTs/FETCHes contains neither the client's port, nor its inbox, nor the mailbox id (`logs_reveal_nothing`).
5. **Build**: two release builds from two different directories give the same SHA-256 (CI).
