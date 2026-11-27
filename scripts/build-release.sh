#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Reproducible build of the Linux binaries (static musl, via zig).
# Used by the Release workflow, by the Reproducible check, and by anyone
# re-building a release to compare it with the published SHA256SUMS:
#   scripts/build-release.sh [x86_64-unknown-linux-musl|aarch64-unknown-linux-musl]
#
# What makes it reproducible: the toolchain is pinned (rust-toolchain.toml),
# dependencies are pinned (Cargo.lock, --locked), the build date is the
# commit date (SOURCE_DATE_EPOCH), absolute paths are rewritten
# (--remap-path-prefix), codegen-units = 1 and no incremental build.
set -euo pipefail
target="${1:-x86_64-unknown-linux-musl}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=$root=. --remap-path-prefix=$cargo_home=/cargo"
rustup target add "$target" >/dev/null
cargo zigbuild --release --locked -p harpochat-server --target "$target"
out="target/$target/release/harpochat-server"
echo "rustc: $(rustc --version) · zig: $(python3 -m ziglang version 2>/dev/null || zig version)"
sha256sum "$out"
