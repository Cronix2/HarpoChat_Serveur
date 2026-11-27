#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Live demonstration: a 5-node HarpoChat mesh on this machine, built the
# way operators build it — one root, then four nodes admitted with one
# copy-paste each (the root sponsors three, its limit; the first admitted
# node sponsors the fourth). Then every node's view, as a phone sees it.
#
#   scripts/demo-mesh.sh            # Ctrl+C stops the five nodes
#
# Nothing is written outside a temporary directory, removed on exit.
set -euo pipefail
root_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root_dir"
cargo build -q --release -p harpochat-server
bin="$root_dir/target/release/harpochat-server"
[ -x "$bin.exe" ] && bin="$bin.exe"
work="$(mktemp -d)"
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

base=47300
listen() { sed -i "s/addr = \"0.0.0.0:443\"/addr = \"127.0.0.1:$2\"/" "$work/$1/harpochat-server.toml"; }
start() {
  "$bin" --dir "$work/$1" run 2>"$work/$1.log" &
  pids+=($!)
}
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "1. La racine (premier nœud du mesh)"
"$bin" --dir "$work/n1" init --root --endpoint "wss://127.0.0.1:$((base + 1))" | sed 's/^/   /'
listen n1 $((base + 1))
start n1
sleep 1

for i in 2 3 4 5; do
  sponsor=n1
  [ "$i" = 5 ] && sponsor=n2
  step "$i. Le nœud n$i rejoint le mesh, parrainé par $sponsor (un seul copier-coller)"
  token="$("$bin" --dir "$work/$sponsor" invite-node 2>/dev/null)"
  echo "   jeton : ${token:0:24}… (${#token} caractères, usage unique, 48 h)"
  "$bin" --dir "$work/n$i" join "$token" --endpoint "wss://127.0.0.1:$((base + i))" | sed 's/^/   /'
  listen "n$i" $((base + i))
  start "n$i"
done

step "6. Le même jeton, réutilisé : refusé, sans dire pourquoi"
"$bin" --dir "$work/replay" join "$token" 2>&1 | sed 's/^/   /' || true

step "7. Gossip : chaque nœud découvre les autres (≈ 10 s)"
sleep 12
for i in 1 5; do
  "$bin" --dir "$work/n$i" status | sed 's/^/   /'
done

step "8. Ce que les nœuds ont journalisé (aucune IP de client, aucun identifiant)"
cat "$work/n1.log" | sed 's/^/   /'

step "Mesh en marche. Ctrl+C pour tout arrêter (la mémoire de chaque nœud est effacée)."
wait
