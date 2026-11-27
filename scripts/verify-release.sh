#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Check a published release end to end:
#   1. the SHA256SUMS file was signed by this repository's Release workflow
#      (Sigstore keyless signature, no key to trust but GitHub's OIDC);
#   2. re-building the tag from source gives exactly the published Linux
#      x86_64 binary, byte for byte.
# Needs: git, gh (or curl), cosign, rustup, python3 -m pip install ziglang,
# cargo install cargo-zigbuild.
#   scripts/verify-release.sh v0.2.0
set -euo pipefail
tag="${1:?usage: verify-release.sh <tag>}"
repo="${REPO:-Cronix2/HarpoChat_Serveur}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

echo "== 1. Signature of SHA256SUMS"
for f in SHA256SUMS SHA256SUMS.cosign.bundle; do
  curl -fsSL -o "$f" "https://github.com/$repo/releases/download/$tag/$f"
done
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp "^https://github.com/$repo/.github/workflows/release.yml@refs/tags/$tag\$" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

echo "== 2. Rebuild from source"
git clone --quiet --depth 1 --branch "$tag" "https://github.com/$repo.git" src
(cd src && scripts/build-release.sh x86_64-unknown-linux-musl)
got="$(sha256sum src/target/x86_64-unknown-linux-musl/release/harpochat-server | cut -d' ' -f1)"
want="$(grep ' harpochat-server-linux-x86_64$' SHA256SUMS | cut -d' ' -f1)"
echo "publié  : $want"
echo "rebâti  : $got"
if [ "$got" = "$want" ]; then
  echo "OK : le binaire publié est exactement celui que produit le code source du tag $tag."
else
  echo "ÉCHEC : le binaire publié ne correspond pas au code source." >&2
  exit 1
fi
