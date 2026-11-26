# HarpoChat Server

Serveur du **mesh HarpoChat** : un réseau de nœuds communautaires qui achemine les messages de
l'application Android HarpoChat **sans pouvoir les lire ni savoir qui parle à qui** — y compris pour
l'administrateur du nœud.

- Le contenu est chiffré de bout en bout par le téléphone avant d'entrer dans le réseau.
- Les paquets ont tous la même taille, traversent plusieurs nœuds en oignon (format **Sphinx**,
  modèle **Loopix**) et sont mêlés à du trafic leurre.
- Un nœud ne garde rien sur disque : les messages en attente vivent en RAM, sous des identifiants
  de boîtes aux lettres aléatoires qui changent chaque jour.
- On n'entre dans le mesh que parrainé par un nœud existant.

## Documents

| Document | Contenu |
|---|---|
| [`docs/SERVER_SPEC.md`](docs/SERVER_SPEC.md) | Contrat client ↔ serveur (exigences) |
| [`docs/superpowers/specs/2026-11-26-harpochat-core-design.md`](docs/superpowers/specs/2026-11-26-harpochat-core-design.md) | Conception technique |
| [`docs/superpowers/plans/`](docs/superpowers/plans/) | Plans d'implémentation par phase |

## Organisation

```text
crates/harpochat-core     noyau partagé serveur + Android : formats, Sphinx, boîtes, jetons (pur, sans I/O)
```

Le binaire `harpochat-server` arrive en phase P3.

## Construire et tester

Prérequis : [Rust](https://rustup.rs) (la version est épinglée dans `rust-toolchain.toml`).

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## État

Phase **P1 en cours** : noyau `harpochat-core` v0.1.

## Licence

Apache-2.0, voir [`LICENSE`](LICENSE).
