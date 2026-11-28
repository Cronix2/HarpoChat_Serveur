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
| [`docs/specs/2026-11-26-harpochat-core-design.md`](docs/specs/2026-11-26-harpochat-core-design.md) | Conception technique |
| [`docs/plans/`](docs/plans/) | Plans d'implémentation par phase |
| [`docs/architecture.md`](docs/architecture.md) | Architecture et garanties |
| [`docs/jury/README.md`](docs/jury/README.md) | Dossier jury : promesses, preuves exécutables, démo, limites |
| [`docs/operators/`](docs/operators/) | Installer, parrainer, faire tourner en service |
| [`docs/android/`](docs/android/) | Intégration côté app Android, écarts à la spec |

## Organisation

```text
crates/harpochat-core     noyau partagé serveur + Android : formats, Sphinx, boîtes, jetons (pur, sans I/O)
crates/harpochat-core-ffi bindings Kotlin (uniffi) du noyau pour l'app Android
crates/harpochat-server   binaire du nœud : TLS + WebSocket + Noise, routeur Sphinx, boîtes aux lettres en RAM
```

Installer un nœud : [`docs/operators/install.md`](docs/operators/install.md).

## Télécharger

Les binaires compilés sont sur la page [Releases](https://github.com/Cronix2/HarpoChat_Serveur/releases) :
chaque fusion dans `main` publie automatiquement une version numérotée **`vX.Y.Z`** (serveur
Windows, Linux x86_64, Linux ARM, et bibliothèque Android). Le numéro de correctif augmente à chaque
fusion ; pour passer à une nouvelle version mineure ou majeure, il suffit de relever `version` dans
`Cargo.toml`. Une fusion qui ne touche que la documentation ne publie rien. Le bouton *Run workflow*
du workflow **Release** (onglet *Actions*) reste disponible pour publier une version précise.

## Construire et tester

Prérequis : [Rust](https://rustup.rs) (la version est épinglée dans `rust-toolchain.toml`).

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## État

Phases **P1** à **P5** terminées : noyau `harpochat-core`, binaire et releases signées, nœud joignable (M1), bindings Android, mesh multi-nœuds (M2). En revue : **P6** (trafic de couverture et temps réel, M3/M3b), **P7** (parrainage par jeton, gossip, révocation, M4) et **P8** (fuzzing, résistance à la charge, rotation des clés, audit des logs, builds reproductibles, services, M5).

Démonstration en local, 5 nœuds : `scripts/demo-mesh.sh`. Dossier jury : [`docs/jury/`](docs/jury/README.md). Voir [`docs/architecture.md`](docs/architecture.md) et, pour l'app Android, [`docs/android/`](docs/android/).

## Licence

Apache-2.0, voir [`LICENSE`](LICENSE).
