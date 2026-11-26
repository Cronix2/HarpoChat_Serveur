# HarpoChat Server — conception technique

> **Statut :** v1, 2026-11-26 — à valider par le porteur du projet.
> **Source des exigences :** [`docs/SERVER_SPEC.md`](../../SERVER_SPEC.md) v0.2 (le *quoi*). Ce document décrit le *comment*.
> En cas de conflit, la spec gagne. Tout écart volontaire est listé au §9. Je ne modifie pas la spec
> moi-même : les écarts sont transmis au porteur (et à l'instance Android) via `docs/android/`.
>
> **Méthode de travail :** une branche par phase, une pull request vers `main` que le porteur fusionne.

---

## 1. Intention

Construire le serveur du mesh HarpoChat : un binaire unique, installable par n'importe quel membre de la
communauté, qui achemine des paquets Sphinx de taille fixe sans jamais pouvoir lire le contenu ni savoir
qui parle à qui — y compris pour son propre administrateur. Le projet est une preuve de concept destinée
à un jury professionnel (juin 2027) : il doit être **complet, propre, documenté et défendable** face à un
examen critique, avec des limites de sécurité énoncées honnêtement.

**Objectifs :** jalons M0 à M5 de la spec, dans l'ordre « noyau d'abord ».
**Non-objectifs :** l'app Android (autre instance), l'appairage des contacts, libsignal, les groupes.
**Anti-objectifs (échec même si « ça marche ») :**

- une donnée utilisateur écrite sur disque ou dans un log ;
- une crypto inventée au lieu d'assemblée ;
- un format qui diverge entre serveur et app (deux implémentations) ;
- une promesse d'anonymat non tenable affichée sans réserve.

## 2. Approches considérées (ordre de construction)

| | Approche | Compromis |
|---|---|---|
| **A (retenue)** | **Noyau d'abord** : `harpochat-core` (formats, Sphinx, boîtes, jetons, vecteurs de test) publié tôt par tag, puis jalons serveur M0→M5. | L'app Android se branche tôt sur un format stable ; le mesh tourne plus tard. |
| B | Jalons dans l'ordre, noyau construit au fil de l'eau. | Formats instables jusqu'à M2/M3, l'app doit suivre plusieurs ruptures. |
| C | Squelette de bout en bout immédiat, approfondi ensuite. | Démo précoce, mais risque de figer de mauvais formats avant d'avoir conçu Sphinx/SURB. |

Choix du porteur : **A**, car le noyau est le contrat entre les deux applications et le calendrier le permet.

## 3. Organisation du dépôt

```text
Cargo.toml                       workspace
crates/
  harpochat-core/                noyau partagé — PUR : aucun I/O, aucun tokio, aucune horloge implicite
    src/
      cbor.rs                    encodage/décodage CBOR strict (ciborium), limites de taille
      envelope.rs                Envelope + types 0x01..0x21 (§8 spec)
      link.rs                    trames du lien Noise (§5.2 ci-dessous)
      descriptor.rs              NodeDescriptor, Vouch, Revoke, Directory, chaîne de parrainage
      invite.rs                  NodeInvite (jeton hcn1-, Base32 Crockford), JoinRequest
      bootstrap.rs               bloc Bootstrap (racines)
      mailbox.rs                 dérivation mailbox_id / clés par époque, write_auth / read_auth
      sphinx.rs                  façade sur sphinx-packet : classes de taille, adresses, SURB
      path.rs                    sélection de chemins (diversité parrain / /16, mesh adaptatif)
      noise.rs                   machine à états Noise XX + liaison à l'identité Ed25519
      keys.rs                    types de clés, zeroize
    test-vectors/                vecteurs versionnés (JSON hex), exécutés par les deux CI
  harpochat-core-ffi/            bindings uniffi pour Android (jalon dédié, après core v0.1)
  harpochat-server/              binaire : CLI, config, réseau, rôles gateway / mix / mailbox
docs/
  SERVER_SPEC.md                 contrat (fourni)
  architecture.md                vue d'ensemble pour le jury
  security/threat-model.md       modèle de menace + limites assumées
  android/                       documents à transmettre à l'instance Android
  operators/                     guide d'installation pour les bénévoles
  decisions/                     ADR courts (une décision = un fichier)
```

Les crates actuels `harpo-proto`, `harpo-crypto`, `harpo-server` (protocole JSON, SQLite, logs
d'identité) sont **supprimés** : ils contredisent P1, P2 et §10. Seul le squelette du workspace est
conservé. Le binaire est renommé `harpochat-server` comme dans la spec.

## 4. Choix de bibliothèques

| Besoin | Crate | Raison |
|---|---|---|
| Sphinx + SURB + délais | `sphinx-packet` 0.8 (Nym, Apache-2.0) | Implémentation de référence de Loopix, chemins ≤ 5 sauts, taille de charge configurable. |
| Noise | `snow` | Standard de fait en Rust. |
| Signatures | `ed25519-dalek` 2 | — |
| DH | `x25519-dalek` (version alignée sur `sphinx-packet`) | Une seule version dans l'arbre. |
| KDF / MAC | `blake2`, `hkdf` | Imposés par la spec. |
| CBOR | `ciborium` | Imposé par la spec. |
| Secrets | `zeroize` | — |
| Réseau | `tokio`, `tokio-tungstenite`, `rustls` (+ `rcgen` pour l'auto-signé) | Serveur uniquement. |
| CLI / config | `clap`, `toml`, `serde` | Serveur uniquement. |
| FFI | `uniffi` + `cargo-ndk` | Imposé par la spec. |

Vérification préalable au plan : compiler `sphinx-packet` sur les cibles Android (pure Rust, attendu OK)
et confirmer que l'arbre de dépendances n'a qu'une version de `x25519-dalek` / `rand`.

## 5. Décisions techniques qui complètent la spec

Ces points sont **sous-spécifiés** dans la spec ; je les tranche ici. Ils font partie du contrat et
seront transmis à l'instance Android (`docs/android/`).

### 5.1 Liaison Noise ↔ identité Ed25519

La spec authentifie un nœud par son `id_pub` Ed25519 « via Noise », mais Noise n'utilise que des clés
statiques X25519. Solution (modèle libp2p-noise) :

- chaque nœud a une clé statique Noise X25519 **long terme**, générée à `init` à côté de l'Ed25519 ;
- dans la charge utile chiffrée du handshake `Noise_XX_25519_ChaChaPoly_BLAKE2s`, le nœud envoie
  `{ id_pub, sig = Ed25519(id_sk, "harpochat/v1/noise-static" || noise_static_pub) }` ;
- le pair vérifie la signature et compare `id_pub` à la clé attendue (bootstrap, descripteur).
Conséquence : le bloc `Bootstrap` (§4.4 spec) reste inchangé — il ne contient que `id_pub`.
Le téléphone n'a **pas** d'identité : il fait un XX avec une clé statique éphémère par connexion.

### 5.2 Trames du lien (couche sous Sphinx)

Toute session Noise transporte des **trames de taille fixe** par classe (2 048 o / 32 768 o après
chiffrement), pour que le contrôle ne se distingue pas des données :

```text
LinkFrame { kind: u8, body: bytes }   // CBOR puis bourrage à la taille de classe
  0x00 PADDING          trafic de couverture de lien (§5 spec)
  0x01 SPHINX           paquet Sphinx
  0x02 DIRECTORY_REQ    demande d'annuaire (aussi à l'amorçage, hors Sphinx)
  0x03 DIRECTORY        réponse signée
  0x04 REGISTER_INBOX   téléphone → gateway : jeton de boîte de réception de 32 o
  0x05 JOIN_REQUEST     nouveau nœud → parrain
  0x06 JOIN_RESPONSE    Vouch ou refus uniforme
  0x07 GOSSIP           descripteurs / révocations
```

`DIRECTORY_REQUEST`/`DIRECTORY` (types 0x20/0x21 de la spec) passent donc **sur le lien**, pas dans une
charge Sphinx : à l'amorçage, le client ne connaît pas encore la topologie. C'est l'écart E1 (§9).

### 5.3 Livraison au téléphone (dernier saut des SURB)

Le téléphone s'enregistre auprès de sa gateway avec `REGISTER_INBOX { token: [32] }` aléatoire.
L'adresse de destination finale de ses SURB est `(gateway, token)`. La gateway relie token → connexion
**en RAM**, sans savoir quelles boîtes le téléphone surveille. Elle ne voit jamais de `mailbox_id`.

### 5.4 Droits sur les boîtes (vérification sans état)

Par époque `e`, le client dérive depuis le secret de paire :
`write_sk_e, read_sk_e = HKDF(pair_secret, "harpo-mbx-keys" || e)` (graines Ed25519),
`mailbox_id_e = BLAKE2b-256("harpo-mbx-id" || write_pub_e || read_pub_e)`.

- `write_auth = { write_pub, read_pub, nonce[16], sig_write("harpochat/v1/put" || mailbox_id || nonce || H(blob)) }`
- `read_auth  = { write_pub, read_pub, ts: u64, nonce[16], sig_read("harpochat/v1/" || op || mailbox_id || ts || nonce || H(body)) }`

La mailbox recalcule `mailbox_id` à partir des deux clés publiques : **aucune boîte à pré-enregistrer,
aucune confiance au premier usage**. Les `nonce` sont mis en cache (RAM, fenêtre ± 10 min sur `ts`)
contre le rejeu. Cela réalise la « variante recommandée » de §7.2 spec.

### 5.5 Anti-rejeu Sphinx

Chaque mix garde les tags de rejeu de la clé Sphinx courante dans un **filtre de Bloom tournant**
de taille bornée (config). Un faux positif = un paquet perdu, compensé par la duplication client.
Un ensemble exact sur 7 jours ne tiendrait pas en RAM sur un Raspberry Pi.

### 5.6 Mémoire

En plus des quotas par boîte (1 000 blobs / 50 Mo), un **plafond global** de RAM pour les mailboxes
et SURB (config, ex. 512 Mo). Au-delà : rejet uniforme, jamais d'éviction silencieuse. `mlock` des clés
(`memsec` ou équivalent ; `VirtualLock` sous Windows), core dumps désactivés.

### 5.7 Adressage Sphinx

Adresse de nœud Sphinx (32 o) = `BLAKE2b-256("harpo-node-addr" || id_pub)`. Les clés Sphinx tournent
tous les 7 jours avec chevauchement ; le numéro d'époque de clé est dans le descripteur.

### 5.8 Transport unique

Téléphone ↔ gateway **et** nœud ↔ nœud : WSS (TLS 1.3, certificat auto-signé accepté, généré à `init`)
plus Noise, sur le port 443 par défaut. Un seul port à ouvrir pour les bénévoles. L'option TCP:7600 de la
spec n'est pas implémentée (écart E2).

## 6. Architecture du serveur

```text
             ┌─────────────────────────── harpochat-server ───────────────────────────┐
WSS+Noise ──▶│ link (session Noise, trames fixes, couverture de lien, limite de débit)│
             │        │                                                               │
             │        ▼                                                               │
             │  sphinx router ──▶ délai exponentiel (file à échéance) ──▶ next hop    │
             │        │ final hop                                                     │
             │        ├──▶ mailbox (RAM : boîtes, TTL 7 j, quotas, SURB d'abonnement) │
             │        └──▶ gateway inbox (token → connexion téléphone)                │
             │  directory (descripteurs, chaînes de parrainage, gossip, révocation)   │
             │  cover (loops / drops émis par le nœud, mesure de pertes)              │
             └────────────────────────────────────────────────────────────────────────┘
```

Chaque rôle est un module activable par config. Communication interne par canaux tokio bornés.
Aucun log par paquet : un garde-fou de test vérifie l'absence de champs sensibles dans les logs.

## 7. Phases (ordre de construction)

| Phase | Contenu | Livrable |
|---|---|---|
| **P1 — core v0.1** | Restructuration du workspace, `harpochat-core` : CBOR strict, Envelope, LinkFrame, descripteurs/Vouch/Revoke/Directory, NodeInvite `hcn1-`, Bootstrap, dérivation des boîtes + auth, façade Sphinx (aller + SURB), vecteurs de test, CI (fmt, clippy, test, deny). | Tag `core-v0.1.0` + `docs/android/core-integration.md`. |
| **P2 — FFI** | `harpochat-core-ffi` (uniffi), build `cargo-ndk` 3 ABI en CI, AAR ou `.so` publiés. | Tag `core-v0.2.0`, guide d'intégration Gradle. |
| **P3 — M0** | `harpochat-server` : CLI (`init --root`, `run`, `status`), TOML, clés, matrice de release signée (Windows, Linux x86_64/aarch64 musl). | Release GitHub avec 3 binaires + `SHA256SUMS` signé. |
| **P4 — M1** | Lien WSS+Noise, mailbox RAM, un saut. Client de test en Rust. | 2 clients échangent un blob ; redémarrage = effacement. |
| **P5 — M2** | Routage Sphinx, délais, SURB, gateway inbox, chemins adaptatifs. | Test 5 nœuds au vert. |
| **P6 — M3 + M3b** | Couverture (lien, drop, loop), mesure de pertes, SUBSCRIBE/PUSH/NOTIFY. | Push < 2 s sur 5 nœuds ; test statistique de couverture. |
| **P7 — M4** | Gossip, `invite-node`/`join`/`revoke`, chaînes de parrainage, limites. | Un nœud rejoint avec un seul copier-coller. |
| **P8 — M5** | Fuzzing (`cargo fuzz`), audit des logs, builds reproductibles, services systemd/Windows, docs opérateur et jury. | Fuzz 24 h sans crash ; build reproduit bit à bit. |

Chaque phase a son propre plan d'implémentation (`docs/superpowers/plans/`). Le premier plan couvre P1.

## 8. Tests et qualité

- TDD sur le noyau : chaque format a des tests de round-trip, de rejet (champ manquant, taille, version
  inconnue) et un vecteur de test figé.
- Vecteurs de test générés avec des aléas déterministes (graines fixes), commités en JSON hex ; la CI
  Android les rejoue via FFI.
- Tests d'intégration multi-nœuds en processus (5 nœuds sur ports locaux).
- `cargo deny` (licences, avis de sécurité), `clippy -D warnings`, `#![forbid(unsafe_code)]` dans le
  noyau.
- Documentation au fil de l'eau : chaque phase met à jour `architecture.md`, les ADR et `docs/android/`.

### 5.9 Petites conventions (choix de l'implémenteur)

- **Époque** de boîte = `floor(unix_secondes / 86 400)` en UTC, encodée `u32` big-endian dans les KDF.
- `H(x)` = BLAKE2b-256 partout où ce document l'emploie.
- **Classes de taille** : 2 048 o et 32 768 o désignent la taille du **message Noise chiffré** sur le
  lien (tag de 16 o inclus). La taille du paquet Sphinx et de sa charge utile s'en déduit et est figée
  comme constante dans le noyau.
- Le secret de paire est **directionnel** (une boîte A→B, une boîte B→A) : seul l'expéditeur détient
  `write_sk`, seul le destinataire `read_sk`. C'est un choix côté client, rappelé dans `docs/android/`.
- Toutes les signatures portent une **étiquette de domaine** `harpochat/v1/...` distincte par usage.

## 9. Écarts à répercuter dans la spec (par le porteur, via `docs/android/`)

| # | Écart | Raison |
|---|---|---|
| E1 | DIRECTORY_REQUEST/DIRECTORY sont des trames de lien, pas des charges Sphinx. | Amorçage sans topologie connue. |
| E2 | Transport nœud ↔ nœud : WSS+Noise uniquement (pas de TCP:7600). | Un seul port pour les opérateurs. |
| E3 | Contenu précis de `write_auth` / `read_auth` et dérivation de `mailbox_id` (§5.4). | La spec les laissait ouverts. |
| E4 | Liaison Noise ↔ Ed25519 par signature de la clé statique (§5.1). | Noise ne fait que du X25519. |
| E5 | Ajout de `noise_pub` (X25519 long terme) dans `NodeDescriptor`. | Conséquence de E4. |

## 10. Laissé au constructeur

Noms internes des modules serveur, structure exacte des files de délais, paramètres du filtre de
Bloom, format des vecteurs de test (tant qu'il est documenté), choix de la crate `mlock`.

## 11. Limites assumées (à présenter au jury)

- Mesh de ~5 nœuds : chemin de 3 nœuds, ensemble d'anonymat petit ; un adversaire global peut corréler.
- Aucun logiciel ne peut prouver qu'un nœud exécute le vrai code : la défense est « un nœud malveillant
  n'apprend rien » (P4) + admission par parrainage, pas l'attestation.
- Les racines sont semi-publiques ; la sécurité repose sur les clés, pas sur le secret des adresses.
- Redémarrage d'une mailbox = perte des messages en attente (voulu, compensé par la duplication).
