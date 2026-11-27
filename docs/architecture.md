# HarpoChat Server — architecture

> **Pour :** toute personne qui découvre le projet, y compris le jury. Mise à jour à chaque phase.
> **État :** phases P1 à P5 terminées (noyau, bindings Android, binaire, nœud joignable, mesh multi-nœuds), en revue.

## 1. Le problème

Une messagerie chiffrée de bout en bout protège le contenu, mais le serveur voit encore **qui parle
à qui, quand, et combien**. HarpoChat vise aussi à cacher ces métadonnées, y compris à
l'administrateur d'un serveur, sur un réseau de serveurs tenus par des bénévoles dont certains
peuvent être malveillants.

## 2. Le principe

- **Contenu :** chiffré par le téléphone (libsignal) avant d'entrer dans le réseau.
- **Qui parle à qui :** chaque message traverse plusieurs nœuds en oignon (**Sphinx**). Chaque nœud
  ne connaît que le saut précédent et le suivant. Des délais aléatoires et du trafic leurre
  brouillent les corrélations (modèle **Loopix**).
- **Destinataire :** les messages attendent dans des **boîtes aux lettres en RAM** désignées par des
  identifiants aléatoires qui changent chaque jour. Le destinataire les relève à travers le mesh,
  avec des blocs de réponse à usage unique (**SURB**) : la boîte ne connaît jamais son IP.
- **Taille :** tous les paquets d'une classe font exactement la même taille (2 Ko ou 32 Ko).
- **Admission :** on n'entre dans le mesh que parrainé par un nœud existant, avec une chaîne de
  parrainage remontant à une clé racine embarquée dans l'app.

## 3. Ce que le projet ne prétend pas

- **Aucun logiciel ne peut prouver qu'un nœud exécute le vrai code.** La défense est double : un
  nœud malveillant n'apprend rien d'utile (principe P4), et l'admission est contrôlée par parrainage.
- Avec ~5 nœuds au lancement, l'ensemble d'anonymat est petit : un adversaire qui observe tout
  Internet peut corréler les entrées et les sorties. Le trafic de couverture complique cette
  corrélation sans la rendre impossible.
- Redémarrer une boîte aux lettres efface les messages en attente. C'est voulu : rien ne survit sur
  un serveur. La duplication côté client compense.

## 4. Organisation du code

```text
crates/harpochat-core   noyau partagé serveur + Android, pur (aucun I/O, aucun unsafe)
  cbor, signed          CBOR strict, objets signés { body, sig }
  keys, hash, domain    Ed25519 / X25519, BLAKE2b, étiquettes de domaine
  mailbox               identifiants de boîtes par époque, autorisations sans état
  envelope              messages applicatifs (PUT, FETCH, ACK, SUBSCRIBE…)
  descriptor, directory descripteurs de nœuds, parrainage, révocation, annuaire signé
  invite, bootstrap     jetons hcn1- d'admission, bloc d'amorçage de l'app
  link, sphinx          trames de taille fixe, routage Sphinx et SURB
  path                  choix des routes (client et leurres des nœuds), placement des boîtes
  test-vectors/v1.json  vecteurs figés, rejoués par les CI serveur et Android
```

```text
crates/harpochat-core-ffi  bindings Kotlin (uniffi) du noyau, pour l'app Android
crates/harpochat-server  binaire du nœud
  config, keystore, node, cli   harpochat-server.toml, node.key, init / run
  net, server                   TLS + WebSocket + Noise, liens téléphone et nœud
  peers                         liens sortants vers les autres nœuds (configurés ou appris)
  membership                    vue du mesh : fusion des annuaires (gossip), revérification
  sponsor, join                 parrainage : jetons, côté parrain et côté nouveau nœud
  router                        couche Sphinx : anti-rejeu, délais, transmission, remise
  service, store                boîtes aux lettres en RAM, abonnements SURB (PUSH / NOTIFY)
  cover                         façonnage des liens, loops et drops du nœud, mesure des pertes
  fuzzing                       corps des cibles de fuzzing (fuzz/, CI)
  winservice                    service Windows (packaging/systemd pour Linux)
```

```text
fuzz/        cibles cargo-fuzz (nightly), hors workspace
packaging/   unité systemd durcie
scripts/     build reproductible, vérification d'une release, démonstration
```

### Durcissement (P8)

- **Entrées hostiles :** dix cibles de fuzzing couvrent tout ce qui arrive du réseau : trames,
  enveloppes, Sphinx, Noise, annuaires, jetons, demandes d'admission, service de boîtes,
  configuration. Elles tournent sous libFuzzer en CI, et sur stable à chaque build.
- **Charge :** plafond de liens et de poignées de main. Au-delà, la connexion est fermée tout de
  suite, et la boucle d'acceptation n'attend jamais.
- **Anti-rejeu :** un filtre de Bloom à clé secrète par clé Sphinx, de taille fixe (environ 7 Mo).
  Un faux positif ne coûte qu'un paquet perdu.
- **Clés Sphinx :** renouvelées chaque semaine. L'ancienne est acceptée une semaine de plus, puis
  effacée.
- **Logs :** totaux agrégés seulement, vérifiés par un test boîte noire.
- **Binaire :** build reproductible (CI : deux compilations, même SHA-256) et signature Sigstore.

### Admission par parrainage (P7)

Un nœud n'entre dans le mesh que par une chaîne de certificats `Vouch` qui remonte à une racine
embarquée dans l'app. Le parrain émet un jeton autoporteur (`invite-node`). Le nouveau nœud le
présente (`join`) en prouvant, par Noise, l'identité de son descripteur. Le parrain brûle le jeton
et signe le certificat. Chaque nœud fusionne ensuite les annuaires de ses voisins toutes les 5 s et
revérifie tout : chaînes, révocations, limite de 3 parrainages par 30 jours. Il ne se relie qu'aux
nœuds qui passent ces vérifications. Un nœud qui n'a pas de chaîne valide n'est accepté par
personne, ni par les autres nœuds ni par les apps : c'est la barrière contre les faux serveurs.

### Trafic de couverture (P6)

Chaque lien sortant émet ses trames aux instants d'un processus de Poisson. À chaque instant, la
trame réelle suivante part, ou une trame de padding s'il n'y en a pas. Ces instants sont tirés
**avant** de regarder la file : le test `shaped_instants_do_not_depend_on_traffic` vérifie qu'avec
la même graine, un lien inactif et un lien chargé à 50 % émettent exactement aux mêmes instants. Seul
le contenu chiffré diffère, et il est invisible. Les nœuds émettent aussi leurs propres loops et
drops, mêlés au trafic réel. Les loops qui ne reviennent pas désignent localement les voisins qui
perdent des paquets.

## 5. Choix cryptographiques

Aucune crypto inventée. Constructions publiées et bibliothèques reconnues :

| Usage | Construction | Bibliothèque |
|---|---|---|
| Routage en oignon, réponses anonymes | Sphinx, SURB à graine unique | `sphinx-packet` (Nym) |
| Signatures | Ed25519 (vérification stricte) | `ed25519-dalek` |
| Échange de clés | X25519 | `x25519-dalek` |
| Hachage, dérivation | BLAKE2b-256, HKDF-SHA256, HMAC-SHA256 | `blake2`, `hkdf`, `hmac` |
| Sérialisation | CBOR (RFC 8949) | `ciborium` |
| Transport (P4) | TLS 1.3 + Noise XX | `rustls`, `snow` |

Chaque signature porte une étiquette de domaine distincte (`harpochat/v1/...`) : une signature
produite pour un usage ne peut jamais être rejouée pour un autre.

## 6. Feuille de route

| Phase | Contenu | État |
|---|---|---|
| P1 | Noyau `harpochat-core` v0.1, vecteurs, CI | **terminé** |
| P2 | Bindings Android (uniffi) | **terminé** |
| P3 | Binaire, CLI, configuration, releases signées (M0) | **terminé** |
| P4 | Lien WSS + Noise, boîte aux lettres en RAM, un saut (M1) | **terminé** |
| P5 | Mesh Sphinx, SURB, 5 nœuds (M2) | **terminé** |
| P6 | Trafic de couverture, temps réel (M3, M3b) | **terminé, en revue** |
| P7 | Gossip, parrainage `invite-node`/`join`, révocation (M4) | **terminé, en revue** |
| P8 | Fuzzing, audit des logs, builds reproductibles, services, dossier jury (M5) | **terminé, en revue** |
