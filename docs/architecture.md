# HarpoChat Server — architecture

> **Pour :** toute personne qui découvre le projet, y compris le jury. Mise à jour à chaque phase.
> **État :** phase P1 (noyau `harpochat-core` v0.1) terminée, en revue.

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
  test-vectors/v1.json  vecteurs figés, rejoués par les CI serveur et Android
```

Le binaire `harpochat-server` (rôles gateway / mix / mailbox) arrive en P3.

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
| P1 | Noyau `harpochat-core` v0.1, vecteurs, CI | **terminé, en revue** |
| P2 | Bindings Android (uniffi) | à faire |
| P3 | Binaire, CLI, configuration, releases signées (M0) | à faire |
| P4 | Lien WSS + Noise, boîte aux lettres en RAM, un saut (M1) | à faire |
| P5 | Mesh Sphinx, SURB, 5 nœuds (M2) | à faire |
| P6 | Trafic de couverture, temps réel (M3, M3b) | à faire |
| P7 | Gossip, parrainage `invite-node`/`join`, révocation (M4) | à faire |
| P8 | Fuzzing, audit des logs, builds reproductibles (M5) | à faire |
