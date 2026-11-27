# Installer un nœud HarpoChat

> **Pour :** les bénévoles qui veulent faire tourner un nœud du mesh HarpoChat.
> **État :** phase P5. Les nœuds forment un mesh (pairs déclarés dans `[[peers]]`) et relaient des
> paquets Sphinx multi-sauts. Le parrainage par jeton (`invite-node` / `join`) et la découverte
> automatique arrivent en phase P7.

## Ce que fait (et ne fait pas) un nœud

- Il achemine des paquets chiffrés de taille fixe. Il ne peut **ni lire les messages, ni savoir qui
  parle à qui** : c'est la conception même du réseau, pas une promesse de l'opérateur.
- Il ne garde **rien sur disque** à part deux fichiers : sa configuration
  (`harpochat-server.toml`) et sa clé (`node.key`). Les messages en attente vivent en mémoire vive
  et disparaissent au redémarrage.
- Il ne contacte aucun service tiers : ni télémétrie, ni mise à jour automatique.

## 1. Télécharger et vérifier

Sur la page [Releases](https://github.com/Cronix2/HarpoChat_Serveur/releases), récupérez le binaire
de votre machine, ainsi que `SHA256SUMS` et `SHA256SUMS.cosign.bundle`.

| Machine | Fichier |
|---|---|
| Windows 64 bits | `harpochat-server-windows-x86_64.exe` |
| Linux 64 bits (PC, VPS) | `harpochat-server-linux-x86_64` |
| Linux ARM 64 bits (Raspberry Pi 4/5, VPS ARM) | `harpochat-server-linux-aarch64` |

Vérifiez que `SHA256SUMS` a bien été produit par le workflow de ce dépôt (signature
[Sigstore](https://www.sigstore.dev/), sans clé à gérer) :

```bash
cosign verify-blob \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/Cronix2/HarpoChat_Serveur/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS      # Windows : Get-FileHash <fichier> -Algorithm SHA256
```

Sous Linux : `chmod +x harpochat-server-linux-*`.

## 2. Initialiser

Le répertoire de données se choisit avec `--dir`. À défaut, c'est `$HARPOCHAT_HOME`, et sinon
`./harpochat-data`.

**Premier nœud du mesh (racine)**, réservé au porteur du projet :

```bash
harpochat-server --dir /var/lib/harpochat init --root --endpoint wss://mon-domaine.example:443 --endpoint wss://203.0.113.7:443
```

La commande affiche l'identifiant du nœud et une ligne `bootstrap-entry: …`. Cette ligne (clé
publique et adresses, **aucun secret**) est à intégrer dans le bloc d'amorçage de l'application.
Mettez de préférence une adresse par nom de domaine **et** une par IP directe (spec §4.4).

**Nœud ordinaire : un seul copier-coller.** Sur un nœud déjà membre du mesh (le *parrain*) :

```bash
harpochat-server --dir /var/lib/harpochat invite-node
hcn1-M9J64VV4F5C919B…(≈ 360 caractères)
  ↳ valable 48 h, utilisable une seule fois. C'est un secret : transmettez-le par un canal de confiance.
```

Sur la nouvelle machine, avec un répertoire de données **vide** :

```bash
harpochat-server --dir /var/lib/harpochat join 'hcn1-M9J64…' --endpoint wss://mon-noeud.example:443
✔ clés générées · id: de8b19a7…
✔ parrain joint · 9aa0182f…
✔ certificat de parrainage reçu (chaîne de 1 maillon(s), 1 racine(s))
→ lancez `harpochat-server --dir /var/lib/harpochat run` : le nœud s'annoncera au mesh
```

- Pour que le jeton n'apparaisse ni dans l'historique du shell ni dans la liste des processus,
  passez `-` : `harpochat-server join - --endpoint … < jeton.txt`.
- `join` n'écrit rien en cas d'échec : jeton expiré, déjà utilisé, mal copié, parrain injoignable,
  ou limite de parrainage atteinte. Le parrain refuse sans dire pourquoi : c'est voulu.
- Le nœud reçoit son **certificat de parrainage** (`Vouch`) et les clés des racines. Le tout est
  écrit dans `harpochat-server.toml` (`node.chain`, `[[roots]]`, le parrain dans `[[peers]]`). Une
  fois lancé, il découvre les autres nœuds par **gossip** : chaque nœud interroge l'annuaire de ses
  voisins toutes les 5 s, et se relie à tout nœud dont la chaîne de parrainage remonte à une racine.
- **Limite :** un nœud parraine au plus **3 nœuds par période de 30 jours** (`[sponsor] limit`,
  3 au maximum). Tous les nœuds **et** toutes les apps appliquent cette règle aux chaînes qu'ils
  vérifient : un parrain compromis ne peut pas inonder le mesh.
- Le parrain garde dans `[[sponsor.vouched]]` la trace des jetons consommés. Un jeton reste donc
  brûlé même après un redémarrage. Ces lignes ne contiennent que des identifiants publics.

**Révoquer** un nœud que vous avez parrainé (ou n'importe quel nœud, depuis une racine) :

```bash
harpochat-server --dir /var/lib/harpochat revoke <id du nœud, 64 caractères hex>
```

La révocation est écrite dans `revocations` et publiée par gossip **au prochain redémarrage** du
nœud. Le nœud révoqué disparaît de tous les annuaires, ainsi que les nœuds qu'il aurait parrainés
**après** la révocation.

**Configuration manuelle** (avancé, sans jeton) : `[[roots]]` (identité et adresses des racines),
`[[peers]]` (nœuds auxquels se relier d'office) et `node.chain` (certificats, hexadécimal CBOR).

`init` refuse de s'exécuter sur un répertoire qui contient déjà un nœud : la clé n'est jamais écrasée.

## 3. Vérifier et lancer

```bash
harpochat-server --dir /var/lib/harpochat run --check   # vérifie la configuration et la clé, puis quitte
harpochat-server --dir /var/lib/harpochat run           # démarre (Ctrl+C pour arrêter)
```

Codes de sortie : `0` OK, `1` erreur d'exécution (clé absente ou corrompue…), `2` erreur de
configuration.

Le niveau de log se règle avec `HARPOCHAT_LOG` (par défaut `info`). Le nœud ne journalise jamais
d'IP, d'identifiant de boîte aux lettres, de taille ni d'horodatage de paquet (spec §10).

## 4. Réseau

- Le nœud écoute par défaut sur `0.0.0.0:443` (section `[listen]`). Sous Linux, plutôt que de
  le lancer en root, autorisez le port 443 :
  `sudo setcap cap_net_bind_service=+ep ./harpochat-server-linux-x86_64`.
- Derrière une box, redirigez le port TCP 443 vers la machine.
- Les certificats TLS auto-signés sont acceptés : l'authentification réelle d'un nœud passe par sa
  clé (Noise), pas par le certificat.

## 5. Trafic de couverture et bande passante

Un nœud émet en permanence, même sans utilisateur : c'est ce qui empêche de distinguer un lien
inactif d'un lien actif (spec §5, §6.3). La section `[cover]` règle ce coût :

```toml
[cover]
node_link_rate = 10.0       # trames/s sur chaque lien vers un autre nœud (réelles ou padding)
phone_link_rate = 1.0       # trames/s vers un téléphone, s'il ne demande rien
phone_link_rate_min = 0.05  # bornes des débits qu'un téléphone peut demander
phone_link_rate_max = 10.0
loop_rate = 0.2             # loops émis par le nœud, par seconde (mesure des pertes)
drop_rate = 0.2             # drops émis par le nœud, par seconde
mean_delay_ms = 100         # délai moyen de mix de ces leurres
```

- **Coût :** une trame fait 2 Ko. `node_link_rate = 10` représente environ 20 Ko/s, soit
  1,7 Go/jour, **par pair et par sens**. Un mesh de 5 nœuds coûte donc environ 7 Go/jour en
  émission par nœud. Baissez ce débit sur une petite connexion. Gardez-le **au-dessus du trafic réel** :
  au-delà, les trames réelles s'accumulent puis partent en rafale, et le lien trahit sa charge.
- **Pertes :** chaque nœud mesure, grâce à ses loops, les voisins qui perdent ses paquets. Un voisin
  qui en perd plus de 75 % devient « suspect » et n'est plus utilisé pour les drops du nœud. Rien
  n'est publié ni journalisé par paquet.
- `0` désactive un mécanisme. **Réservé au développement :** sans couverture, un observateur du
  réseau voit quand un utilisateur reçoit du courrier.

## 6. Protéger la clé

`node.key` est créé avec les droits `0600` sous Linux. Sous Windows, gardez le répertoire de données
dans votre profil utilisateur. Le durcissement des ACL est prévu en phase P8. Si vous perdez
`node.key`, le nœud perd son identité et devra être de nouveau parrainé.

Le lancement en service (systemd, service Windows) sera documenté en phase P8.
