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

**Nœud ordinaire :**

```bash
harpochat-server --dir /var/lib/harpochat init --endpoint wss://mon-noeud.example:443
```

Ajoutez ensuite les racines dans `harpochat-server.toml` :

```toml
[[roots]]
id_pub = "<64 caractères hexadécimaux>"
endpoints = ["wss://racine.example:443"]
```

Et les autres nœuds du mesh, auxquels ce nœud se connecte pour relayer les paquets :

```toml
[[peers]]
id_pub = "<64 caractères hexadécimaux>"
endpoint = "wss://autre-noeud.example:443"
```

(En phase P7, ces deux étapes seront remplacées par un seul copier-coller,
`harpochat-server join <jeton>`, et les pairs seront découverts automatiquement par gossip.)

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

## 5. Protéger la clé

`node.key` est créé avec les droits `0600` sous Linux. Sous Windows, gardez le répertoire de données
dans votre profil utilisateur. Le durcissement des ACL est prévu en phase P8. Si vous perdez
`node.key`, le nœud perd son identité et devra être de nouveau parrainé.

Le lancement en service (systemd, service Windows) sera documenté en phase P8.
