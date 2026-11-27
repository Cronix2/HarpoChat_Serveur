# Faire tourner un nœud en service

> **Pour :** les opérateurs qui veulent un nœud qui démarre avec la machine et redémarre seul.
> Prérequis : un nœud initialisé (`init --root`) ou parrainé (`join`), voir [`install.md`](install.md).

## Linux (systemd)

L'unité fournie, [`packaging/systemd/harpochat-server.service`](../../packaging/systemd/harpochat-server.service),
fait tourner le nœud sous un utilisateur dédié, sans aucun privilège en dehors de l'écoute sur le
port 443. Elle garantit en plus deux propriétés qui découlent de la spec (§7.3, §10) :

- `MemorySwapMax=0` : les boîtes aux lettres, les SURB et les clés Sphinx, qui ne vivent qu'en RAM,
  ne partent **jamais dans le swap** ;
- `LimitCORE=0` : un plantage ne produit **aucun fichier core**, qui contiendrait cette mémoire.

Le reste de l'unité met le nœud en bac à sable : système en lecture seule, pas d'accès aux
répertoires personnels, filtre d'appels système, aucun nouveau privilège.

```bash
sudo useradd --system --home /var/lib/harpochat --shell /usr/sbin/nologin harpochat
sudo install -m 0755 harpochat-server-linux-x86_64 /usr/local/bin/harpochat-server
sudo install -d -o harpochat -g harpochat -m 0700 /var/lib/harpochat

# Nœud parrainé (ou `init --root` pour une racine), en tant qu'utilisateur harpochat :
sudo -u harpochat harpochat-server --dir /var/lib/harpochat join - --endpoint wss://mon-noeud.example:443 < jeton.txt

sudo install -m 0644 harpochat-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now harpochat-server
journalctl -u harpochat-server -f        # démarrage, puis une ligne de compteurs toutes les 10 min
```

Pour arrêter : `sudo systemctl stop harpochat-server`. L'état en mémoire est effacé, et c'est voulu.

## Windows (service)

Dans une invite **administrateur**, une seule fois :

```powershell
mkdir C:\ProgramData\HarpoChat
harpochat-server.exe --dir C:\ProgramData\HarpoChat join - --endpoint wss://mon-noeud.example:443 < jeton.txt
# Le service tourne sous le compte LocalService, sans droits d'administrateur : il doit pouvoir lire
# ses deux fichiers, et personne d'autre que les administrateurs ne doit le pouvoir.
icacls C:\ProgramData\HarpoChat /inheritance:r /grant:r "Administrators:(OI)(CI)F" "NT AUTHORITY\LocalService:(OI)(CI)M"
harpochat-server.exe --dir C:\ProgramData\HarpoChat service install
sc.exe start HarpoChat
```

- Le service démarre automatiquement avec Windows. Il s'arrête proprement, mémoire effacée, sur
  `sc.exe stop HarpoChat` et à l'extinction.
- `harpochat-server.exe service uninstall` l'arrête et le supprime.
- En service, le nœud n'a pas de console : ses rares logs sont perdus. Pour diagnostiquer, arrêtez
  le service et lancez `harpochat-server.exe --dir C:\ProgramData\HarpoChat run` dans une console.
- `run --service` ne se lance pas à la main : c'est la commande que le gestionnaire de services
  exécute.

## Résistance à la charge

| Protection | Valeur | Réglage |
|---|---|---|
| Liens simultanés (téléphones et nœuds) | 4 096 | `[limits] max_links` |
| Poignées de main en cours | 256 | fixe |
| Trames par lien téléphone | 50/s, rafales de 200 | fixe |
| Trames par lien nœud | 2 000/s, rafales de 8 000 | fixe |
| Paquets en attente par pair | 1 024 | fixe |
| Mémoire anti-rejeu | ≈ 7 Mo par clé Sphinx, taille fixe | fixe |
| Mémoire des boîtes et des SURB | 512 Mo | `[limits] global_ram_bytes` |

Au-delà d'une limite, le nœud **ferme ou jette sans répondre**, et compte l'événement dans ses
compteurs agrégés. La boucle d'acceptation n'attend jamais.

La clé Sphinx change tous les 7 jours. L'ancienne reste acceptée une semaine de plus, pour que les
paquets en vol et les SURB récents passent, puis elle est effacée : un trafic enregistré ne peut
plus être déroulé avec elle.
