# HarpoChat Server — dossier pour le jury

> **Pour :** le jury professionnel (juin 2027).
> **Ce qu'il contient :** chaque promesse du projet, le mécanisme qui la tient, et la preuve
> exécutable correspondante (un test que l'on peut lancer). Puis la démonstration et les limites.

## En une phrase

Un réseau de relais tenus par des bénévoles, où **aucun opérateur, administrateur compris, ne peut
lire les messages ni savoir qui parle à qui**, et où un serveur qui n'a pas été admis par le
réseau n'est accepté par personne.

## Le principe

```text
 Téléphone A                                                        Téléphone B
     │ chiffré de bout en bout (Signal, côté app)                        ▲
     ▼                                                                   │
 ┌─────────┐   Sphinx    ┌─────┐   Sphinx   ┌─────────┐   SURB   ┌─────┐  │  ┌─────────┐
 │ gateway │ ──────────▶ │ mix │ ─────────▶ │ mailbox │ ───────▶ │ mix │ ─┴─▶│ gateway │
 └─────────┘  délai      └─────┘  délai     └─────────┘  (RAM)   └─────┘     └─────────┘
  voit l'IP de A,         ne voit ni A       voit la boîte,                 voit l'IP de B,
  pas la boîte            ni la boîte        ni A ni B                      pas la boîte
            ◀────────── trafic leurre (padding, loops, drops) sur chaque lien ──────────▶
```

Chaque nœud ne connaît **qu'un voisin de chaque côté**. Les paquets ont tous la même taille et
sont retardés au hasard. Les liens émettent au même rythme qu'ils transportent des messages ou non.

## Les promesses, et leurs preuves

Chaque preuve est un test du dépôt. `cargo test --workspace <nom>` le lance, par exemple
`cargo test --workspace shaped_instants_do_not_depend_on_traffic`.

| Promesse | Mécanisme | Preuve exécutable |
|---|---|---|
| **Un opérateur ne lit rien** | Contenu chiffré de bout en bout par l'app. Le serveur ne manipule que des paquets Sphinx opaques de taille fixe, des boîtes aux lettres anonymes et des blobs chiffrés. | `m2_mesh` `put_and_fetch_across_five_nodes` : un message traverse 5 vrais nœuds, et le nœud qui le garde n'a jamais vu le destinataire. |
| **Personne ne sait qui parle à qui** | Mix-net de type Loopix : au moins 3 nœuds par route, délais exponentiels choisis par l'expéditeur, réponses par SURB. Une route ne finit jamais sur sa propre gateway. | `m2_mesh` (la boîte ne voit aucun lien de téléphone), tests `path` `route_may_not_end_at_its_gateway` et `never_repeats_a_node`. |
| **Un lien inactif ressemble à un lien actif** | Chaque lien émet ses trames aux instants d'un processus de Poisson, tirés sans regarder s'il y a du trafic réel. Le padding comble les instants vides. | `cover` `shaped_instants_do_not_depend_on_traffic` : avec la même graine, un lien vide et un lien chargé émettent **aux mêmes instants**. `m3_cover_realtime` `phone_link_rate_is_independent_of_traffic`. |
| **Les faux serveurs sont exclus** | Un nœud n'est accepté que par une chaîne de certificats qui remonte aux racines embarquées dans l'app. Son identité est prouvée par Noise. Au plus 3 parrainages par 30 jours, vérifiés par tous. Révocation propagée. | `m4_membership` `join_chain_and_revoke` ; `m2_mesh` `directory_lists_whole_mesh` (sans la bonne racine, rien n'est accepté) ; tests `directory` `sponsor_limit_enforced_by_verifiers` et `vouch_before_sponsor_admission_rejected`. |
| **Rien sur disque** | Boîtes, SURB et clés Sphinx en RAM seulement. Seuls la configuration et la clé d'identité sont persistantes. En service Linux : ni swap ni fichier core. | `m1_single_hop` (un redémarrage efface tout), `logs` `logs_reveal_nothing`. |
| **Des logs qui ne trahissent personne** | Démarrage, arrêt, compteurs agrégés. Jamais d'IP de client, d'identifiant de boîte, de taille ni d'horodatage par paquet. | `logs` `logs_reveal_nothing` : le vrai binaire, en niveau *debug*, avec un téléphone actif. Le test casse si l'on ajoute un log de l'adresse cliente. |
| **Temps réel** | Le téléphone dépose des SURB (SUBSCRIBE). À l'arrivée d'un message, la boîte le pousse à travers le mix. | `m3_cover_realtime` `push_arrives_under_two_seconds` (5 nœuds, mesuré). |
| **Rejoindre le réseau est simple** | `invite-node` sur un membre, puis `join <jeton>` sur la nouvelle machine : un seul copier-coller. | `m4_membership` ; démonstration ci-dessous. |
| **Résister aux entrées hostiles** | 10 cibles de fuzzing sur tout ce qui vient du réseau. Plafonds de connexions. Filtre anti-rejeu de taille fixe. Clé Sphinx renouvelée chaque semaine. | `fuzz_bodies` (sur stable, à chaque build), workflow *Fuzz* (libFuzzer en CI), `m1_single_hop` `link_cap_refuses_excess`, `router` `replay_after_rotation_refused`. |
| **Le binaire est bien ce code** | Builds reproductibles, et signature Sigstore des sommes de contrôle. | Workflow *Reproducible build* (deux compilations, même SHA-256) ; `scripts/verify-release.sh <tag>`. |

## Démonstration (5 minutes)

```bash
scripts/demo-mesh.sh
```

Le script fait, en direct et sur une seule machine, ce que feraient cinq opérateurs :

1. une racine est créée ;
2. quatre nœuds rejoignent le mesh, **chacun par un copier-coller** de jeton. La racine en
   parraine trois, c'est sa limite ; le premier admis parraine le quatrième (chaîne de 2) ;
3. le même jeton, réutilisé, est **refusé sans explication** (aucun oracle) ;
4. après quelques secondes de gossip, la commande `status` montre, depuis la racine **et** depuis
   le dernier arrivé, les 5 nœuds, tous vérifiés jusqu'à la racine ;
5. les logs : un démarrage et trois parrainages, rien d'autre.

Pour montrer un message qui traverse le mesh, avec réponse et notification en temps réel :

```bash
cargo test -p harpochat-server --test m3_cover_realtime push_arrives_under_two_seconds
cargo test -p harpochat-server --test m4_membership
```

## Les limites, dites honnêtement

| Limite | Pourquoi | Ce qui l'atténue |
|---|---|---|
| Un adversaire qui **voit tout Internet** peut corréler les entrées et les sorties. | Aucun mix-net ne l'empêche entièrement. Avec ~5 nœuds et peu d'utilisateurs, l'ensemble d'anonymat est petit. | Délais aléatoires et trafic de couverture rendent la corrélation coûteuse et statistique. La protection grandit avec le nombre de nœuds et d'utilisateurs (3 couches de mix à partir de 12 nœuds). |
| La couverture **montante** (du téléphone vers le réseau) dépend de l'app. | Le serveur ne peut pas émettre à la place du téléphone. | Documenté pour l'équipe Android (`docs/android/core-integration.md` §8). Le noyau fournit drops et loops. |
| Un **gros message** (classe 32 Kio) se distingue d'un petit par sa taille. | Deux classes de taille seulement, choix de la spec. | Le padding est toujours de classe petite. Les médias sont découpés. |
| Le débit de couverture coûte de la **bande passante** (≈ 20 Ko/s par lien et par sens, au défaut). | C'est le prix de l'indistinguabilité. | Réglable par l'opérateur. Le téléphone choisit son débit descendant (batterie ou anonymat). |
| Un parrain compromis peut admettre jusqu'à **3 complices par mois**. | Le parrainage repose sur la confiance dans le parrain. | La limite est vérifiée par tous, l'antidatage est borné, et la révocation retire aussi tout ce que le nœud révoqué a parrainé après coup. Les chemins évitent deux nœuds du même parrain. |
| Un annuaire contient au plus **environ 50 nœuds**. | Il doit tenir dans une trame de lien. | Suffisant pour le lancement. La pagination reste à faire. |
| Une révocation est publiée **au redémarrage** du nœud qui la signe. | Elle passe par la configuration. | Elle se propage ensuite en quelques secondes par gossip. |

## En chiffres

- 3 crates Rust : noyau partagé avec l'app Android, serveur, bindings Kotlin. Aucun `unsafe` dans le
  noyau.
- 287 tests automatiques, dont 5 scénarios « jalons » (M1 à M4) sur de vrais nœuds en
  réseau local, et un audit des logs sur le vrai binaire.
- 10 cibles de fuzzing, une CI sous Linux et Windows, un contrôle des licences et des failles
  (`cargo-deny`).
- 22 écarts à la spec, tous documentés et justifiés (`docs/android/spec-deltas.md`).
- Aucune cryptographie maison : Sphinx (Nym), Noise (snow), Ed25519 / X25519 (dalek), rustls.

## Pour aller plus loin

- Architecture : [`../architecture.md`](../architecture.md)
- Contrat entre l'app et le serveur : [`../SERVER_SPEC.md`](../SERVER_SPEC.md) et ses écarts
  [`../android/spec-deltas.md`](../android/spec-deltas.md)
- Exploitation : [`../operators/install.md`](../operators/install.md),
  [`../operators/services.md`](../operators/services.md)
