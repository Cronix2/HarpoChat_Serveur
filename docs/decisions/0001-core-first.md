# ADR 0001 — Construire le noyau partagé avant le serveur

- **Statut :** accepté (2026-11-26)
- **Décideur :** porteur du projet, sur proposition de l'équipe serveur

## Contexte

Le serveur et l'app Android doivent parler exactement le même format : Sphinx, CBOR, dérivation des
boîtes, jetons de parrainage. La spec (§9) impose un crate Rust commun, `harpochat-core`, compilé
dans les deux. L'app Android est plus avancée que le serveur. Le jury a lieu en juin 2027.

## Options

| Option | Pour | Contre |
|---|---|---|
| **A. Noyau d'abord**, puis jalons M0→M5 | Format stable très tôt pour l'app ; un seul contrat testé par vecteurs. | Le mesh tourne plus tard. |
| B. Jalons dans l'ordre, noyau au fil de l'eau | Simple à suivre. | Formats instables jusqu'à M2–M3, l'app suit plusieurs ruptures. |
| C. Squelette de bout en bout immédiat | Démo précoce. | Risque de figer de mauvais formats avant d'avoir conçu Sphinx/SURB. |

## Décision

**A.** Le noyau est le contrat entre les deux applications ; il doit être solide en premier.

## Conséquences

- P1 livre `harpochat-core` v0.1 avec des vecteurs de test figés, P2 les bindings Android.
- L'ancien relais JSON (SQLite, routage `from`/`to`, logs d'identité) est supprimé : il contredisait
  les principes P1, P2 et le §10 de la spec.
