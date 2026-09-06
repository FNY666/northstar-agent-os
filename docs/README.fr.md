# Northstar Agent OS

**Composants de runtime ouverts, fiables et gouvernés pour des coéquipiers IA autonomes.**

[English](../README.md) · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [Español](README.es.md) · [한국어](README.ko.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Português (Brasil)](README.pt-BR.md) · [Italiano](README.it.md) · [Türkçe](README.tr.md) · [Tiếng Việt](README.vi.md)

**En une phrase :** Northstar est un projet indépendant qui assemble des coéquipiers IA gouvernés à partir d’un routage explicite des modèles, de limites d’outils locaux, d’auditabilité et d’une exécution récupérable. **Le composant publié aujourd’hui est Northstar Codex Sidecar, un adaptateur local restreint pour worker — pas une plateforme complète d’agents autonomes.**

> English is the canonical project entry. Translations mirror its scope and security claims; update them when the canonical README changes.

## Ce que c’est

Northstar est un projet de runtime modulaire pour les développeurs qui veulent que leurs coéquipiers IA opèrent avec des limites visibles, plutôt que dans une boucle sans contrainte de prompts et d’outils. Le projet privilégie des briques petites et testables : contrat visible par l’appelant, exécution restreinte, résultats structurés et reprise opérationnelle.

Le projet est construit progressivement. Un composant peut être utile seul, mais le succès de ses tests ne prouve pas qu’une plateforme complète d’agents est sûre ou prête pour la production.

## Ce qui est publié aujourd’hui

- `../components/northstar-codex-sidecar/` — service local Unix socket qui valide les requêtes, exécute Codex en mode read-only, limite les entrées et sorties, masque les erreurs, nettoie les groupes de processus arrivés à expiration et renvoie des états structurés.
- `../components/northstar-run-contract/` — contrat Run Request/Receipt versionné, Run Binding HMAC à expiration et frontière d'adaptateur stricte pour transmettre une exécution vérifiée au Sidecar.
- `../components/northstar-agent-runtime/` — boucle d'agent gouvernée : flux d'événements, dix hooks de cycle de vie, porte d'autorisation à trois couches, plafonds indépendants de tours, d'appels d'outils et d'USD, sous-agents, sessions en ajout seul, compaction sur frontière sûre uniquement et traçage par spans. Il ne détient aucun identifiant de modèle et ne lance aucune CLI de modèle : l'exécution de Codex est déléguée au Sidecar via son Unix socket.
- Tests déterministes, modèle de durcissement systemd, installateur prudent et script de rollback.

## Fonctionnement du Sidecar

Une requête JSON est acceptée par connexion Unix socket :

```json
{"request_id":"demo-1","prompt":"Reply with OK","timeout_ms":10000}
```

La réponse est un objet JSON borné :

```json
{"request_id":"demo-1","status":"ok","text":"OK"}
```

Propriétés importantes :

- Unix socket uniquement ; aucun listener TCP.
- Liste stricte des champs : `request_id`, `prompt`, `timeout_ms`.
- Limites du prompt et du timeout.
- Codex s’exécute avec `--sandbox read-only` et `--ephemeral`.
- Groupe de processus séparé, nettoyé par TERM puis KILL en cas de timeout.
- Deadline de lecture par connexion et pool de workers borné.
- Classes d’erreur structurées et masquage des secrets.
- Utilisateur de service dédié et modèle systemd renforcé.
- Codex reste désactivé tant qu’un administrateur n’a pas installé et activé explicitement le service.

## Démarrage rapide

Prérequis : Linux, Python 3.10 ou supérieur, un exécutable `codex` installé séparément et accessible à l’utilisateur du service, systemd, et un utilisateur/espace de travail dédié sans privilèges.

```sh
cd components/northstar-codex-sidecar
python3 -m py_compile sidecar.py transport.py service.py sidecar_socket.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
sh -n install.sh rollback.sh
```

Examinez les scripts et le compte de service avant d’activer le cycle prudent :

```sh
sudo ./install.sh
sudo systemctl enable --now northstar-codex-sidecar.service
```

L’exécutable Codex est recherché dans `PATH` par défaut ; utilisez `CODEX_BIN` pour un chemin non standard.

## Pour qui

Northstar s’adresse aux développeurs et opérateurs de runtimes IA locaux ou self-hosted qui ont besoin d’un composant d’exécution limité, testable, auditable, désactivable et réversible. Ce n’est pas un produit IA hébergé, une garantie de sécurité automatique ni un remplacement d’une architecture complète d’identité, de politiques, d’espaces de travail et d’observabilité.

## Ce que ce n’est pas

- Pas encore un système d’exploitation multi-agents complet.
- Pas un service hébergé ni une promesse de préparation à la production.
- Pas une API générale d’exécution shell.
- N’autorise pas lui-même les appelants, n’isole pas chaque exécution et ne propage pas l’annulation du parent.
- N’inclut pas d’identifiants Codex et ne fournit pas de compte Codex.

**Not a complete autonomous-agent platform.**

## Relation avec OpenBot

Northstar est un projet indépendant destiné aux intégrations compatibles avec OpenBot. Il n’est ni affilié ni approuvé par OpenBot, CopilotKit ou leurs mainteneurs. Le Sidecar peut s’intégrer à des runtimes de style OpenBot sans prétendre faire partie du dépôt amont OpenBot.

La compatibilité est une cible d’intégration, pas une propriété, une approbation ou une équivalence de sécurité.

## Limite de sécurité

Le Sidecar authentifie les appelants uniquement par les permissions Unix. Une intégration de production doit ajouter l’autorisation et la liaison d’identité de l’appelant, l’isolation de l’espace de travail par exécution ou acteur, la propagation de l’annulation, une observabilité sans journaliser les prompts sensibles, des contrôles de santé et un rollback, la vérification de la concurrence et de l’arbre des processus sur Linux natif, ainsi qu’un examen du compte, du réseau et de la configuration des outils de Codex.

N’exposez pas le Unix socket via un proxy TCP. Ne committez jamais de clés API, tokens OAuth, état de connexion Codex, clés privées, fichiers `.env` de production ou transcriptions utilisateur.

## État du projet

Il s’agit du premier composant public de Northstar. Le runtime plus large de Northstar Agent OS est construit progressivement. La liaison d’identité, l’autorisation de l’espace de travail par exécution, l’annulation, la vérification end-to-end sur Linux natif et l’intégration de déploiement en production restent des responsabilités de l’hôte ou des travaux futurs. **Ce dépôt n’est pas une plateforme complète d’agents autonomes.**

Le nettoyage des groupes de processus doit être validé sur la distribution Linux native cible ; le comportement des signaux et de la récupération des PID sur Linux mobile peut ne pas être représentatif.

## Contribution et maintenance

Voir [CONTRIBUTING.md](../CONTRIBUTING.md) pour les attentes en matière de preuves, tests, sécurité, compatibilité et rollback. Voir [SECURITY.md](../SECURITY.md) pour les signalements de sécurité. English is the canonical source for project scope; translations should be updated when it changes.

## Licence

MIT. Voir [LICENSE](../LICENSE).
