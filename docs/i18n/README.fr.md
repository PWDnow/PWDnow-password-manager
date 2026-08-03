<div align="center">

# PWDnow

Gestionnaire de mots de passe à connaissance nulle, local avant tout

[![CI](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml)
[![Security Audit](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml)
[![Coverage](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml)
[![Mutation Testing](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

[Signaler un bug](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[Proposer une fonctionnalité](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[Politique de sécurité](#politique-de-securite)

</div>

<div align="center">

**Lire dans une autre langue**

| | | | |
|---|---|---|---|
| [English](../../README.md) | Français | [Español](README.es.md) | [Deutsch](README.de.md) |
| [Italiano](README.it.md) | [Português](README.pt.md) | [Русский](README.ru.md) | [العربية](README.ar.md) |
| [हिन्दी](README.hi.md) | [中文](README.zh.md) | [日本語](README.ja.md) | [한국어](README.ko.md) |
| [Bahasa Indonesia](README.id.md) | | | |

</div>

---

## À propos

PWDnow est un gestionnaire de mots de passe construit sur un principe simple : ni le serveur, ni le navigateur, ni le réseau entre les deux ne doivent jamais voir un secret en clair. Toutes les opérations cryptographiques s'exécutent dans un daemon Rust dédié, installé sur la machine qui héberge le coffre. L'interface web, qu'elle soit ouverte localement ou servie à un navigateur, n'échange avec ce daemon que des blocs de données chiffrées et opaques. Il n'y a pas de synchronisation cloud par défaut, aucune télémétrie, et aucun fournisseur qui puisse être contraint de livrer vos données, tout simplement parce qu'il ne les possède jamais.

Le projet est réparti en deux couches qui communiquent via un canal IPC local :

- **Daemon du coffre** (`daemon/`), écrit en Rust : dérivation de clés, chiffrement, déchiffrement, stockage SQLCipher, verrouillage mémoire et effacement sécurisé. C'est la seule partie du système qui manipule une clé ou un identifiant en clair.
- **Interface web** (`web/`), une application React 19 monopage servie par un processus Express : affiche l'interface, transmet les requêtes chiffrées au daemon via une socket Unix, et ne conserve jamais de clé en dehors d'un jeton de session éphémère, gardé uniquement en mémoire.

PWDnow peut fonctionner entièrement hors ligne sur une seule machine, ou être déployé derrière Nginx avec TLS pour un accès en réseau local ou en auto-hébergement. Dans les deux cas, la frontière de confiance reste la même : votre mot de passe maître et vos données ne quittent jamais la mémoire protégée du daemon.

## Sommaire

- [Fonctionnalités](#fonctionnalites)
- [Architecture](#architecture)
- [Modèle de sécurité](#modele-de-securite)
- [Plateformes prises en charge](#plateformes-prises-en-charge)
- [Démarrage](#demarrage)
  - [Installation rapide](#installation-rapide)
  - [Compilation depuis les sources](#compilation-depuis-les-sources)
  - [Configuration](#configuration)
- [Utilisation](#utilisation)
- [Développement](#developpement)
- [Tests](#tests)
- [Déploiement](#deploiement)
- [Politique de sécurité](#politique-de-securite)
- [Contribuer](#contribuer)
- [Licence](#licence)

## Fonctionnalités

**Coffre principal**
- Organisation des identifiants par dossiers, avec réorganisation par glisser-déposer
- Stockage par identifiant du mot de passe, du secret TOTP, de notes et de champs personnalisés
- Notation de la robustesse des mots de passe, détection de réutilisation et détection des mots de passe courants
- Vérification des fuites hors ligne, à partir d'un filtre de Cuckoo local construit sur la base de mots de passe compromis de Have I Been Pwned, sans appel réseau à chaque vérification
- Vue "porteur d'actifs" : une liste consolidée de chaque adresse e-mail, numéro de téléphone et clé de sécurité matérielle enregistrés parmi vos identifiants

**Authentification et MFA**
- Prise en charge de WebAuthn et FIDO2 pour les clés de sécurité matérielles et les authentificateurs de plateforme (Touch ID, Windows Hello)
- Génération TOTP (RFC 6238) et HOTP (RFC 4226), avec protection contre le rejeu
- Connexion sans mot de passe via des clés d'accès synchronisées ou liées à l'appareil
- Application du MFA configurable par compte

**Modes de sécurité**
- Mode contrainte : déverrouiller avec un mot de passe alternatif désigné déclenche un effacement forensique au lieu d'accorder l'accès
- Mode voyage : masque un sous-ensemble choisi d'identifiants derrière un mot de passe distinct avant de franchir une frontière ou de remettre un appareil
- Verrouillage à délai exponentiel après des tentatives de déverrouillage échouées répétées
- Accès d'urgence : accordez à un contact de confiance un accès différé dans le temps à votre coffre si vous devenez injoignable

**Import et export**
- Format natif `.p2w` : un export chiffré en double AEAD, avec remplissage et obfuscation des métadonnées, conçu pour résister à la falsification hors ligne et à l'analyse de trafic
- Export et import en JSON brut, CSV, et XML compatible KeePass
- Import depuis des exports Bitwarden, 1Password (CSV, 1PUX) et NordPass

**Cryptographie post-quantique et de niveau normatif**
- Encapsulation de clé hybride X25519 + ML-KEM-768/1024 (activée par défaut, pas une option à activer séparément)
- Signatures post-quantiques ML-DSA-87
- Dérivation de clé Argon2id, chiffrement authentifié AES-256-GCM et XChaCha20-Poly1305
- Mode strict CNSA 2.0 optionnel, qui restreint le daemon à la suite d'algorithmes de sécurité nationale commerciale de la NSA (HKDF-SHA-384, PBKDF2-SHA-512, et suppression de BLAKE3, SHA3, XChaCha20, Ed25519 et X25519 des chemins de code actifs)

## Architecture

```
┌─────────────────────────────┐        socket Unix        ┌──────────────────────────────┐
│   Interface web (web/)      │  msgpack via /run/...     │   Daemon du coffre (daemon/) │
│   React 19 + Express        │ ─────────────────────────▶│   Rust, SQLCipher, mlock()   │
│   Interface à connaissance   │◀─────────────────────────  │   Argon2id, AES-256-GCM,     │
│   nulle, jeton de session    │      réponses chiffrées   │   XChaCha20-Poly1305,        │
│   uniquement, aucune clé     │                            │   KEM hybride post-quantique │
└─────────────────────────────┘                            └──────────────────────────────┘
```

Le daemon expose un protocole de requêtes et réponses fortement typé (`daemon/src/ipc/protocol.rs`), transporté sous forme de trames MessagePack via une socket Unix. Chaque requête authentifiée porte un jeton de session que le daemon valide avant de toucher à la base de données. Le daemon vérifie également l'identité du processus qui se connecte au niveau du système d'exploitation (`SO_PEERCRED`), de sorte que seul le proxy web de confiance, exécuté sous le bon utilisateur système, puisse l'atteindre.

La couche web ne reçoit jamais de clé maître, de clé de chiffrement de clé, de clé maître du coffre, ou de clé de chiffrement de données, sous quelque forme que ce soit. Elle reçoit du texte chiffré et le transmet. Un daemon de surveillance compagnon (`monitor/`) suit la croissance mémoire, l'utilisation disque et l'état des processus indépendamment du daemon du coffre lui-même, de sorte qu'une fuite mémoire ou un processus bloqué soit détecté et signalé plutôt que de dégrader silencieusement le service.

Le détail technique complet, incluant la hiérarchie de dérivation de clés, la spécification du format de fichier P2W et le modèle de menace, est documenté dans [`architecture.md`](../../architecture.md).

## Modèle de sécurité

PWDnow part du principe que le réseau, le processus du navigateur et le système d'exploitation hôte sont tous potentiellement hostiles, et conçoit son architecture en conséquence plutôt que sur une hypothèse plus favorable.

- **Connaissance nulle par construction** : le navigateur ne peut pas divulguer ce qu'il n'a jamais possédé. Les clés maîtres et les clés dérivées n'existent que dans l'espace mémoire du daemon.
- **Protection mémoire** : la clé maître du coffre est conservée dans une zone mémoire verrouillée (`mlock`), scellée avec `mprotect(PROT_NONE)` au repos, et effacée avec la crate `zeroize` dès qu'elle n'est plus nécessaire.
- **Chiffrement au repos** : la base de données du coffre est chiffrée de bout en bout avec SQLCipher. Les exports utilisent un double AEAD (une couche interne AES-256-GCM et une couche externe XChaCha20-Poly1305), avec l'en-tête lié aux deux étiquettes d'authentification.
- **Vérification indépendante** : le projet exécute en continu des tests de mutation et des tests de chaos dans son intégration continue, en plus des suites de tests unitaires et de bout en bout habituelles, spécifiquement pour détecter les tests qui passent sans réellement vérifier le comportement qu'ils prétendent couvrir.

Si vous découvrez une vulnérabilité, consultez la [Politique de sécurité](#politique-de-securite) avant d'ouvrir un ticket public.

## Plateformes prises en charge

PWDnow est développé et testé principalement sur **Ubuntu 26.04 LTS (Resolute)**. L'installateur détecte et prend également en charge :

- Debian et les distributions dérivées de Debian (Ubuntu, Linux Mint, Pop!_OS, Zorin, Kali)
- Fedora et les distributions de la famille RHEL (Fedora, RHEL, CentOS, Rocky Linux, AlmaLinux)

Les architectures `x86_64` et `aarch64` sont toutes deux prises en charge par la chaîne d'outils Rust. D'autres distributions Linux peuvent fonctionner mais ne font pas partie de la matrice de tests régulière. Il n'existe actuellement pas de version pour macOS ou Windows.

## Démarrage

### Installation rapide

```bash
git clone https://github.com/PWDnow/PWDnow-password-manager.git
cd PWDnow
./install.sh
```

L'installateur détecte votre distribution, vérifie les dépendances manquantes et propose de les installer, audite votre configuration SSH, vérifie les conflits de ports, compile le daemon et le frontend web depuis les sources, puis installe les deux en tant que services systemd, exécutés sous des utilisateurs système dédiés et non privilégiés. Rien n'est installé avec des privilèges élevés au-delà de ce qu'exigent systemd, AppArmor et l'installation des paquets, et chaque étape privilégiée est affichée avant son exécution.

### Compilation depuis les sources

Prérequis : Node.js 20 ou supérieur, Rust 1.94 ou supérieur (fixé dans `daemon/rust-toolchain.toml`), `protoc`, ainsi que les en-têtes de développement pour `libsodium`, `sqlcipher` et `libfido2`.

```bash
# Daemon
cd daemon
cargo build --release
cargo test

# Web
cd web
npm install
npm run build
npm start
```

Ou, depuis `deploy/` :

```bash
make build          # daemon + web, mode release
make test            # cargo test + vitest
make install          # installe le binaire, les unités systemd, le profil AppArmor et la config nginx (nécessite sudo)
```

L'encapsulation de clé post-quantique est activée par défaut. `make build-pq` et `cargo build --release --features pq-hybrid-1024` sont conservés comme alias explicites de cette même compilation par défaut, pour plus de clarté et par compatibilité avec l'ancienne documentation. Utilisez `--features cnsa-strict` pour le mode strict CNSA 2.0.

### Configuration

Copiez `web/.env.example` vers `web/.env` et ajustez selon vos besoins :

| Variable | Rôle |
|---|---|
| `DAEMON_GRPC_ADDR` | Adresse utilisée par la couche web pour joindre le daemon (par défaut `127.0.0.1:50051`) |
| `VAULT_ORIGIN` | Origine navigateur autorisée en production, utilisée pour la vérification d'origine WebSocket |
| `BIND_HOST` | Interface sur laquelle le serveur web écoute (par défaut `127.0.0.1` ; utilisez `0.0.0.0` pour un accès réseau local) |
| `SSL`, `SSL_PORT`, `SSL_DIR` | HTTPS auto-signé optionnel, généré par `web/scripts/generate-ssl.sh` |

## Utilisation

Au premier lancement, `Setup.tsx` guide la création du coffre : choix d'un mot de passe maître, enregistrement optionnel d'une clé de sécurité matérielle ou d'un TOTP, et le daemon crée une base de données SQLCipher chiffrée ainsi qu'un fichier annexe en clair qui n'enregistre que ce dont la page de connexion a besoin (quelles méthodes MFA sont configurées, si la connexion par mot de passe est même activée), afin que rien n'ait besoin d'être déchiffré avant que vous ne soyez authentifié.

À partir de là :

- Organisez vos identifiants en dossiers, ajoutez des champs personnalisés et générez des mots de passe robustes directement sur place
- Activez le mode contrainte et le mode voyage depuis les Paramètres si vous souhaitez pouvoir présenter un état sûr et plausible sous la contrainte ou lors du passage d'une frontière
- Utilisez le moniteur de fuites intégré pour vérifier vos mots de passe enregistrés par rapport à une copie locale et hors ligne de mots de passe compromis connus, sans requête sortante par mot de passe
- Exportez un fichier `.p2w` pour la sauvegarde, ou importez depuis un autre gestionnaire de mots de passe, sans jamais quitter votre machine

## Développement

Organisation du dépôt :

```
PWDnow/
├── daemon/     Daemon du coffre en Rust. Toute la cryptographie se trouve ici.
├── web/        Frontend React 19 + Express et proxy IPC.
├── monitor/    Processus Rust indépendant de surveillance et de détection de fuites mémoire.
├── deploy/     Unités systemd, profil AppArmor, config Nginx, Makefile.
├── proto/      Définitions gRPC/protobuf partagées entre le daemon et le web.
└── hibp/       Script qui construit le filtre de Cuckoo HIBP hors ligne.
```

Consultez [`CLAUDE.md`](../../CLAUDE.md) pour la référence architecturale complète utilisée par les contributeurs et les outils automatisés, et [`web/CLAUDE.md`](../../web/CLAUDE.md) pour les conventions spécifiques au frontend, y compris le registre des clés localStorage, la liste de vérification IPC pour ajouter un nouveau point d'accès au daemon, et les frontières cryptographiques que le frontend ne doit jamais franchir.

## Tests

```bash
# Daemon
cd daemon && cargo test
cargo test -- <test_name>       # exécuter un seul test

# Tests unitaires web
cd web && npm run test
npx vitest run src/utils/crypto.test.ts   # un seul fichier

# Bout en bout (Playwright)
cd web && npx playwright test
npx playwright test e2e/comprehensive-platform.spec.ts   # parcours de non-régression complet
```

L'intégration continue exécute les tests unitaires, les tests de bout en bout, l'audit des dépendances, les tests de mutation et les tests de chaos à chaque push et pull request. `web/e2e/comprehensive-platform.spec.ts` est le portail de non-régression : il parcourt l'authentification (succès et échec), la navigation, les opérations CRUD sur les dossiers et identifiants, le mode contrainte et la destruction de compte, et doit passer avant tout changement frontend ou lié à l'authentification.

## Déploiement

Pour tout usage dépassant une seule machine locale, placez Nginx devant le processus Express :

- `deploy/nginx/vault.conf` gère la terminaison TLS, HSTS et la limitation de débit. Nginx ne doit pas définir son propre en-tête Content-Security-Policy, car le serveur Express injecte un nonce distinct à chaque requête.
- `deploy/vault-daemon.service` exécute le daemon sous un utilisateur système dédié `vault`, avec `MemorySwapMax=0`, `NoNewPrivileges`, `PrivateTmp`, et uniquement la capacité `CAP_IPC_LOCK` nécessaire au verrouillage mémoire.
- `deploy/apparmor.d/vault-daemon` confine l'accès au système de fichiers et aux capacités du daemon au niveau du noyau, et s'applique sans modification aussi bien sur des hôtes `x86_64` que `aarch64`.

`make install` (ou `install.sh` pour une installation guidée complète) met tout cela en place, y compris le chargement du profil AppArmor et l'activation des unités systemd.

## Politique de sécurité

PWDnow manipule des identifiants, un signalement de vulnérabilité y compte donc plus que dans la plupart des projets. Si vous découvrez un problème de sécurité, merci de ne pas ouvrir de ticket public. Utilisez plutôt le signalement privé de vulnérabilités de GitHub pour ce dépôt, ou contactez directement les mainteneurs. Fournissez suffisamment de détails pour reproduire le problème et, si possible, une évaluation de son impact. Nous accuserons réception rapidement et créditerons les personnes qui le souhaitent une fois le correctif publié.

## Contribuer

Les tickets et les pull requests sont les bienvenus. Avant de soumettre une modification :

- Exécutez `make lint` (`cargo clippy -D warnings` et `tsc --noEmit`) et `make test`
- Pour les modifications frontend ou liées à l'authentification, exécutez la suite complète de non-régression Playwright
- Conservez les modifications cryptographiques dans le daemon uniquement ; la couche web ne doit jamais obtenir accès à des clés comme effet secondaire d'un changement de fonctionnalité
- Suivez les conventions décrites dans `CLAUDE.md` et `web/CLAUDE.md`

## Licence

PWDnow est distribué sous [licence MIT](../../LICENSE).
