<div align="center">

# PWDnow

Zero-Knowledge-Passwortmanager, lokal zuerst

[![CI](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml)
[![Security Audit](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml)
[![Coverage](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml)
[![Mutation Testing](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

[Fehler melden](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[Funktion vorschlagen](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[Sicherheitsrichtlinie](#sicherheitsrichtlinie)

</div>

<div align="center">

**In einer anderen Sprache lesen**

| | | | |
|---|---|---|---|
| [English](../../README.md) | [Français](README.fr.md) | [Español](README.es.md) | Deutsch |
| [Italiano](README.it.md) | [Português](README.pt.md) | [Русский](README.ru.md) | [العربية](README.ar.md) |
| [हिन्दी](README.hi.md) | [中文](README.zh.md) | [日本語](README.ja.md) | [한국어](README.ko.md) |
| [Bahasa Indonesia](README.id.md) | | | |

</div>

---

## Über PWDnow

PWDnow ist ein Passwortmanager, der auf einer einfachen Prämisse aufbaut: Weder der Server noch der Browser noch das Netzwerk dazwischen sollen jemals ein Geheimnis im Klartext zu Gesicht bekommen. Sämtliche kryptografischen Operationen laufen in einem eigenen Rust-Daemon auf demselben Rechner, auf dem der Tresor liegt. Die Weboberfläche, ob lokal geöffnet oder einem Browser bereitgestellt, tauscht mit diesem Daemon ausschließlich verschlüsselte, undurchsichtige Datenblöcke aus. Es gibt standardmäßig keine Cloud-Synchronisierung, keine Telemetrie und keinen Anbieter, der gezwungen werden könnte, Ihre Daten herauszugeben, weil er sie schlicht nie besitzt.

Das Projekt gliedert sich in zwei Schichten, die über einen lokalen IPC-Kanal kommunizieren:

- **Tresor-Daemon** (`daemon/`), geschrieben in Rust: Schlüsselableitung, Ver- und Entschlüsselung, SQLCipher-Speicherung, Speicher-Locking und sicheres Löschen. Dies ist der einzige Teil des Systems, der jemals einen Klartextschlüssel oder eine Klartext-Zugangsdaten berührt.
- **Weboberfläche** (`web/`), eine React-19-Single-Page-Anwendung, bereitgestellt durch einen Express-Prozess: rendert die Oberfläche, leitet verschlüsselte Anfragen über einen Unix-Domain-Socket an den Daemon weiter und hält niemals Schlüsselmaterial vor, außer einem kurzlebigen Sitzungstoken, das nur im Arbeitsspeicher existiert.

PWDnow kann vollständig offline auf einem einzelnen Rechner laufen oder hinter Nginx mit TLS für LAN- oder selbstgehosteten Serverzugriff bereitgestellt werden. In beiden Fällen bleibt die Vertrauensgrenze dieselbe: Ihr Master-Passwort und Ihre Daten verlassen niemals den geschützten Speicherbereich des Daemons.

## Inhalt

- [Funktionen](#funktionen)
- [Architektur](#architektur)
- [Sicherheitsmodell](#sicherheitsmodell)
- [Unterstützte Plattformen](#unterstutzte-plattformen)
- [Erste Schritte](#erste-schritte)
  - [Schnellinstallation](#schnellinstallation)
  - [Aus dem Quellcode kompilieren](#aus-dem-quellcode-kompilieren)
  - [Konfiguration](#konfiguration)
- [Verwendung](#verwendung)
- [Entwicklung](#entwicklung)
- [Tests](#tests)
- [Bereitstellung](#bereitstellung)
- [Sicherheitsrichtlinie](#sicherheitsrichtlinie)
- [Mitwirken](#mitwirken)
- [Lizenz](#lizenz)

## Funktionen

**Kern-Tresor**
- Ordnerbasierte Organisation von Zugangsdaten mit Drag-and-drop-Sortierung
- Speicherung von Passwort, TOTP-Secret, Notizen und benutzerdefinierten Feldern pro Zugangsdatensatz
- Bewertung der Passwortstärke, Erkennung von Wiederverwendung und Erkennung gängiger Passwörter
- Offline-Leck-Prüfung anhand eines lokal erstellten Cuckoo-Filters auf Basis des Have-I-Been-Pwned-Passwort-Korpus, ohne Netzwerkabfrage bei jeder Prüfung
- Ansicht der Datenträger: eine konsolidierte Liste jeder E-Mail-Adresse, Telefonnummer und Hardware-Sicherheitsschlüssel, die über Ihre Zugangsdaten hinweg registriert sind

**Authentifizierung und MFA**
- Unterstützung für WebAuthn und FIDO2 für Hardware-Sicherheitsschlüssel und plattformeigene Authentifikatoren (Touch ID, Windows Hello)
- TOTP-Erzeugung (RFC 6238) und HOTP-Erzeugung (RFC 4226) mit Replay-Schutz
- Passwortloses Anmelden über synchronisierte oder geräte-gebundene Passkeys
- Konfigurierbare MFA-Erzwingung pro Konto

**Sicherheitsmodi**
- Zwangsmodus: Das Entsperren mit einem festgelegten alternativen Passwort löst statt der Zugangsgewährung eine forensische Löschung aus
- Reisemodus: verbirgt eine ausgewählte Teilmenge von Zugangsdaten hinter einem separaten Passwort, bevor eine Grenze überschritten oder ein Gerät übergeben wird
- Sperre mit exponentiellem Backoff nach wiederholten fehlgeschlagenen Entsperrversuchen
- Notfallzugriff: gewähren Sie einer vertrauenswürdigen Kontaktperson zeitverzögerten Zugriff auf Ihren Tresor, falls Sie nicht erreichbar sind

**Import und Export**
- Natives `.p2w`-Format: ein doppelt AEAD-verschlüsselter Export mit Padding und verschleierten Metadaten, ausgelegt darauf, Offline-Manipulation und Traffic-Analyse zu widerstehen
- Export und Import als reines JSON, CSV und KeePass-kompatibles XML
- Import aus Bitwarden-, 1Password- (CSV, 1PUX) und NordPass-Exporten

**Post-Quanten- und normgerechte Kryptografie**
- Hybride X25519- + ML-KEM-768/1024-Schlüsselkapselung (standardmäßig aktiv, keine separat zu aktivierende Option)
- ML-DSA-87-Post-Quanten-Signaturen
- Argon2id-Schlüsselableitung, authentifizierte Verschlüsselung mit AES-256-GCM und XChaCha20-Poly1305
- Optionaler CNSA-2.0-Strict-Modus, der den Daemon auf die Commercial National Security Algorithm Suite der NSA beschränkt (HKDF-SHA-384, PBKDF2-SHA-512, sowie die Entfernung von BLAKE3, SHA3, XChaCha20, Ed25519 und X25519 aus den aktiven Codepfaden)

## Architektur

```
┌─────────────────────────────┐        Unix-Socket        ┌──────────────────────────────┐
│  Weboberfläche (web/)       │  msgpack über /run/...    │  Tresor-Daemon (daemon/)     │
│  React 19 + Express         │ ─────────────────────────▶│  Rust, SQLCipher, mlock()   │
│  Zero-Knowledge-Oberfläche,  │◀─────────────────────────  │  Argon2id, AES-256-GCM,     │
│  nur Sitzungstoken,          │      verschlüsselte       │  XChaCha20-Poly1305,        │
│  keine Schlüssel             │      Antworten             │  hybrides PQ-KEM             │
└─────────────────────────────┘                            └──────────────────────────────┘
```

Der Daemon stellt ein stark typisiertes Anfrage-Antwort-Protokoll bereit (`daemon/src/ipc/protocol.rs`), übertragen als MessagePack-Frames über einen Unix-Domain-Socket. Jede authentifizierte Anfrage trägt ein Sitzungstoken, das der Daemon validiert, bevor er auf die Datenbank zugreift. Der Daemon prüft zudem die Identität des verbindenden Prozesses auf Betriebssystemebene (`SO_PEERCRED`), sodass nur der vertrauenswürdige Web-Proxy, der unter dem korrekten Systembenutzer läuft, ihn erreichen kann.

Die Web-Schicht erhält niemals einen Master-Schlüssel, einen Schlüsselverschlüsselungsschlüssel, einen Tresor-Master-Schlüssel oder einen Datenverschlüsselungsschlüssel, in keiner Form. Sie erhält Chiffretext und leitet ihn weiter. Ein begleitender Überwachungs-Daemon (`monitor/`) verfolgt Speicherwachstum, Festplattennutzung und Prozessgesundheit unabhängig vom Tresor-Daemon selbst, sodass ein Speicherleck oder ein hängender Prozess erkannt und gemeldet wird, statt den Dienst stillschweigend zu beeinträchtigen.

Vollständige technische Details, einschließlich der Schlüsselableitungshierarchie, der P2W-Dateiformatspezifikation und des Bedrohungsmodells, sind in [`architecture.md`](../../architecture.md) dokumentiert.

## Sicherheitsmodell

PWDnow geht davon aus, dass das Netzwerk, der Browser-Prozess und das Host-Betriebssystem allesamt potenziell feindselig sind, und richtet die Architektur an dieser Annahme aus statt an einer wohlwollenderen Standardannahme.

- **Zero-Knowledge durch Konstruktion**: Der Browser kann nicht preisgeben, was er nie besaß. Master- und abgeleitete Schlüssel existieren ausschließlich im Adressraum des Daemons.
- **Speicherschutz**: Der Tresor-Master-Schlüssel wird in einem gesperrten Speicherbereich (`mlock`) gehalten, der im Ruhezustand mit `mprotect(PROT_NONE)` versiegelt und mit der `zeroize`-Crate gelöscht wird, sobald er nicht mehr benötigt wird.
- **Verschlüsselung im Ruhezustand**: Die Tresor-Datenbank ist durchgängig mit SQLCipher verschlüsselt. Exporte verwenden doppelte AEAD-Verschlüsselung (eine innere AES-256-GCM-Schicht und eine äußere XChaCha20-Poly1305-Schicht), wobei der Header in beide Authentifizierungs-Tags eingebunden ist.
- **Unabhängige Verifikation**: Das Projekt führt in seiner Continuous Integration fortlaufend Mutationstests und Chaos-Tests durch, zusätzlich zu den üblichen Unit- und End-to-End-Testsuiten, gezielt um Tests aufzuspüren, die bestehen, ohne das behauptete Verhalten tatsächlich zu prüfen.

Wenn Sie eine Sicherheitslücke finden, lesen Sie bitte die [Sicherheitsrichtlinie](#sicherheitsrichtlinie), bevor Sie ein öffentliches Issue eröffnen.

## Unterstützte Plattformen

PWDnow wird primär auf **Ubuntu 26.04 LTS (Resolute)** entwickelt und getestet. Der Installer erkennt und unterstützt zusätzlich:

- Debian und Debian-basierte Distributionen (Ubuntu, Linux Mint, Pop!_OS, Zorin, Kali)
- Fedora und Distributionen der RHEL-Familie (Fedora, RHEL, CentOS, Rocky Linux, AlmaLinux)

Sowohl `x86_64` als auch `aarch64` werden von der Rust-Toolchain unterstützt. Andere Linux-Distributionen funktionieren möglicherweise, sind aber nicht Teil der regulären Testmatrix. Derzeit gibt es keinen Build für macOS oder Windows.

## Erste Schritte

### Schnellinstallation

```bash
git clone https://github.com/PWDnow/PWDnow-password-manager.git
cd PWDnow
./install.sh
```

Der Installer erkennt Ihre Distribution, prüft auf fehlende Abhängigkeiten und bietet an, diese zu installieren, prüft Ihre SSH-Konfiguration, kontrolliert Portkonflikte, kompiliert Daemon und Web-Frontend aus dem Quellcode und installiert beide als systemd-Dienste, die unter dedizierten, unprivilegierten Systembenutzern laufen. Es wird nichts mit erhöhten Rechten installiert, das über die Anforderungen von systemd, AppArmor und der Paketinstallation hinausgeht, und jeder privilegierte Schritt wird angezeigt, bevor er ausgeführt wird.

### Aus dem Quellcode kompilieren

Voraussetzungen: Node.js 20 oder neuer, Rust 1.94 oder neuer (festgelegt in `daemon/rust-toolchain.toml`), `protoc`, sowie die Entwickler-Header für `libsodium`, `sqlcipher` und `libfido2`.

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

Oder, von `deploy/` aus:

```bash
make build          # Daemon + Web, Release-Modus
make test            # cargo test + vitest
make install          # installiert Binary, systemd-Units, AppArmor-Profil und nginx-Konfiguration (benötigt sudo)
```

Die Post-Quanten-Schlüsselkapselung ist standardmäßig aktiviert. `make build-pq` und `cargo build --release --features pq-hybrid-1024` bleiben als explizite Aliase desselben Standard-Builds erhalten, aus Gründen der Klarheit und der Kompatibilität mit älterer Dokumentation. Verwenden Sie `--features cnsa-strict` für den CNSA-2.0-Strict-Modus.

### Konfiguration

Kopieren Sie `web/.env.example` nach `web/.env` und passen Sie die Werte nach Bedarf an:

| Variable | Zweck |
|---|---|
| `DAEMON_GRPC_ADDR` | Adresse, über die die Web-Schicht den Daemon erreicht (Standard `127.0.0.1:50051`) |
| `VAULT_ORIGIN` | In der Produktion erlaubte Browser-Origin, verwendet für WebSocket-Origin-Prüfungen |
| `BIND_HOST` | Schnittstelle, an die der Webserver gebunden wird (Standard `127.0.0.1`; für LAN-Zugriff auf `0.0.0.0` setzen) |
| `SSL`, `SSL_PORT`, `SSL_DIR` | Optionales selbstsigniertes HTTPS, erzeugt durch `web/scripts/generate-ssl.sh` |

## Verwendung

Beim ersten Start führt `Setup.tsx` durch die Tresor-Erstellung: Wahl eines Master-Passworts, optionale Registrierung eines Hardware-Sicherheitsschlüssels oder eines TOTP, und der Daemon erstellt eine verschlüsselte SQLCipher-Datenbank sowie eine Klartext-Begleitdatei, die nur das festhält, was die Anmeldeseite benötigt (welche MFA-Methoden konfiguriert sind, ob eine Passwort-Anmeldung überhaupt aktiviert ist), sodass nichts entschlüsselt werden muss, bevor Sie sich authentifiziert haben.

Von dort aus können Sie:

- Zugangsdaten in Ordnern organisieren, benutzerdefinierte Felder hinzufügen und starke Passwörter direkt vor Ort erzeugen
- Zwangsmodus und Reisemodus in den Einstellungen aktivieren, wenn Sie unter Zwang oder beim Grenzübertritt einen plausiblen, sicheren Zustand vorzeigen möchten
- Den integrierten Leck-Monitor ausführen, um Ihre gespeicherten Passwörter gegen eine lokale, offline vorliegende Kopie bekannter kompromittierter Passwörter zu prüfen, ohne ausgehende Abfrage pro Passwort
- Eine `.p2w`-Datei zur Sicherung exportieren oder aus einem anderen Passwortmanager importieren, ohne jemals Ihren Rechner zu verlassen

## Entwicklung

Struktur des Repositorys:

```
PWDnow/
├── daemon/     Tresor-Daemon in Rust. Sämtliche Kryptografie liegt hier.
├── web/        React-19- + Express-Frontend und IPC-Proxy.
├── monitor/    Unabhängiger Rust-Prozess zur Überwachung und Speicherleck-Erkennung.
├── deploy/     systemd-Units, AppArmor-Profil, Nginx-Konfiguration, Makefile.
├── proto/      gRPC/Protobuf-Definitionen, gemeinsam genutzt von Daemon und Web.
└── hibp/       Skript, das den offline HIBP-Cuckoo-Filter erstellt.
```

Die vollständige architektonische Referenz für Mitwirkende und automatisierte Werkzeuge finden Sie in [`CLAUDE.md`](../../CLAUDE.md), frontend-spezifische Konventionen, einschließlich des localStorage-Schlüsselregisters, der IPC-Checkliste zum Hinzufügen eines neuen Daemon-Endpunkts, und der kryptografischen Grenzen, die das Frontend niemals überschreiten darf, in [`web/CLAUDE.md`](../../web/CLAUDE.md).

## Tests

```bash
# Daemon
cd daemon && cargo test
cargo test -- <test_name>       # einen einzelnen Test ausführen

# Web-Unit-Tests
cd web && npm run test
npx vitest run src/utils/crypto.test.ts   # einzelne Datei

# End-to-End (Playwright)
cd web && npx playwright test
npx playwright test e2e/comprehensive-platform.spec.ts   # vollständiger Regressionsdurchlauf
```

Die Continuous Integration führt bei jedem Push und jeder Pull Request Unit-Tests, End-to-End-Tests, Abhängigkeitsprüfungen, Mutationstests und Chaos-Tests aus. `web/e2e/comprehensive-platform.spec.ts` ist das Regressions-Gate: Es durchläuft Authentifizierung (Erfolgs- und Fehlerpfade), Navigation, CRUD-Operationen für Ordner und Zugangsdaten, den Zwangsmodus und die Kontovernichtung und sollte bestehen, bevor eine Frontend- oder Authentifizierungsänderung ausgeliefert wird.

## Bereitstellung

Für alles, was über eine einzelne lokale Maschine hinausgeht, stellen Sie Nginx vor den Express-Prozess:

- `deploy/nginx/vault.conf` übernimmt TLS-Terminierung, HSTS und Ratenbegrenzung. Nginx darf keinen eigenen Content-Security-Policy-Header setzen, da der Express-Server bei jeder Anfrage eine neue Nonce einfügt.
- `deploy/vault-daemon.service` führt den Daemon unter einem dedizierten Systembenutzer `vault` aus, mit `MemorySwapMax=0`, `NoNewPrivileges`, `PrivateTmp`, und nur der für Speicher-Locking benötigten Capability `CAP_IPC_LOCK`.
- `deploy/apparmor.d/vault-daemon` schränkt den Zugriff des Daemons auf Dateisystem und Capabilities auf Kernel-Ebene ein und funktioniert unverändert sowohl auf `x86_64`- als auch auf `aarch64`-Hosts.

`make install` (oder `install.sh` für eine vollständig geführte Installation) verdrahtet all dies, einschließlich des Ladens des AppArmor-Profils und der Aktivierung der systemd-Units.

## Sicherheitsrichtlinie

PWDnow verwaltet Zugangsdaten, weshalb ein Sicherheitsbericht hier mehr wiegt als in den meisten Projekten. Wenn Sie ein Sicherheitsproblem finden, eröffnen Sie bitte kein öffentliches Issue. Nutzen Sie stattdessen die private Sicherheitslücken-Meldung von GitHub für dieses Repository oder kontaktieren Sie die Maintainer direkt. Geben Sie genügend Details an, um das Problem reproduzieren zu können, und nach Möglichkeit eine Einschätzung der Auswirkungen. Wir bestätigen Meldungen zeitnah und würdigen Melderinnen und Melder, die dies wünschen, sobald ein Fix veröffentlicht ist.

## Mitwirken

Issues und Pull Requests sind willkommen. Bevor Sie eine Änderung einreichen:

- Führen Sie `make lint` (`cargo clippy -D warnings` und `tsc --noEmit`) sowie `make test` aus
- Führen Sie bei Frontend- oder Authentifizierungsänderungen die vollständige Playwright-Regressionssuite aus
- Belassen Sie kryptografische Änderungen ausschließlich im Daemon; die Web-Schicht darf niemals als Nebeneffekt einer Funktionsänderung Zugriff auf Schlüsselmaterial erhalten
- Halten Sie sich an die in `CLAUDE.md` und `web/CLAUDE.md` beschriebenen Konventionen

## Lizenz

PWDnow wird unter der [MIT-Lizenz](../../LICENSE) veröffentlicht.
