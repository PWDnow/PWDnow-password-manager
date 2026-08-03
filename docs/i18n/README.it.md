<div align="center">

# PWDnow

Gestore di password a conoscenza zero, locale prima di tutto

[![CI](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml)
[![Security Audit](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml)
[![Coverage](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml)
[![Mutation Testing](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

[Segnala un bug](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[Proponi una funzionalità](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[Politica di sicurezza](#politica-di-sicurezza)

</div>

<div align="center">

**Leggi in un'altra lingua**

| | | | |
|---|---|---|---|
| [English](../../README.md) | [Français](README.fr.md) | [Español](README.es.md) | [Deutsch](README.de.md) |
| Italiano | [Português](README.pt.md) | [Русский](README.ru.md) | [العربية](README.ar.md) |
| [हिन्दी](README.hi.md) | [中文](README.zh.md) | [日本語](README.ja.md) | [한국어](README.ko.md) |
| [Bahasa Indonesia](README.id.md) | | | |

</div>

---

## Informazioni

PWDnow è un gestore di password costruito su un principio semplice: né il server, né il browser, né la rete che li collega devono mai vedere un segreto in chiaro. Tutte le operazioni crittografiche vengono eseguite all'interno di un daemon Rust dedicato, installato sulla stessa macchina in cui risiede il vault. L'interfaccia web, sia che venga aperta localmente sia che venga servita a un browser, scambia con quel daemon solo blocchi di dati cifrati e opachi. Non c'è sincronizzazione cloud di default, nessuna telemetria, e nessun fornitore che possa essere costretto a consegnare i vostri dati, semplicemente perché non li possiede mai.

Il progetto è suddiviso in due livelli che comunicano tramite un canale IPC locale:

- **Daemon del vault** (`daemon/`), scritto in Rust: derivazione delle chiavi, cifratura, decifratura, archiviazione SQLCipher, blocco della memoria e cancellazione sicura. È l'unica parte del sistema che tocca mai una chiave o una credenziale in chiaro.
- **Interfaccia web** (`web/`), un'applicazione a pagina singola in React 19 servita da un processo Express: mostra l'interfaccia, inoltra le richieste cifrate al daemon tramite un socket Unix, e non conserva mai materiale chiave al di fuori di un token di sessione effimero, mantenuto solo in memoria.

PWDnow può funzionare interamente offline su una singola macchina, oppure essere distribuito dietro Nginx con TLS per l'accesso in rete locale o su server autogestito. In entrambi i casi, il confine di fiducia resta lo stesso: la password principale e i dati non lasciano mai la memoria protetta del daemon.

## Indice

- [Funzionalità](#funzionalita)
- [Architettura](#architettura)
- [Modello di sicurezza](#modello-di-sicurezza)
- [Piattaforme supportate](#piattaforme-supportate)
- [Per iniziare](#per-iniziare)
  - [Installazione rapida](#installazione-rapida)
  - [Compilazione dai sorgenti](#compilazione-dai-sorgenti)
  - [Configurazione](#configurazione)
- [Utilizzo](#utilizzo)
- [Sviluppo](#sviluppo)
- [Test](#test)
- [Distribuzione](#distribuzione)
- [Politica di sicurezza](#politica-di-sicurezza)
- [Contribuire](#contribuire)
- [Licenza](#licenza)

## Funzionalità

**Vault principale**
- Organizzazione delle credenziali per cartelle, con riordino tramite trascinamento
- Archiviazione per credenziale di password, secret TOTP, note e campi personalizzati
- Valutazione della robustezza delle password, rilevamento del riutilizzo e rilevamento delle password comuni
- Verifica delle violazioni offline tramite un filtro di Cuckoo locale costruito sul corpus di password compromesse di Have I Been Pwned, senza chiamate di rete a ogni verifica
- Vista dei titolari di asset: un elenco consolidato di ogni indirizzo email, numero di telefono e chiave di sicurezza hardware registrati tra le vostre credenziali

**Autenticazione e MFA**
- Supporto a WebAuthn e FIDO2 per chiavi di sicurezza hardware e autenticatori di piattaforma (Touch ID, Windows Hello)
- Generazione TOTP (RFC 6238) e HOTP (RFC 4226), con protezione dal replay
- Accesso senza password tramite passkey sincronizzate o vincolate al dispositivo
- Applicazione dell'MFA configurabile per singolo account

**Modalità di sicurezza**
- Modalità coercizione: sbloccare con una password alternativa designata avvia una cancellazione forense invece di concedere l'accesso
- Modalità viaggio: nasconde un sottoinsieme scelto di credenziali dietro una password separata prima di attraversare una frontiera o consegnare un dispositivo
- Blocco con backoff esponenziale dopo ripetuti tentativi di sblocco falliti
- Accesso di emergenza: concedete a un contatto fidato un accesso ritardato nel tempo al vostro vault nel caso non foste raggiungibili

**Importazione ed esportazione**
- Formato nativo `.p2w`: un'esportazione cifrata con doppio AEAD, con padding e offuscamento dei metadati, progettata per resistere alla manomissione offline e all'analisi del traffico
- Esportazione e importazione in JSON semplice, CSV e XML compatibile con KeePass
- Importazione da esportazioni Bitwarden, 1Password (CSV, 1PUX) e NordPass

**Crittografia post-quantistica e di livello normativo**
- Incapsulamento di chiave ibrido X25519 + ML-KEM-768/1024 (attivo di default, non un'opzione da abilitare separatamente)
- Firme post-quantistiche ML-DSA-87
- Derivazione di chiave Argon2id, cifratura autenticata AES-256-GCM e XChaCha20-Poly1305
- Modalità rigorosa CNSA 2.0 opzionale, che limita il daemon alla Commercial National Security Algorithm Suite della NSA (HKDF-SHA-384, PBKDF2-SHA-512, e rimozione di BLAKE3, SHA3, XChaCha20, Ed25519 e X25519 dai percorsi di codice attivi)

## Architettura

```
┌─────────────────────────────┐        socket Unix        ┌──────────────────────────────┐
│  Interfaccia web (web/)     │  msgpack su /run/...      │  Daemon del vault            │
│  React 19 + Express         │ ─────────────────────────▶│  (daemon/)                   │
│  Interfaccia a conoscenza    │◀─────────────────────────  │  Rust, SQLCipher, mlock()   │
│  zero, solo token di         │      risposte cifrate     │  Argon2id, AES-256-GCM,     │
│  sessione, nessuna chiave    │                            │  XChaCha20-Poly1305,        │
└─────────────────────────────┘                            │  KEM ibrido post-quantistico │
                                                             └──────────────────────────────┘
```

Il daemon espone un protocollo di richieste e risposte fortemente tipizzato (`daemon/src/ipc/protocol.rs`), trasportato come frame MessagePack su un socket Unix. Ogni richiesta autenticata porta un token di sessione che il daemon convalida prima di accedere al database. Il daemon verifica inoltre l'identità del processo che si connette a livello di sistema operativo (`SO_PEERCRED`), in modo che solo il proxy web fidato, in esecuzione con l'utente di sistema corretto, possa raggiungerlo.

Il livello web non riceve mai una chiave principale, una chiave di cifratura della chiave, una chiave principale del vault o una chiave di cifratura dei dati, in nessuna forma. Riceve testo cifrato e lo inoltra. Un daemon di monitoraggio complementare (`monitor/`) traccia la crescita della memoria, l'utilizzo del disco e lo stato dei processi in modo indipendente dal daemon del vault stesso, in modo che una perdita di memoria o un processo bloccato venga rilevato e segnalato invece di degradare silenziosamente il servizio.

I dettagli tecnici completi, inclusa la gerarchia di derivazione delle chiavi, la specifica del formato di file P2W e il modello di minaccia, sono documentati in [`architecture.md`](../../architecture.md).

## Modello di sicurezza

PWDnow parte dal presupposto che la rete, il processo del browser e il sistema operativo host siano tutti potenzialmente ostili, e progetta la propria architettura in base a questa ipotesi anziché a una più favorevole.

- **Conoscenza zero per costruzione**: il browser non può divulgare ciò che non ha mai posseduto. Le chiavi principali e le chiavi derivate esistono solo all'interno dello spazio di memoria del daemon.
- **Protezione della memoria**: la chiave principale del vault è mantenuta in una regione di memoria bloccata (`mlock`), sigillata con `mprotect(PROT_NONE)` durante l'inattività, e cancellata con la crate `zeroize` non appena non è più necessaria.
- **Cifratura a riposo**: il database del vault è cifrato end-to-end con SQLCipher. Le esportazioni utilizzano un doppio AEAD (uno strato interno AES-256-GCM e uno strato esterno XChaCha20-Poly1305), con l'header vincolato a entrambi i tag di autenticazione.
- **Verifica indipendente**: il progetto esegue continuamente test di mutazione e test di caos nella propria integrazione continua, oltre alle consuete suite di test unitari e end-to-end, specificamente per individuare test che passano senza verificare realmente il comportamento che affermano di coprire.

Se trovate una vulnerabilità, consultate la [Politica di sicurezza](#politica-di-sicurezza) prima di aprire un ticket pubblico.

## Piattaforme supportate

PWDnow viene sviluppato e testato principalmente su **Ubuntu 26.04 LTS (Resolute)**. L'installer inoltre rileva e supporta:

- Debian e distribuzioni derivate da Debian (Ubuntu, Linux Mint, Pop!_OS, Zorin, Kali)
- Fedora e distribuzioni della famiglia RHEL (Fedora, RHEL, CentOS, Rocky Linux, AlmaLinux)

Sia `x86_64` sia `aarch64` sono supportate dalla toolchain Rust. Altre distribuzioni Linux potrebbero funzionare ma non fanno parte della matrice di test regolare. Al momento non esiste una build per macOS o Windows.

## Per iniziare

### Installazione rapida

```bash
git clone https://github.com/PWDnow/PWDnow-password-manager.git
cd PWDnow
./install.sh
```

L'installer rileva la vostra distribuzione, verifica le dipendenze mancanti e offre di installarle, verifica la configurazione SSH, controlla i conflitti di porta, compila il daemon e il frontend web dai sorgenti, e installa entrambi come servizi systemd eseguiti sotto utenti di sistema dedicati e privi di privilegi. Nulla viene installato con privilegi elevati oltre a quanto richiesto da systemd, AppArmor e dall'installazione dei pacchetti, e ogni passaggio privilegiato viene mostrato prima di essere eseguito.

### Compilazione dai sorgenti

Requisiti: Node.js 24 o superiore, Rust 1.94 o superiore (fissato in `daemon/rust-toolchain.toml`), `protoc`, e gli header di sviluppo per `libsodium`, `sqlcipher` e `libfido2`.

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

Oppure, da `deploy/`:

```bash
make build          # daemon + web, modalità release
make test            # cargo test + vitest
make install          # installa il binario, le unità systemd, il profilo AppArmor e la configurazione nginx (richiede sudo)
```

L'incapsulamento di chiave post-quantistico è attivo di default. `make build-pq` e `cargo build --release --features pq-hybrid-1024` restano come alias espliciti della stessa build predefinita, per chiarezza e per compatibilità con la documentazione precedente. Usate `--features cnsa-strict` per la modalità rigorosa CNSA 2.0.

### Configurazione

Copiate `web/.env.example` in `web/.env` e regolate secondo necessità:

| Variabile | Scopo |
|---|---|
| `DAEMON_GRPC_ADDR` | Indirizzo usato dal livello web per raggiungere il daemon (default `127.0.0.1:50051`) |
| `VAULT_ORIGIN` | Origine browser consentita in produzione, usata per i controlli di origine WebSocket |
| `BIND_HOST` | Interfaccia su cui il server web resta in ascolto (default `127.0.0.1`; impostare `0.0.0.0` per l'accesso in rete locale) |
| `SSL`, `SSL_PORT`, `SSL_DIR` | HTTPS autofirmato opzionale, generato da `web/scripts/generate-ssl.sh` |

## Utilizzo

Al primo avvio, `Setup.tsx` guida la creazione del vault: scelta di una password principale, registrazione facoltativa di una chiave di sicurezza hardware o di un TOTP, e il daemon crea un database SQLCipher cifrato oltre a un file di supporto in chiaro che registra solo ciò di cui la pagina di accesso ha bisogno (quali metodi MFA sono configurati, se l'accesso con password è anche solo abilitato), in modo che nulla debba essere decifrato prima che vi siate autenticati.

Da lì:

- Organizzate le credenziali in cartelle, aggiungete campi personalizzati e generate password robuste direttamente sul posto
- Attivate la modalità coercizione e la modalità viaggio dalle Impostazioni se volete poter presentare uno stato sicuro e plausibile sotto coercizione o all'attraversamento di una frontiera
- Eseguite il monitor di violazioni integrato per verificare le password salvate rispetto a una copia locale e offline di password compromesse note, senza alcuna richiesta in uscita per ogni password
- Esportate un file `.p2w` per il backup, o importate da un altro gestore di password, senza mai lasciare il vostro computer

## Sviluppo

Struttura del repository:

```
PWDnow/
├── daemon/     Daemon del vault in Rust. Tutta la crittografia risiede qui.
├── web/        Frontend React 19 + Express e proxy IPC.
├── monitor/    Processo Rust indipendente di monitoraggio e rilevamento perdite di memoria.
├── deploy/     Unità systemd, profilo AppArmor, configurazione Nginx, Makefile.
├── proto/      Definizioni gRPC/protobuf condivise tra daemon e web.
└── hibp/       Script che costruisce il filtro di Cuckoo HIBP offline.
```

Consultate [`CLAUDE.md`](../../CLAUDE.md) per il riferimento architetturale completo usato dai collaboratori e dagli strumenti automatizzati, e [`web/CLAUDE.md`](../../web/CLAUDE.md) per le convenzioni specifiche del frontend, incluso il registro delle chiavi di localStorage, la checklist IPC per aggiungere un nuovo endpoint al daemon, e i confini crittografici che il frontend non deve mai oltrepassare.

## Test

```bash
# Daemon
cd daemon && cargo test
cargo test -- <test_name>       # eseguire un singolo test

# Test unitari web
cd web && npm run test
npx vitest run src/utils/crypto.test.ts   # singolo file

# End-to-end (Playwright)
cd web && npx playwright test
npx playwright test e2e/comprehensive-platform.spec.ts   # percorso di regressione completo
```

L'integrazione continua esegue test unitari, test end-to-end, verifica delle dipendenze, test di mutazione e test di caos a ogni push e pull request. `web/e2e/comprehensive-platform.spec.ts` è il gate di regressione: percorre l'autenticazione (percorsi di successo e fallimento), la navigazione, le operazioni CRUD su cartelle e credenziali, la modalità coercizione e la distruzione dell'account, e deve superarlo prima che venga rilasciata qualsiasi modifica al frontend o all'autenticazione.

## Distribuzione

Per qualsiasi utilizzo oltre una singola macchina locale, mettete Nginx davanti al processo Express:

- `deploy/nginx/vault.conf` gestisce la terminazione TLS, HSTS e il rate limiting. Nginx non deve impostare una propria intestazione Content-Security-Policy, poiché il server Express inietta un nonce nuovo a ogni richiesta.
- `deploy/vault-daemon.service` esegue il daemon sotto un utente di sistema dedicato `vault`, con `MemorySwapMax=0`, `NoNewPrivileges`, `PrivateTmp`, e solo la capability `CAP_IPC_LOCK` necessaria per il blocco della memoria.
- `deploy/apparmor.d/vault-daemon` confina l'accesso del daemon al filesystem e alle capability a livello di kernel, e si applica senza modifiche sia su host `x86_64` sia `aarch64`.

`make install` (oppure `install.sh` per un'installazione guidata completa) collega tutto questo, incluso il caricamento del profilo AppArmor e l'abilitazione delle unità systemd.

## Politica di sicurezza

PWDnow gestisce credenziali, quindi una segnalazione di vulnerabilità qui conta più che nella maggior parte dei progetti. Se trovate un problema di sicurezza, non aprite un ticket pubblico. Utilizzate invece la segnalazione privata di vulnerabilità di GitHub per questo repository, oppure contattate direttamente i manutentori. Includete dettagli sufficienti per riprodurre il problema e, se possibile, una valutazione dell'impatto. Confermeremo la ricezione tempestivamente e accrediteremo chi lo desidera una volta pubblicata la correzione.

## Contribuire

Ticket e pull request sono benvenuti. Prima di inviare una modifica:

- Eseguite `make lint` (`cargo clippy -D warnings` e `tsc --noEmit`) e `make test`
- Per le modifiche al frontend o all'autenticazione, eseguite la suite di regressione Playwright completa
- Mantenete le modifiche crittografiche solo nel daemon; il livello web non deve mai ottenere accesso al materiale chiave come effetto collaterale di una modifica a una funzionalità
- Seguite le convenzioni descritte in `CLAUDE.md` e `web/CLAUDE.md`

## Licenza

PWDnow è distribuito con [licenza MIT](../../LICENSE).
