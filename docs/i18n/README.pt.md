<div align="center">

# PWDnow

Gerenciador de senhas de conhecimento zero, local antes de tudo

[![CI](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml)
[![Security Audit](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml)
[![Coverage](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml)
[![Mutation Testing](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

[Reportar um problema](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[Sugerir uma funcionalidade](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[Política de segurança](#politica-de-seguranca)

</div>

<div align="center">

**Ler em outro idioma**

| | | | |
|---|---|---|---|
| [English](../../README.md) | [Français](README.fr.md) | [Español](README.es.md) | [Deutsch](README.de.md) |
| [Italiano](README.it.md) | Português | [Русский](README.ru.md) | [العربية](README.ar.md) |
| [हिन्दी](README.hi.md) | [中文](README.zh.md) | [日本語](README.ja.md) | [한국어](README.ko.md) |
| [Bahasa Indonesia](README.id.md) | | | |

</div>

---

## Sobre

PWDnow é um gerenciador de senhas construído sobre uma premissa simples: nem o servidor, nem o navegador, nem a rede entre eles devem jamais ver um segredo em texto simples. Todas as operações criptográficas são executadas dentro de um daemon dedicado em Rust, instalado na mesma máquina onde o cofre reside. A interface web, seja aberta localmente ou servida a um navegador, troca com esse daemon apenas blocos de dados criptografados e opacos. Não há sincronização em nuvem por padrão, nenhuma telemetria, e nenhum fornecedor que possa ser obrigado a entregar seus dados, simplesmente porque nunca os possui.

O projeto é dividido em duas camadas que se comunicam através de um canal IPC local:

- **Daemon do cofre** (`daemon/`), escrito em Rust: derivação de chaves, criptografia, descriptografia, armazenamento SQLCipher, bloqueio de memória e apagamento seguro. É a única parte do sistema que chega a manipular uma chave ou uma credencial em texto simples.
- **Interface web** (`web/`), uma aplicação de página única em React 19 servida por um processo Express: renderiza a interface, encaminha requisições criptografadas ao daemon por meio de um socket Unix, e nunca retém material de chave fora de um token de sessão efêmero, mantido apenas em memória.

O PWDnow pode funcionar inteiramente offline em uma única máquina, ou ser implantado atrás do Nginx com TLS para acesso em rede local ou em servidor autogerenciado. Em qualquer caso, o limite de confiança permanece o mesmo: sua senha mestra e seus dados nunca saem da memória protegida do daemon.

## Sumário

- [Funcionalidades](#funcionalidades)
- [Arquitetura](#arquitetura)
- [Modelo de segurança](#modelo-de-seguranca)
- [Plataformas suportadas](#plataformas-suportadas)
- [Primeiros passos](#primeiros-passos)
  - [Instalação rápida](#instalacao-rapida)
  - [Compilação a partir do código-fonte](#compilacao-a-partir-do-codigo-fonte)
  - [Configuração](#configuracao)
- [Uso](#uso)
- [Desenvolvimento](#desenvolvimento)
- [Testes](#testes)
- [Implantação](#implantacao)
- [Política de segurança](#politica-de-seguranca)
- [Contribuindo](#contribuindo)
- [Licença](#licenca)

## Funcionalidades

**Cofre principal**
- Organização de credenciais por pastas, com reordenação por arrastar e soltar
- Armazenamento por credencial de senha, segredo TOTP, notas e campos personalizados
- Pontuação de robustez de senhas, detecção de reutilização e detecção de senhas comuns
- Verificação de vazamentos offline, usando um filtro Cuckoo local construído a partir do corpus de senhas comprometidas do Have I Been Pwned, sem chamada de rede a cada verificação
- Visão de titulares de ativos: uma lista consolidada de cada endereço de e-mail, número de telefone e chave de segurança física registrados entre suas credenciais

**Autenticação e MFA**
- Suporte a WebAuthn e FIDO2 para chaves de segurança físicas e autenticadores de plataforma (Touch ID, Windows Hello)
- Geração TOTP (RFC 6238) e HOTP (RFC 4226), com proteção contra repetição
- Login sem senha por meio de passkeys sincronizadas ou vinculadas ao dispositivo
- Aplicação de MFA configurável por conta

**Modos de segurança**
- Modo coação: desbloquear com uma senha alternativa designada aciona um apagamento forense em vez de conceder acesso
- Modo viagem: oculta um subconjunto escolhido de credenciais atrás de uma senha separada antes de atravessar uma fronteira ou entregar um dispositivo
- Bloqueio com atraso exponencial após tentativas de desbloqueio malsucedidas repetidas
- Acesso de emergência: conceda a um contato de confiança acesso com atraso temporal ao seu cofre caso fique inacessível

**Importação e exportação**
- Formato nativo `.p2w`: uma exportação criptografada com AEAD duplo, com preenchimento e ofuscação de metadados, projetada para resistir a adulteração offline e análise de tráfego
- Exportação e importação em JSON simples, CSV e XML compatível com KeePass
- Importação a partir de exportações do Bitwarden, 1Password (CSV, 1PUX) e NordPass

**Criptografia pós-quântica e de nível normativo**
- Encapsulamento de chave híbrido X25519 + ML-KEM-768/1024 (ativado por padrão, não uma opção separada a ser habilitada)
- Assinaturas pós-quânticas ML-DSA-87
- Derivação de chave Argon2id, criptografia autenticada AES-256-GCM e XChaCha20-Poly1305
- Modo estrito CNSA 2.0 opcional, que restringe o daemon ao conjunto de algoritmos de segurança nacional comercial da NSA (HKDF-SHA-384, PBKDF2-SHA-512, e remoção de BLAKE3, SHA3, XChaCha20, Ed25519 e X25519 dos caminhos de código ativos)

## Arquitetura

```
┌─────────────────────────────┐        socket Unix        ┌──────────────────────────────┐
│  Interface web (web/)       │  msgpack sobre /run/...   │  Daemon do cofre             │
│  React 19 + Express         │ ─────────────────────────▶│  (daemon/)                   │
│  Interface de conhecimento   │◀─────────────────────────  │  Rust, SQLCipher, mlock()   │
│  zero, apenas token de       │      respostas             │  Argon2id, AES-256-GCM,     │
│  sessão, sem chaves          │      criptografadas        │  XChaCha20-Poly1305,        │
└─────────────────────────────┘                            │  KEM híbrido pós-quântico    │
                                                             └──────────────────────────────┘
```

O daemon expõe um protocolo de requisições e respostas fortemente tipado (`daemon/src/ipc/protocol.rs`), transportado como quadros MessagePack sobre um socket Unix. Cada requisição autenticada carrega um token de sessão que o daemon valida antes de acessar o banco de dados. O daemon também verifica a identidade do processo que se conecta em nível de sistema operacional (`SO_PEERCRED`), de modo que somente o proxy web confiável, executado sob o usuário de sistema correto, consiga alcançá-lo.

A camada web nunca recebe uma chave mestra, uma chave de criptografia de chave, uma chave mestra do cofre ou uma chave de criptografia de dados, em nenhuma forma. Ela recebe texto cifrado e o encaminha. Um daemon de monitoramento complementar (`monitor/`) acompanha o crescimento de memória, o uso de disco e a saúde dos processos de forma independente do próprio daemon do cofre, de modo que um vazamento de memória ou um processo travado seja detectado e sinalizado em vez de degradar o serviço silenciosamente.

O detalhamento técnico completo, incluindo a hierarquia de derivação de chaves, a especificação do formato de arquivo P2W e o modelo de ameaças, está documentado em [`architecture.md`](../../architecture.md).

## Modelo de segurança

O PWDnow parte do princípio de que a rede, o processo do navegador e o sistema operacional hospedeiro são todos potencialmente hostis, e projeta sua arquitetura em função dessa suposição, em vez de uma mais favorável.

- **Conhecimento zero por construção**: o navegador não pode vazar o que nunca teve. Chaves mestras e chaves derivadas existem apenas dentro do espaço de memória do daemon.
- **Proteção de memória**: a chave mestra do cofre é mantida em uma região de memória bloqueada (`mlock`), selada com `mprotect(PROT_NONE)` enquanto ociosa, e apagada com a crate `zeroize` assim que deixa de ser necessária.
- **Criptografia em repouso**: o banco de dados do cofre é criptografado de ponta a ponta com SQLCipher. As exportações usam AEAD duplo (uma camada interna AES-256-GCM e uma camada externa XChaCha20-Poly1305), com o cabeçalho vinculado a ambas as tags de autenticação.
- **Verificação independente**: o projeto executa continuamente testes de mutação e testes de caos em sua integração contínua, além das suítes usuais de testes unitários e de ponta a ponta, especificamente para detectar testes que passam sem realmente verificar o comportamento que afirmam cobrir.

Se encontrar uma vulnerabilidade, consulte a [Política de segurança](#politica-de-seguranca) antes de abrir um ticket público.

## Plataformas suportadas

O PWDnow é desenvolvido e testado principalmente no **Ubuntu 26.04 LTS (Resolute)**. O instalador também detecta e suporta:

- Debian e distribuições derivadas do Debian (Ubuntu, Linux Mint, Pop!_OS, Zorin, Kali)
- Fedora e distribuições da família RHEL (Fedora, RHEL, CentOS, Rocky Linux, AlmaLinux)

Tanto `x86_64` quanto `aarch64` são suportados pela toolchain Rust. Outras distribuições Linux podem funcionar, mas não fazem parte da matriz de testes regular. Atualmente não existe build para macOS ou Windows.

## Primeiros passos

### Instalação rápida

```bash
git clone https://github.com/PWDnow/PWDnow-password-manager.git
cd PWDnow
./install.sh
```

O instalador detecta sua distribuição, verifica dependências ausentes e oferece instalá-las, audita sua configuração SSH, verifica conflitos de porta, compila o daemon e o frontend web a partir do código-fonte, e instala ambos como serviços systemd executados sob usuários de sistema dedicados e sem privilégios. Nada é instalado com privilégios elevados além do que systemd, AppArmor e a instalação de pacotes exigem, e cada etapa privilegiada é exibida antes de ser executada.

### Compilação a partir do código-fonte

Requisitos: Node.js 24 ou superior, Rust 1.94 ou superior (fixado em `daemon/rust-toolchain.toml`), `protoc`, e os cabeçalhos de desenvolvimento para `libsodium`, `sqlcipher` e `libfido2`.

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

Ou, a partir de `deploy/`:

```bash
make build          # daemon + web, modo release
make test            # cargo test + vitest
make install          # instala o binário, as unidades systemd, o perfil AppArmor e a configuração do nginx (requer sudo)
```

O encapsulamento de chave pós-quântico está ativado por padrão. `make build-pq` e `cargo build --release --features pq-hybrid-1024` são mantidos como aliases explícitos dessa mesma compilação padrão, por clareza e compatibilidade com documentação anterior. Use `--features cnsa-strict` para o modo estrito CNSA 2.0.

### Configuração

Copie `web/.env.example` para `web/.env` e ajuste conforme necessário:

| Variável | Finalidade |
|---|---|
| `DAEMON_GRPC_ADDR` | Endereço usado pela camada web para alcançar o daemon (padrão `127.0.0.1:50051`) |
| `VAULT_ORIGIN` | Origem de navegador permitida em produção, usada nas verificações de origem do WebSocket |
| `BIND_HOST` | Interface em que o servidor web escuta (padrão `127.0.0.1`; defina `0.0.0.0` para acesso em rede local) |
| `SSL`, `SSL_PORT`, `SSL_DIR` | HTTPS autoassinado opcional, gerado por `web/scripts/generate-ssl.sh` |

## Uso

Na primeira execução, `Setup.tsx` conduz a criação do cofre: escolha de uma senha mestra, registro opcional de uma chave de segurança física ou de um TOTP, e o daemon cria um banco de dados SQLCipher criptografado além de um arquivo auxiliar em texto simples que registra apenas o que a página de login precisa (quais métodos de MFA estão configurados, se o login por senha sequer está habilitado), de modo que nada precise ser descriptografado antes de você ter se autenticado.

A partir daí:

- Organize credenciais em pastas, adicione campos personalizados e gere senhas robustas diretamente no local
- Ative o modo coação e o modo viagem em Configurações se quiser poder apresentar um estado seguro e plausível sob coação ou ao atravessar uma fronteira
- Execute o monitor de vazamentos integrado para verificar suas senhas salvas contra uma cópia local e offline de senhas comprometidas conhecidas, sem nenhuma consulta de saída por senha
- Exporte um arquivo `.p2w` para backup, ou importe de outro gerenciador de senhas, sem nunca sair da sua máquina

## Desenvolvimento

Estrutura do repositório:

```
PWDnow/
├── daemon/     Daemon do cofre em Rust. Toda a criptografia vive aqui.
├── web/        Frontend React 19 + Express e proxy IPC.
├── monitor/    Processo Rust independente de monitoramento e detecção de vazamento de memória.
├── deploy/     Unidades systemd, perfil AppArmor, configuração Nginx, Makefile.
├── proto/      Definições gRPC/protobuf compartilhadas entre daemon e web.
└── hibp/       Script que constrói o filtro de Cuckoo HIBP offline.
```

Consulte [`CLAUDE.md`](../../CLAUDE.md) para a referência arquitetural completa usada por colaboradores e ferramentas automatizadas, e [`web/CLAUDE.md`](../../web/CLAUDE.md) para convenções específicas do frontend, incluindo o registro de chaves do localStorage, a lista de verificação IPC para adicionar um novo endpoint ao daemon, e os limites criptográficos que o frontend nunca deve cruzar.

## Testes

```bash
# Daemon
cd daemon && cargo test
cargo test -- <test_name>       # executar um único teste

# Testes unitários web
cd web && npm run test
npx vitest run src/utils/crypto.test.ts   # arquivo único

# Ponta a ponta (Playwright)
cd web && npx playwright test
npx playwright test e2e/comprehensive-platform.spec.ts   # percurso completo de regressão
```

A integração contínua executa testes unitários, testes de ponta a ponta, auditoria de dependências, testes de mutação e testes de caos a cada push e pull request. `web/e2e/comprehensive-platform.spec.ts` é o portão de regressão: percorre autenticação (caminhos de sucesso e falha), navegação, operações CRUD de pastas e credenciais, modo coação e destruição de conta, e deve passar antes de qualquer mudança de frontend ou autenticação ser lançada.

## Implantação

Para qualquer uso além de uma única máquina local, coloque o Nginx à frente do processo Express:

- `deploy/nginx/vault.conf` cuida da terminação TLS, HSTS e limitação de taxa. O Nginx não deve definir seu próprio cabeçalho Content-Security-Policy, já que o servidor Express injeta um nonce novo a cada requisição.
- `deploy/vault-daemon.service` executa o daemon sob um usuário de sistema dedicado `vault`, com `MemorySwapMax=0`, `NoNewPrivileges`, `PrivateTmp`, e apenas a capability `CAP_IPC_LOCK` necessária para o bloqueio de memória.
- `deploy/apparmor.d/vault-daemon` confina o acesso do daemon ao sistema de arquivos e às capabilities em nível de kernel, e se aplica sem modificações tanto em hosts `x86_64` quanto `aarch64`.

`make install` (ou `install.sh` para uma instalação guiada completa) conecta tudo isso, incluindo o carregamento do perfil AppArmor e a habilitação das unidades systemd.

## Política de segurança

O PWDnow lida com credenciais, então um relatório de vulnerabilidade aqui importa mais do que na maioria dos projetos. Se encontrar um problema de segurança, não abra um ticket público. Em vez disso, use o relatório privado de vulnerabilidades do GitHub para este repositório, ou entre em contato diretamente com os mantenedores. Inclua detalhes suficientes para reproduzir o problema e, se possível, uma avaliação do impacto. Confirmaremos o recebimento prontamente e creditaremos quem desejar assim que a correção for lançada.

## Contribuindo

Tickets e pull requests são bem-vindos. Antes de enviar uma alteração:

- Execute `make lint` (`cargo clippy -D warnings` e `tsc --noEmit`) e `make test`
- Para alterações de frontend ou autenticação, execute a suíte completa de regressão Playwright
- Mantenha alterações criptográficas apenas no daemon; a camada web nunca deve obter acesso a material de chave como efeito colateral de uma mudança de funcionalidade
- Siga as convenções descritas em `CLAUDE.md` e `web/CLAUDE.md`

## Licença

O PWDnow é distribuído sob a [licença MIT](../../LICENSE).
