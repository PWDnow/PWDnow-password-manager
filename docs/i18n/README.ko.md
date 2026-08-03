<div align="center">

# PWDnow

제로 지식, 로컬 우선 비밀번호 관리자

[![CI](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml)
[![Security Audit](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml)
[![Coverage](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml)
[![Mutation Testing](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

[버그 신고](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[기능 제안](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[보안 정책](#보안-정책)

</div>

<div align="center">

**다른 언어로 보기**

| | | | |
|---|---|---|---|
| [English](../../README.md) | [Français](README.fr.md) | [Español](README.es.md) | [Deutsch](README.de.md) |
| [Italiano](README.it.md) | [Português](README.pt.md) | [Русский](README.ru.md) | [العربية](README.ar.md) |
| [हिन्दी](README.hi.md) | [中文](README.zh.md) | [日本語](README.ja.md) | 한국어 |
| [Bahasa Indonesia](README.id.md) | | | |

</div>

---

## 소개

PWDnow는 단순한 원칙 위에 구축된 비밀번호 관리자입니다. 서버도, 브라우저도, 그 사이의 네트워크도 평문 상태의 비밀 정보를 절대 볼 수 없어야 한다는 원칙입니다. 모든 암호화 연산은 볼트가 위치한 바로 그 기기에 설치된 전용 Rust 데몬 내부에서 실행됩니다. 웹 인터페이스는 로컬에서 열리든 브라우저로 제공되든 관계없이, 해당 데몬과 오직 불투명하게 암호화된 데이터 블록만을 주고받습니다. 기본적으로 클라우드 동기화도, 원격 측정도 없으며, 데이터를 넘기도록 강제될 수 있는 벤더도 존재하지 않습니다. 벤더가 애초에 그 데이터를 가진 적이 없기 때문입니다.

이 프로젝트는 로컬 IPC 채널을 통해 통신하는 두 개의 계층으로 나뉩니다.

- **볼트 데몬** (`daemon/`), Rust로 작성됨: 키 파생, 암호화, 복호화, SQLCipher 저장소, 메모리 잠금, 안전한 삭제를 담당합니다. 시스템에서 평문 키나 평문 자격 증명을 다루는 유일한 부분입니다.
- **웹 인터페이스** (`web/`), Express 프로세스가 제공하는 React 19 단일 페이지 애플리케이션: 화면을 렌더링하고, 암호화된 요청을 유닉스 도메인 소켓을 통해 데몬으로 전달하며, 메모리에만 존재하는 수명이 짧은 세션 토큰을 제외하고는 키 자료를 절대 보유하지 않습니다.

PWDnow는 단일 기기에서 완전히 오프라인으로 실행할 수도 있고, LAN 또는 자체 호스팅 서버 접근을 위해 TLS를 적용한 Nginx 뒤에 배포할 수도 있습니다. 어느 경우든 신뢰 경계는 동일합니다. 마스터 비밀번호와 데이터는 데몬의 보호된 메모리를 절대 벗어나지 않습니다.

## 목차

- [기능](#기능)
- [아키텍처](#아키텍처)
- [보안 모델](#보안-모델)
- [지원 플랫폼](#지원-플랫폼)
- [시작하기](#시작하기)
  - [빠른 설치](#빠른-설치)
  - [소스에서 빌드하기](#소스에서-빌드하기)
  - [설정](#설정)
- [사용법](#사용법)
- [개발](#개발)
- [테스트](#테스트)
- [배포](#배포)
- [보안 정책](#보안-정책)
- [기여하기](#기여하기)
- [라이선스](#라이선스)

## 기능

**핵심 볼트**
- 드래그로 순서를 변경할 수 있는 폴더 기반 자격 증명 관리
- 자격 증명별로 비밀번호, TOTP 시크릿, 메모, 사용자 지정 필드 저장
- 비밀번호 강도 평가, 재사용 감지, 흔히 쓰이는 비밀번호 감지
- Have I Been Pwned의 유출 비밀번호 데이터를 기반으로 로컬에서 구축한 Cuckoo 필터를 이용한 오프라인 유출 확인. 확인할 때마다 네트워크 호출이 필요하지 않습니다
- 자산 보유자 보기: 자격 증명 전반에 등록된 모든 이메일 주소, 전화번호, 하드웨어 보안 키를 통합해 보여주는 목록

**인증 및 다중 인증(MFA)**
- 하드웨어 보안 키와 플랫폼 인증기(Touch ID, Windows Hello)를 위한 WebAuthn 및 FIDO2 지원
- 재전송 방지 기능을 갖춘 TOTP(RFC 6238) 및 HOTP(RFC 4226) 생성
- 동기화되거나 기기에 바인딩된 패스키를 통한 비밀번호 없는 로그인
- 계정별로 설정 가능한 MFA 강제 적용

**보안 모드**
- 협박 모드: 지정된 대체 비밀번호로 잠금을 해제하면 접근을 허용하는 대신 포렌식 삭제가 실행됩니다
- 여행 모드: 국경을 넘거나 기기를 넘겨주기 전에 선택한 일부 자격 증명을 별도의 비밀번호 뒤에 숨깁니다
- 반복된 잠금 해제 실패 후 지수적으로 지연되는 잠금
- 긴급 접근: 연락이 닿지 않을 경우를 대비해 신뢰하는 연락처에게 시간이 지연된 볼트 접근 권한을 부여합니다

**가져오기 및 내보내기**
- 자체 `.p2w` 형식: 오프라인 변조와 트래픽 분석에 저항하도록 설계된, 이중 AEAD 암호화와 패딩, 메타데이터 난독화를 적용한 내보내기 형식
- 일반 JSON, CSV, KeePass 호환 XML로 내보내기 및 가져오기
- Bitwarden, 1Password(CSV, 1PUX), NordPass에서 내보낸 파일 가져오기

**포스트 양자 및 표준 수준 암호화**
- 하이브리드 X25519 + ML-KEM-768/1024 키 캡슐화(기본적으로 활성화되며, 별도로 켜야 하는 옵션이 아닙니다)
- ML-DSA-87 포스트 양자 서명
- Argon2id 키 파생, AES-256-GCM 및 XChaCha20-Poly1305 인증 암호화
- 선택적인 CNSA 2.0 엄격 모드. 데몬을 NSA의 상용 국가 보안 알고리즘 스위트로 제한합니다(HKDF-SHA-384, PBKDF2-SHA-512 사용, 활성 코드 경로에서 BLAKE3, SHA3, XChaCha20, Ed25519, X25519 제거)

## 아키텍처

```
┌─────────────────────────────┐        유닉스 소켓         ┌──────────────────────────────┐
│  웹 인터페이스 (web/)        │  /run/... 위의 msgpack    │  볼트 데몬 (daemon/)          │
│  React 19 + Express          │ ─────────────────────────▶│  Rust, SQLCipher, mlock()    │
│  제로 지식 인터페이스,       │◀─────────────────────────  │  Argon2id, AES-256-GCM,      │
│  세션 토큰만 보유, 키 없음    │      암호화된 응답          │  XChaCha20-Poly1305,         │
└─────────────────────────────┘                            │  하이브리드 PQ KEM             │
                                                             └──────────────────────────────┘
```

데몬은 유닉스 도메인 소켓을 통해 MessagePack 프레임으로 전송되는, 강하게 타입이 지정된 요청/응답 프로토콜(`daemon/src/ipc/protocol.rs`)을 제공합니다. 인증된 모든 요청에는 세션 토큰이 포함되며, 데몬은 데이터베이스에 접근하기 전에 이를 검증합니다. 데몬은 또한 OS 수준(`SO_PEERCRED`)에서 연결하는 프로세스의 신원을 확인하므로, 올바른 시스템 사용자로 실행 중인 신뢰된 웹 프록시만이 데몬에 접근할 수 있습니다.

웹 계층은 어떤 형태로도 마스터 키, 키 암호화 키, 볼트 마스터 키, 데이터 암호화 키를 받는 일이 없습니다. 오직 암호문을 받아 전달할 뿐입니다. 함께 동작하는 모니터링 데몬(`monitor/`)은 볼트 데몬 자체와 독립적으로 메모리 증가, 디스크 사용량, 프로세스 상태를 추적하므로, 메모리 누수나 멈춘 프로세스가 서비스를 조용히 저하시키는 대신 감지되어 경고를 발생시킵니다.

키 파생 계층 구조, P2W 파일 형식 사양, 위협 모델을 포함한 전체 기술 세부 사항은 [`architecture.md`](../../architecture.md)에 문서화되어 있습니다.

## 보안 모델

PWDnow는 네트워크, 브라우저 프로세스, 호스트 운영체제 모두가 잠재적으로 적대적이라는 전제를 두고, 더 우호적인 기본값이 아니라 이 전제에 맞춰 아키텍처를 설계합니다.

- **구조적으로 보장되는 제로 지식**: 브라우저는 애초에 가진 적 없는 것을 유출할 수 없습니다. 마스터 키와 파생 키는 오직 데몬의 주소 공간 안에만 존재합니다.
- **메모리 보호**: 볼트 마스터 키는 잠긴 메모리 영역(`mlock`)에 보관되며, 유휴 상태에서는 `mprotect(PROT_NONE)`으로 봉인되고, 더 이상 필요하지 않게 되는 즉시 `zeroize` 크레이트로 삭제됩니다.
- **저장 시 암호화**: 볼트 데이터베이스는 SQLCipher로 종단 간 암호화됩니다. 내보내기는 이중 AEAD를 사용하며(내부 AES-256-GCM 계층과 외부 XChaCha20-Poly1305 계층), 헤더는 두 인증 태그 모두에 결합됩니다.
- **독립적인 검증**: 이 프로젝트는 일반적인 단위 테스트 및 종단 간 테스트 스위트에 더해, CI에서 지속적으로 뮤테이션 테스트와 카오스 테스트를 실행합니다. 이는 실제로는 검증하지 못하면서 통과하는 척하는 테스트를 잡아내기 위한 것입니다.

취약점을 발견하셨다면, 공개 이슈를 등록하기 전에 [보안 정책](#보안-정책)을 먼저 확인해 주세요.

## 지원 플랫폼

PWDnow는 주로 **Ubuntu 26.04 LTS(Resolute)**에서 개발 및 테스트됩니다. 설치 스크립트는 다음도 감지하여 지원합니다.

- Debian 및 Debian 파생 배포판(Ubuntu, Linux Mint, Pop!_OS, Zorin, Kali)
- Fedora 및 RHEL 계열 배포판(Fedora, RHEL, CentOS, Rocky Linux, AlmaLinux)

Rust 툴체인은 `x86_64`와 `aarch64`를 모두 지원합니다. 다른 리눅스 배포판에서도 동작할 수 있지만 정기 테스트 매트릭스에는 포함되어 있지 않습니다. 현재 macOS나 Windows용 빌드는 존재하지 않습니다.

## 시작하기

### 빠른 설치

```bash
git clone https://github.com/PWDnow/PWDnow-password-manager.git
cd PWDnow
./install.sh
```

설치 스크립트는 배포판을 감지하고, 누락된 의존성을 확인해 설치를 제안하며, SSH 설정을 점검하고, 포트 충돌을 확인하고, 소스에서 데몬과 웹 프론트엔드를 빌드한 다음, 전용 비특권 시스템 사용자 아래에서 실행되는 systemd 서비스로 둘 다 설치합니다. systemd, AppArmor, 패키지 설치에 필요한 수준을 넘어서는 상승된 권한으로 설치되는 것은 아무것도 없으며, 권한이 필요한 각 단계는 실행되기 전에 화면에 표시됩니다.

### 소스에서 빌드하기

요구 사항: Node.js 24 이상, Rust 1.94 이상(`daemon/rust-toolchain.toml`에 고정됨), `protoc`, 그리고 `libsodium`, `sqlcipher`, `libfido2`의 개발용 헤더.

```bash
# 데몬
cd daemon
cargo build --release
cargo test

# 웹
cd web
npm install
npm run build
npm start
```

또는 `deploy/`에서:

```bash
make build          # 데몬 + 웹, 릴리스 모드
make test            # cargo test + vitest
make install          # 바이너리, systemd 유닛, AppArmor 프로필, nginx 설정 설치(sudo 필요)
```

포스트 양자 키 캡슐화는 기본적으로 활성화되어 있습니다. `make build-pq`와 `cargo build --release --features pq-hybrid-1024`는 명확성과 이전 문서와의 호환성을 위해 동일한 기본 빌드의 명시적 별칭으로 남아 있습니다. CNSA 2.0 엄격 모드에는 `--features cnsa-strict`를 사용하세요.

### 설정

`web/.env.example`을 `web/.env`로 복사한 뒤 필요에 따라 조정하세요.

| 변수 | 용도 |
|---|---|
| `DAEMON_GRPC_ADDR` | 웹 계층이 데몬에 접근할 때 사용하는 주소(기본값 `127.0.0.1:50051`) |
| `VAULT_ORIGIN` | 프로덕션에서 허용되는 브라우저 출처, WebSocket 출처 검사에 사용 |
| `BIND_HOST` | 웹 서버가 바인딩되는 인터페이스(기본값 `127.0.0.1`; LAN 접근을 원하면 `0.0.0.0`으로 설정) |
| `SSL`, `SSL_PORT`, `SSL_DIR` | `web/scripts/generate-ssl.sh`로 생성되는 선택적 자체 서명 HTTPS |

## 사용법

처음 실행하면 `Setup.tsx`가 볼트 생성을 안내합니다. 마스터 비밀번호를 선택하고, 원한다면 하드웨어 보안 키나 TOTP를 등록하며, 데몬은 암호화된 SQLCipher 데이터베이스와 함께, 로그인 페이지에 필요한 정보(어떤 MFA 방식이 설정되어 있는지, 비밀번호 로그인이 애초에 활성화되어 있는지)만 기록하는 평문 사이드카 파일을 생성합니다. 덕분에 인증을 마치기 전에는 아무것도 복호화할 필요가 없습니다.

이후에는 다음을 할 수 있습니다.

- 자격 증명을 폴더로 정리하고, 사용자 지정 필드를 추가하고, 그 자리에서 바로 강력한 비밀번호를 생성합니다
- 협박을 받는 상황이나 국경을 넘을 때 그럴듯하고 안전한 상태를 보여주고 싶다면 설정에서 협박 모드와 여행 모드를 활성화합니다
- 내장된 유출 모니터를 실행해 저장된 비밀번호를 로컬에 오프라인으로 보관된 알려진 유출 비밀번호와 대조합니다. 비밀번호마다 외부로 나가는 조회는 발생하지 않습니다
- 백업을 위해 `.p2w` 파일을 내보내거나, 다른 비밀번호 관리자에서 가져옵니다. 이 모든 과정은 사용자의 기기를 벗어나지 않습니다

## 개발

저장소 구조:

```
PWDnow/
├── daemon/     Rust로 작성된 볼트 데몬. 모든 암호화 로직이 여기 있습니다.
├── web/        React 19 + Express 프론트엔드와 IPC 프록시.
├── monitor/    상태 및 메모리 누수 모니터링을 위한 독립적인 Rust 프로세스.
├── deploy/     systemd 유닛, AppArmor 프로필, Nginx 설정, Makefile.
├── proto/      데몬과 웹이 공유하는 gRPC/protobuf 정의.
└── hibp/       오프라인 HIBP Cuckoo 필터를 빌드하는 스크립트.
```

기여자와 자동화 도구가 사용하는 전체 아키텍처 참조는 [`CLAUDE.md`](../../CLAUDE.md)를, localStorage 키 레지스트리, 새 데몬 엔드포인트를 추가할 때의 IPC 체크리스트, 프론트엔드가 절대 넘어서는 안 되는 암호화 경계를 포함한 프론트엔드 관련 규약은 [`web/CLAUDE.md`](../../web/CLAUDE.md)를 참고하세요.

## 테스트

```bash
# 데몬
cd daemon && cargo test
cargo test -- <test_name>       # 단일 테스트 실행

# 웹 단위 테스트
cd web && npm run test
npx vitest run src/utils/crypto.test.ts   # 단일 파일

# 종단 간 테스트(Playwright)
cd web && npx playwright test
npx playwright test e2e/comprehensive-platform.spec.ts   # 전체 회귀 테스트
```

CI는 push와 pull request가 있을 때마다 단위 테스트, 종단 간 테스트, 의존성 감사, 뮤테이션 테스트, 카오스 테스트를 실행합니다. `web/e2e/comprehensive-platform.spec.ts`는 회귀 게이트로, 인증(성공 및 실패 경로), 내비게이션, 폴더 및 자격 증명 CRUD, 협박 모드, 계정 파기 과정을 확인하며, 프론트엔드나 인증 관련 변경 사항을 배포하기 전에 반드시 통과해야 합니다.

## 배포

단일 로컬 기기를 넘어서는 용도라면 Express 프로세스 앞에 Nginx를 두세요.

- `deploy/nginx/vault.conf`는 TLS 종료, HSTS, 속도 제한을 처리합니다. Express 서버가 요청마다 새로운 nonce를 삽입하므로 Nginx가 자체 Content-Security-Policy 헤더를 설정해서는 안 됩니다.
- `deploy/vault-daemon.service`는 전용 시스템 사용자 `vault` 아래에서 데몬을 실행하며, `MemorySwapMax=0`, `NoNewPrivileges`, `PrivateTmp`와 메모리 잠금에 필요한 `CAP_IPC_LOCK` 권한만을 부여합니다.
- `deploy/apparmor.d/vault-daemon`은 커널 수준에서 데몬의 파일 시스템 및 권한 접근을 제한하며, `x86_64`와 `aarch64` 호스트 모두에 수정 없이 적용됩니다.

`make install`(또는 전체 안내식 설치를 위한 `install.sh`)이 AppArmor 프로필 로드와 systemd 유닛 활성화를 포함해 이 모든 것을 연결합니다.

## 보안 정책

PWDnow는 자격 증명을 다루기 때문에, 이곳에서의 취약점 보고는 대부분의 프로젝트보다 더 중요한 의미를 가집니다. 보안 문제를 발견하셨다면 공개 이슈를 등록하지 말아 주세요. 대신 이 저장소에 대한 GitHub의 비공개 취약점 보고 기능을 사용하거나, 메인테이너에게 직접 연락해 주세요. 문제를 재현할 수 있을 만큼 충분한 세부 정보와, 가능하다면 영향도 평가를 포함해 주세요. 저희는 신속하게 접수를 확인하며, 수정 사항이 배포된 이후 원하는 신고자에게 크레딧을 부여합니다.

## 기여하기

이슈와 풀 리퀘스트를 환영합니다. 변경 사항을 제출하기 전에:

- `make lint`(`cargo clippy -D warnings` 및 `tsc --noEmit`)와 `make test`를 실행하세요
- 프론트엔드나 인증 관련 변경 사항이라면 Playwright 전체 회귀 스위트를 실행하세요
- 암호화 관련 변경은 데몬 안에만 두세요. 웹 계층은 기능 변경의 부작용으로 키 자료에 접근할 수 있게 되어서는 절대 안 됩니다
- `CLAUDE.md`와 `web/CLAUDE.md`에 설명된 규약을 따르세요

## 라이선스

PWDnow는 [MIT 라이선스](../../LICENSE) 하에 공개됩니다.
