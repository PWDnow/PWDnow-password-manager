<div align="center">

# PWDnow

零知识、本地优先的密码管理器

[![CI](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml)
[![Security Audit](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml)
[![Coverage](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml)
[![Mutation Testing](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

[报告问题](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[提出功能建议](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[安全政策](#安全政策)

</div>

<div align="center">

**阅读其他语言版本**

| | | | |
|---|---|---|---|
| [English](../../README.md) | [Français](README.fr.md) | [Español](README.es.md) | [Deutsch](README.de.md) |
| [Italiano](README.it.md) | [Português](README.pt.md) | [Русский](README.ru.md) | [العربية](README.ar.md) |
| [हिन्दी](README.hi.md) | 中文 | [日本語](README.ja.md) | [한국어](README.ko.md) |
| [Bahasa Indonesia](README.id.md) | | | |

</div>

---

## 项目简介

PWDnow 是一款建立在简单前提之上的密码管理器：服务器、浏览器,以及两者之间的网络,都不应该看到明文形式的密钥。所有加密操作都在一个专用的 Rust 守护进程中运行,该进程安装在保险库所在的机器上。无论 Web 界面是在本地打开还是提供给浏览器访问,它与该守护进程之间只交换不透明的加密数据块。默认情况下没有云同步,没有遥测,也没有任何供应商能够被强制交出你的数据,因为供应商本来就从未拥有过这些数据。

项目分为两层,通过本地 IPC 通道进行通信:

- **保险库守护进程**(`daemon/`),使用 Rust 编写:负责密钥派生、加密、解密、基于 SQLCipher 的存储、内存锁定,以及安全擦除。这是系统中唯一会接触明文密钥或明文凭证的部分。
- **Web 界面**(`web/`),一个由 Express 进程提供服务的 React 19 单页应用:负责渲染界面,通过 Unix 域套接字将加密请求转发给守护进程,除了一个仅存在于内存中的短生命周期会话令牌外,从不保留任何密钥材料。

PWDnow 既可以完全离线运行在单台机器上,也可以部署在带有 TLS 的 Nginx 之后,以供局域网或自托管服务器访问。无论哪种方式,信任边界始终相同:你的主密码和数据永远不会离开守护进程受保护的内存。

## 目录

- [功能特性](#功能特性)
- [架构](#架构)
- [安全模型](#安全模型)
- [支持的平台](#支持的平台)
- [快速上手](#快速上手)
  - [快速安装](#快速安装)
  - [从源码构建](#从源码构建)
  - [配置](#配置)
- [使用方法](#使用方法)
- [开发](#开发)
- [测试](#测试)
- [部署](#部署)
- [安全政策](#安全政策)
- [参与贡献](#参与贡献)
- [许可证](#许可证)

## 功能特性

**核心保险库**
- 基于文件夹的凭证组织方式,支持拖拽重新排序
- 每条凭证均可存储密码、TOTP 密钥、备注和自定义字段
- 密码强度评分、重复使用检测,以及常见密码检测
- 基于本地构建的 Cuckoo 过滤器进行离线泄露检查,该过滤器基于 Have I Been Pwned 的密码语料库构建,每次检查无需网络请求
- 资产持有人视图:整合展示你所有凭证中登记的每一个电子邮件地址、电话号码和硬件安全密钥

**身份验证与多因素认证**
- 支持 WebAuthn 和 FIDO2,兼容硬件安全密钥和平台认证器(Touch ID、Windows Hello)
- 支持 TOTP(RFC 6238)和 HOTP(RFC 4226)生成,并具备重放保护
- 通过同步或设备绑定的通行密钥实现无密码登录
- 可按账户配置的多因素认证强制策略

**安全模式**
- 胁迫模式:使用指定的备用密码解锁时,会触发取证式擦除,而不是授予访问权限
- 旅行模式:在过境或交出设备之前,将选定的部分凭证隐藏在单独的密码之后
- 多次解锁失败后采用指数退避锁定机制
- 紧急访问:如果你失联,可授予受信任联系人延时访问你的保险库

**导入与导出**
- 原生 `.p2w` 格式:采用双重 AEAD 加密、填充与元数据混淆,专为抵御离线篡改和流量分析而设计的导出格式
- 支持导出与导入为纯 JSON、CSV,以及兼容 KeePass 的 XML 格式
- 支持从 Bitwarden、1Password(CSV、1PUX)以及 NordPass 的导出文件导入

**后量子与规范级加密**
- 混合 X25519 + ML-KEM-768/1024 密钥封装(默认开启,而非需要单独启用的选项)
- ML-DSA-87 后量子签名
- Argon2id 密钥派生,AES-256-GCM 与 XChaCha20-Poly1305 认证加密
- 可选的 CNSA 2.0 严格模式,将守护进程限制为美国国家安全局的商用国家安全算法套件(HKDF-SHA-384、PBKDF2-SHA-512,并从活跃代码路径中移除 BLAKE3、SHA3、XChaCha20、Ed25519 和 X25519)

## 架构

```
┌─────────────────────────────┐        Unix 套接字         ┌──────────────────────────────┐
│  Web 界面 (web/)             │  经由 /run/... 的 msgpack │  保险库守护进程                │
│  React 19 + Express          │ ─────────────────────────▶│  (daemon/)                    │
│  零知识界面,仅保留会话令牌,  │◀─────────────────────────  │  Rust, SQLCipher, mlock()    │
│  不保留任何密钥               │      加密响应              │  Argon2id, AES-256-GCM,      │
│                               │                            │  XChaCha20-Poly1305,         │
└─────────────────────────────┘                            │  混合后量子 KEM                │
                                                             └──────────────────────────────┘
```

守护进程通过 Unix 域套接字以 MessagePack 帧的形式,提供一套强类型的请求与响应协议(`daemon/src/ipc/protocol.rs`)。每个经过身份验证的请求都携带一个会话令牌,守护进程会在访问数据库之前对其进行校验。守护进程还会在操作系统层面(`SO_PEERCRED`)验证发起连接的进程身份,因此只有以正确系统用户身份运行的受信任 Web 代理才能访问它。

Web 层永远不会以任何形式接收到主密钥、密钥加密密钥、保险库主密钥或数据加密密钥。它只接收密文并转发出去。一个配套的监控守护进程(`monitor/`)独立于保险库守护进程本身,持续追踪内存增长、磁盘使用情况和进程健康状态,从而使内存泄漏或进程卡死能够被发现并发出告警,而不是让服务在无声无息中退化。

包括密钥派生层级、P2W 文件格式规范以及威胁模型在内的完整技术细节,记录在 [`architecture.md`](../../architecture.md) 中。

## 安全模型

PWDnow 假设网络、浏览器进程以及宿主操作系统都有潜在的敌意,并据此设计其架构,而不是基于更友好的默认假设。

- **构造层面的零知识**:浏览器无法泄露它从未拥有过的东西。主密钥和派生密钥只存在于守护进程的地址空间内。
- **内存保护**:保险库主密钥保存在一个被锁定的内存区域(`mlock`)中,空闲时通过 `mprotect(PROT_NONE)` 进行密封,一旦不再需要,便通过 `zeroize` crate 进行擦除。
- **静态加密**:保险库数据库通过 SQLCipher 实现端到端加密。导出文件采用双重 AEAD(内层为 AES-256-GCM,外层为 XChaCha20-Poly1305),并将文件头绑定到两个认证标签中。
- **独立验证**:除了常规的单元测试和端到端测试套件之外,该项目还在持续集成中持续运行变异测试和混沌测试,专门用于发现那些通过了测试却并未真正验证其所声称覆盖行为的测试用例。

如果你发现了安全漏洞,请在提交公开 issue 之前先查阅[安全政策](#安全政策)。

## 支持的平台

PWDnow 主要在 **Ubuntu 26.04 LTS(Resolute)**上进行开发和测试。安装脚本还能检测并支持以下系统:

- Debian 及其衍生发行版(Ubuntu、Linux Mint、Pop!_OS、Zorin、Kali)
- Fedora 及 RHEL 系发行版(Fedora、RHEL、CentOS、Rocky Linux、AlmaLinux)

Rust 工具链同时支持 `x86_64` 和 `aarch64` 架构。其他 Linux 发行版可能也能运行,但不在常规测试矩阵范围内。目前尚无 macOS 或 Windows 版本。

## 快速上手

### 快速安装

```bash
git clone https://github.com/PWDnow/PWDnow-password-manager.git
cd PWDnow
./install.sh
```

安装脚本会检测你的发行版,检查缺失的依赖并提供安装选项,审计你的 SSH 配置,检查端口冲突,从源码编译守护进程和 Web 前端,并将两者都安装为在专用、无特权系统用户下运行的 systemd 服务。除了 systemd、AppArmor 和软件包安装本身所需的权限之外,不会以更高权限安装任何内容,并且每一个需要提权的步骤在执行前都会展示出来。

### 从源码构建

前置要求:Node.js 24 或更高版本,Rust 1.94 或更高版本(在 `daemon/rust-toolchain.toml` 中固定),`protoc`,以及 `libsodium`、`sqlcipher` 和 `libfido2` 的开发头文件。

```bash
# 守护进程
cd daemon
cargo build --release
cargo test

# Web
cd web
npm install
npm run build
npm start
```

或者,在 `deploy/` 目录下执行:

```bash
make build          # 守护进程 + Web,发布模式
make test            # cargo test + vitest
make install          # 安装二进制文件、systemd 单元、AppArmor 配置文件和 nginx 配置(需要 sudo)
```

后量子密钥封装默认已启用。`make build-pq` 与 `cargo build --release --features pq-hybrid-1024` 作为同一默认构建的显式别名保留下来,以提高清晰度并兼容旧文档。使用 `--features cnsa-strict` 可启用 CNSA 2.0 严格模式。

### 配置

将 `web/.env.example` 复制为 `web/.env` 并按需调整:

| 变量 | 用途 |
|---|---|
| `DAEMON_GRPC_ADDR` | Web 层用于访问守护进程的地址(默认 `127.0.0.1:50051`) |
| `VAULT_ORIGIN` | 生产环境中允许的浏览器来源,用于 WebSocket 来源校验 |
| `BIND_HOST` | Web 服务器绑定的网络接口(默认 `127.0.0.1`;设置为 `0.0.0.0` 可开放局域网访问) |
| `SSL`、`SSL_PORT`、`SSL_DIR` | 可选的自签名 HTTPS,由 `web/scripts/generate-ssl.sh` 生成 |

## 使用方法

首次运行时,`Setup.tsx` 会引导你完成保险库的创建:选择一个主密码,可选择注册硬件安全密钥或 TOTP,随后守护进程会创建一个加密的 SQLCipher 数据库,以及一个明文的附属文件,该文件只记录登录页面所需的信息(配置了哪些多因素认证方式,是否启用了密码登录),这样在你完成身份验证之前就无需解密任何内容。

之后,你可以:

- 将凭证整理到文件夹中,添加自定义字段,并直接在原地生成强密码
- 如果你希望在受胁迫或过境时能够呈现出一个可信、安全的状态,可在设置中启用胁迫模式和旅行模式
- 运行内置的泄露监控功能,将已保存的密码与本地离线保存的已知泄露密码副本进行比对,每个密码都无需任何外发查询
- 导出 `.p2w` 文件用于备份,或从其他密码管理器导入,全程无需离开你自己的设备

## 开发

代码仓库结构:

```
PWDnow/
├── daemon/     Rust 编写的保险库守护进程。所有加密逻辑都在这里。
├── web/        React 19 + Express 前端与 IPC 代理。
├── monitor/    独立的 Rust 进程,用于健康状况与内存泄漏监控。
├── deploy/     systemd 单元、AppArmor 配置文件、Nginx 配置、Makefile。
├── proto/      守护进程与 Web 共用的 gRPC/protobuf 定义。
└── hibp/       用于构建离线 HIBP Cuckoo 过滤器的脚本。
```


## 测试

```bash
# 守护进程
cd daemon && cargo test
cargo test -- <test_name>       # 运行单个测试

# Web 单元测试
cd web && npm run test
npx vitest run src/utils/crypto.test.ts   # 单个文件

# 端到端测试(Playwright)
cd web && npx playwright test
npx playwright test e2e/comprehensive-platform.spec.ts   # 完整回归走查
```

持续集成会在每次 push 和 pull request 时运行单元测试、端到端测试、依赖审计、变异测试和混沌测试。`web/e2e/comprehensive-platform.spec.ts` 是回归测试关卡:它会走查身份验证(成功与失败路径)、导航、文件夹与凭证的增删改查、胁迫模式,以及账户销毁流程,任何前端或身份验证方面的更改在发布前都应通过该测试。

## 部署

对于超出单台本地机器的任何用途,请在 Express 进程前部署 Nginx:

- `deploy/nginx/vault.conf` 负责 TLS 终止、HSTS 以及限流。Nginx 不应设置自己的 Content-Security-Policy 响应头,因为 Express 服务器会为每个请求注入一个新的 nonce。
- `deploy/vault-daemon.service` 让守护进程以专用的 `vault` 系统用户身份运行,并设置了 `MemorySwapMax=0`、`NoNewPrivileges`、`PrivateTmp`,仅保留内存锁定所需的 `CAP_IPC_LOCK` 能力。
- `deploy/apparmor.d/vault-daemon` 在内核层面限制守护进程对文件系统和能力的访问,并且无需修改即可同时适用于 `x86_64` 和 `aarch64` 主机。

`make install`(或使用 `install.sh` 进行完整的引导式安装)会将上述所有内容配置到位,包括加载 AppArmor 配置文件和启用 systemd 单元。

## 安全政策

PWDnow 处理的是凭证数据,因此这里的漏洞报告比大多数项目更为重要。如果你发现了安全问题,请不要提交公开 issue。请改用该仓库的 GitHub 私密漏洞报告功能,或直接联系维护者。请附上足够的细节以便复现问题,如果可能的话,也请附上影响评估。我们会及时确认收到报告,并在修复发布后为希望署名的报告者署名。

## 参与贡献

欢迎提交 issue 和 pull request。在提交更改之前:

- 运行 `make lint`(`cargo clippy -D warnings` 与 `tsc --noEmit`)以及 `make test`
- 对于前端或身份验证方面的更改,请运行完整的 Playwright 回归测试套件
- 将加密相关的更改保留在守护进程内;Web 层绝不能因为功能更改而附带获得对密钥材料的访问权限

## 许可证

PWDnow 基于 [MIT 许可证](../../LICENSE)发布。
