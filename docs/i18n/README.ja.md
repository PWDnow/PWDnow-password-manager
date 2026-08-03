<div align="center">

# PWDnow

ゼロ知識、ローカルファーストのパスワードマネージャー

[![CI](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml)
[![Security Audit](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml)
[![Coverage](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml)
[![Mutation Testing](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

[バグを報告する](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[機能を提案する](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[セキュリティポリシー](#セキュリティポリシー)

</div>

<div align="center">

**他の言語で読む**

| | | | |
|---|---|---|---|
| [English](../../README.md) | [Français](README.fr.md) | [Español](README.es.md) | [Deutsch](README.de.md) |
| [Italiano](README.it.md) | [Português](README.pt.md) | [Русский](README.ru.md) | [العربية](README.ar.md) |
| [हिन्दी](README.hi.md) | [中文](README.zh.md) | 日本語 | [한국어](README.ko.md) |
| [Bahasa Indonesia](README.id.md) | | | |

</div>

---

## 概要

PWDnowは、単純な前提に基づいて構築されたパスワードマネージャーです。サーバーもブラウザも、その間のネットワークも、平文の秘密情報を決して目にすることはありません。すべての暗号処理は、ボールトが存在するマシン上で動作する専用のRustデーモンの内部で実行されます。Webインターフェースは、ローカルで開かれる場合でもブラウザに提供される場合でも、そのデーモンとの間で不透明な暗号化データブロックのみをやり取りします。デフォルトではクラウド同期はなく、テレメトリもなく、データを渡すよう強制されうるベンダーも存在しません。なぜなら、ベンダーがそもそもデータを保持することがないからです。

このプロジェクトは、ローカルIPCチャネルを介して通信する2つの層に分かれています。

- **ボールトデーモン**(`daemon/`)、Rustで記述:鍵導出、暗号化、復号、SQLCipherによるストレージ、メモリロック、そして安全な消去を担当します。システム内で平文の鍵や認証情報に触れる唯一の部分です。
- **Webインターフェース**(`web/`)、Expressプロセスによって提供されるReact 19のシングルページアプリケーション:UIを描画し、暗号化されたリクエストをUnixドメインソケット経由でデーモンに転送し、短命でメモリ上にのみ存在するセッショントークンを除いて、鍵素材を一切保持しません。

PWDnowは単一のマシン上で完全にオフラインで動作させることも、TLSを使ったNginxの背後に配置してLANまたは自己ホスト型サーバーからのアクセスに対応させることもできます。いずれの場合も、信頼境界は変わりません。マスターパスワードとデータは、デーモンの保護されたメモリから外に出ることは決してありません。

## 目次

- [機能](#機能)
- [アーキテクチャ](#アーキテクチャ)
- [セキュリティモデル](#セキュリティモデル)
- [対応プラットフォーム](#対応プラットフォーム)
- [はじめに](#はじめに)
  - [クイックインストール](#クイックインストール)
  - [ソースからのビルド](#ソースからのビルド)
  - [設定](#設定)
- [使い方](#使い方)
- [開発](#開発)
- [テスト](#テスト)
- [デプロイ](#デプロイ)
- [セキュリティポリシー](#セキュリティポリシー)
- [コントリビューション](#コントリビューション)
- [ライセンス](#ライセンス)

## 機能

**コアボールト**
- ドラッグでの並べ替えに対応した、フォルダ単位での認証情報管理
- 認証情報ごとにパスワード、TOTPシークレット、メモ、カスタムフィールドを保存
- パスワード強度スコアリング、再利用の検出、よく使われるパスワードの検出
- Have I Been Pwnedのパスワードコーパスをもとにローカルで構築されたCuckooフィルタによるオフライン漏洩チェック。確認のたびにネットワーク呼び出しを行う必要はありません
- アセットホルダービュー:登録済みのすべてのメールアドレス、電話番号、ハードウェアセキュリティキーを認証情報横断でまとめて一覧表示

**認証と多要素認証**
- ハードウェアセキュリティキーおよびプラットフォーム認証器(Touch ID、Windows Hello)に対応したWebAuthnおよびFIDO2
- リプレイ保護付きのTOTP(RFC 6238)およびHOTP(RFC 4226)生成
- 同期型またはデバイスバインド型のパスキーによるパスワードレスログイン
- アカウントごとに設定可能な多要素認証の強制

**セキュリティモード**
- デュレスモード:指定された代替パスワードでロックを解除すると、アクセスを許可する代わりにフォレンジック消去がトリガーされます
- トラベルモード:国境を越えたりデバイスを他者に渡したりする前に、選択した認証情報のサブセットを別のパスワードの背後に隠します
- 繰り返しロック解除に失敗した場合の指数バックオフによるロックアウト
- 緊急アクセス:連絡が取れなくなった場合に備え、信頼できる連絡先に時間差でボールトへのアクセスを許可します

**インポートとエクスポート**
- ネイティブの`.p2w`形式:オフラインでの改ざんとトラフィック解析への耐性を目的として設計された、二重AEAD暗号化、パディング、メタデータ難読化を伴うエクスポート形式
- 平文JSON、CSV、KeePass互換のXMLでのエクスポートおよびインポート
- Bitwarden、1Password(CSV、1PUX)、NordPassのエクスポートファイルからのインポート

**ポスト量子および規格準拠の暗号技術**
- ハイブリッドX25519 + ML-KEM-768/1024鍵カプセル化(デフォルトで有効。別途有効化するオプションではありません)
- ML-DSA-87ポスト量子署名
- Argon2id鍵導出、AES-256-GCMおよびXChaCha20-Poly1305による認証付き暗号化
- オプションのCNSA 2.0厳格モード。デーモンをNSAのCommercial National Security Algorithm Suiteに制限します(HKDF-SHA-384、PBKDF2-SHA-512、およびBLAKE3、SHA3、XChaCha20、Ed25519、X25519をアクティブなコードパスから排除)

## アーキテクチャ

```
┌─────────────────────────────┐        Unixソケット        ┌──────────────────────────────┐
│  Webインターフェース (web/)  │  /run/... 上のmsgpack      │  ボールトデーモン             │
│  React 19 + Express          │ ─────────────────────────▶│  (daemon/)                    │
│  ゼロ知識インターフェース、   │◀─────────────────────────  │  Rust, SQLCipher, mlock()    │
│  セッショントークンのみ、    │      暗号化された応答       │  Argon2id, AES-256-GCM,      │
│  鍵は保持しない               │                            │  XChaCha20-Poly1305,         │
└─────────────────────────────┘                            │  ハイブリッドPQ KEM            │
                                                             └──────────────────────────────┘
```

デーモンは、Unixドメインソケット上でMessagePackフレームとして転送される、強く型付けされたリクエスト/レスポンスプロトコル(`daemon/src/ipc/protocol.rs`)を公開します。認証済みのリクエストにはすべてセッショントークンが付与され、デーモンはデータベースにアクセスする前にこれを検証します。デーモンはまた、接続元プロセスの識別をOSレベル(`SO_PEERCRED`)でも検証するため、正しいシステムユーザーで動作している信頼済みのWebプロキシのみがアクセスできます。

Web層は、マスターキー、鍵暗号化キー、ボールトマスターキー、データ暗号化キーのいずれも、いかなる形でも受け取ることはありません。暗号文を受け取り、それを転送するだけです。付随する監視デーモン(`monitor/`)は、ボールトデーモン自体とは独立してメモリ増加、ディスク使用量、プロセスの健全性を追跡するため、メモリリークやプロセスのフリーズは、サービスを静かに劣化させるのではなく、検知され通知されます。

鍵導出の階層構造、P2Wファイル形式の仕様、脅威モデルを含む完全な技術詳細は、[`architecture.md`](../../architecture.md)に記載されています。

## セキュリティモデル

PWDnowは、ネットワーク、ブラウザプロセス、そしてホストOSのすべてが潜在的に敵対的であるという前提に立ち、より寛容なデフォルトではなく、この前提に基づいてアーキテクチャを設計しています。

- **構造上のゼロ知識**:ブラウザは一度も持ったことのないものを漏洩させることはできません。マスターキーと派生キーは、デーモンのアドレス空間内にのみ存在します。
- **メモリ保護**:ボールトマスターキーはロックされたメモリ領域(`mlock`)に保持され、アイドル時には`mprotect(PROT_NONE)`で封印され、不要になり次第`zeroize`クレートによって消去されます。
- **保存時の暗号化**:ボールトデータベースはSQLCipherによってエンドツーエンドで暗号化されています。エクスポートでは二重AEAD(内側のAES-256-GCM層と外側のXChaCha20-Poly1305層)を使用し、ヘッダーは両方の認証タグに紐付けられます。
- **独立した検証**:このプロジェクトは、通常のユニットテストおよびエンドツーエンドテストのスイートに加えて、CI上で継続的にミューテーションテストとカオステストを実行しています。これは、実際にはカバーしていると主張する挙動を検証しないまま通過してしまうテストを見つけ出すことを目的としています。

脆弱性を発見した場合は、公開のissueを立てる前に[セキュリティポリシー](#セキュリティポリシー)を確認してください。

## 対応プラットフォーム

PWDnowは主に**Ubuntu 26.04 LTS(Resolute)**上で開発およびテストされています。インストーラーは以下も検出し、対応します。

- Debianおよびその派生ディストリビューション(Ubuntu、Linux Mint、Pop!_OS、Zorin、Kali)
- FedoraおよびRHEL系ディストリビューション(Fedora、RHEL、CentOS、Rocky Linux、AlmaLinux)

Rustのツールチェーンは`x86_64`および`aarch64`の両方に対応しています。他のLinuxディストリビューションでも動作する可能性はありますが、通常のテストマトリクスには含まれていません。現時点ではmacOSまたはWindows向けのビルドはありません。

## はじめに

### クイックインストール

```bash
git clone https://github.com/PWDnow/PWDnow-password-manager.git
cd PWDnow
./install.sh
```

インストーラーはディストリビューションを検出し、不足している依存関係を確認してインストールを提案し、SSH設定を監査し、ポートの競合を確認し、ソースからデーモンとWebフロントエンドをビルドし、両方を専用の非特権システムユーザーの下で動作するsystemdサービスとしてインストールします。systemd、AppArmor、パッケージインストールが必要とする以上の昇格された権限で何かがインストールされることはなく、権限を要する各ステップは実行前に画面に表示されます。

### ソースからのビルド

必要要件:Node.js 20以降、Rust 1.94以降(`daemon/rust-toolchain.toml`で固定)、`protoc`、および`libsodium`、`sqlcipher`、`libfido2`の開発用ヘッダー。

```bash
# デーモン
cd daemon
cargo build --release
cargo test

# Web
cd web
npm install
npm run build
npm start
```

または、`deploy/`から:

```bash
make build          # デーモン + Web、リリースモード
make test            # cargo test + vitest
make install          # バイナリ、systemdユニット、AppArmorプロファイル、nginx設定をインストール(sudoが必要)
```

ポスト量子鍵カプセル化はデフォルトで有効になっています。`make build-pq`および`cargo build --release --features pq-hybrid-1024`は、明確さと古いドキュメントとの互換性のために、この同じデフォルトビルドの明示的なエイリアスとして残されています。CNSA 2.0厳格モードには`--features cnsa-strict`を使用してください。

### 設定

`web/.env.example`を`web/.env`にコピーし、必要に応じて調整してください。

| 変数 | 用途 |
|---|---|
| `DAEMON_GRPC_ADDR` | Web層がデーモンに到達するために使用するアドレス(デフォルト`127.0.0.1:50051`) |
| `VAULT_ORIGIN` | 本番環境で許可されるブラウザオリジン。WebSocketのオリジンチェックに使用 |
| `BIND_HOST` | Webサーバーがバインドするインターフェース(デフォルト`127.0.0.1`。LANアクセスには`0.0.0.0`を設定) |
| `SSL`、`SSL_PORT`、`SSL_DIR` | `web/scripts/generate-ssl.sh`によって生成されるオプションの自己署名HTTPS |

## 使い方

初回起動時、`Setup.tsx`がボールトの作成を案内します。マスターパスワードの選択、ハードウェアセキュリティキーまたはTOTPの任意の登録が行われ、デーモンは暗号化されたSQLCipherデータベースに加えて、ログインページが必要とする情報のみ(どのMFA方式が設定されているか、そもそもパスワードログインが有効かどうか)を記録する平文のサイドカーファイルを作成します。これにより、認証が完了する前に何かを復号する必要がなくなります。

その後は次のことができます。

- 認証情報をフォルダに整理し、カスタムフィールドを追加し、その場で強力なパスワードを生成する
- 強要下や国境通過時に、もっともらしい安全な状態を提示したい場合は、設定からデュレスモードとトラベルモードを有効にする
- 内蔵の漏洩モニターを実行し、保存済みパスワードをローカルのオフラインコピーである既知の漏洩パスワードと照合する。パスワードごとの外部送信クエリは発生しません
- バックアップのために`.p2w`ファイルをエクスポートするか、他のパスワードマネージャーからインポートする。すべて自分のマシンから出ることなく行えます

## 開発

リポジトリの構成:

```
PWDnow/
├── daemon/     Rustで書かれたボールトデーモン。すべての暗号処理はここにあります。
├── web/        React 19 + ExpressのフロントエンドとIPCプロキシ。
├── monitor/    健全性とメモリリークを監視する独立したRustプロセス。
├── deploy/     systemdユニット、AppArmorプロファイル、Nginx設定、Makefile。
├── proto/      デーモンとWebで共有されるgRPC/protobuf定義。
└── hibp/       オフラインのHIBP Cuckooフィルタを構築するスクリプト。
```

コントリビューターおよび自動化ツールが使用する完全なアーキテクチャリファレンスは[`CLAUDE.md`](../../CLAUDE.md)を、localStorageキーレジストリ、デーモンに新しいエンドポイントを追加する際のIPCチェックリスト、フロントエンドが決して越えてはならない暗号境界を含むフロントエンド固有の規約は[`web/CLAUDE.md`](../../web/CLAUDE.md)を参照してください。

## テスト

```bash
# デーモン
cd daemon && cargo test
cargo test -- <test_name>       # 単一のテストを実行

# Webユニットテスト
cd web && npm run test
npx vitest run src/utils/crypto.test.ts   # 単一ファイル

# エンドツーエンド(Playwright)
cd web && npx playwright test
npx playwright test e2e/comprehensive-platform.spec.ts   # 完全な回帰ウォークスルー
```

CIはpushおよびpull requestのたびに、ユニットテスト、エンドツーエンドテスト、依存関係の監査、ミューテーションテスト、カオステストを実行します。`web/e2e/comprehensive-platform.spec.ts`は回帰ゲートであり、認証(成功と失敗の両方の経路)、ナビゲーション、フォルダおよび認証情報のCRUD操作、デュレスモード、アカウント破棄を一通り確認します。フロントエンドまたは認証に関する変更を出荷する前には、必ずこれに合格する必要があります。

## デプロイ

単一のローカルマシンを超える用途では、Expressプロセスの前段にNginxを配置してください。

- `deploy/nginx/vault.conf`はTLS終端、HSTS、レート制限を処理します。ExpressサーバーがリクエストごとにNonceを新しく発行するため、Nginx側で独自のContent-Security-Policyヘッダーを設定してはいけません。
- `deploy/vault-daemon.service`は、専用の`vault`システムユーザーの下でデーモンを実行し、`MemorySwapMax=0`、`NoNewPrivileges`、`PrivateTmp`、そしてメモリロックに必要な`CAP_IPC_LOCK`のみのケーパビリティを設定します。
- `deploy/apparmor.d/vault-daemon`は、カーネルレベルでデーモンのファイルシステムおよびケーパビリティへのアクセスを制限し、`x86_64`ホストと`aarch64`ホストのいずれにも変更なしで適用されます。

`make install`(または完全なガイド付きインストールには`install.sh`)は、AppArmorプロファイルの読み込みやsystemdユニットの有効化を含め、これらすべてを配線します。

## セキュリティポリシー

PWDnowは認証情報を扱うため、ここでの脆弱性レポートはほとんどのプロジェクトよりも重要な意味を持ちます。セキュリティ上の問題を発見した場合は、公開のissueを立てないでください。代わりに、このリポジトリ向けのGitHubの非公開脆弱性報告機能を使用するか、メンテナーに直接連絡してください。問題を再現するのに十分な詳細と、可能であれば影響度の評価を含めてください。私たちは速やかに報告を確認し、修正がリリースされた時点で、希望する報告者にクレジットを付与します。

## コントリビューション

issueおよびpull requestを歓迎します。変更を送信する前に:

- `make lint`(`cargo clippy -D warnings`および`tsc --noEmit`)と`make test`を実行してください
- フロントエンドまたは認証に関する変更については、Playwrightの完全な回帰スイートを実行してください
- 暗号関連の変更はデーモン内にのみ留めてください。Web層は、機能変更の副作用として鍵素材へのアクセスを得ることが決してあってはなりません
- `CLAUDE.md`および`web/CLAUDE.md`に記載された規約に従ってください

## ライセンス

PWDnowは[MITライセンス](../../LICENSE)の下で公開されています。
