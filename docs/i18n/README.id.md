<div align="center">

# PWDnow

Pengelola kata sandi zero-knowledge yang mengutamakan lokal

[![CI](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml)
[![Security Audit](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml)
[![Coverage](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml)
[![Mutation Testing](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

[Laporkan bug](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[Ajukan fitur](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[Kebijakan keamanan](#kebijakan-keamanan)

</div>

<div align="center">

**Baca dalam bahasa lain**

| | | | |
|---|---|---|---|
| [English](../../README.md) | [Français](README.fr.md) | [Español](README.es.md) | [Deutsch](README.de.md) |
| [Italiano](README.it.md) | [Português](README.pt.md) | [Русский](README.ru.md) | [العربية](README.ar.md) |
| [हिन्दी](README.hi.md) | [中文](README.zh.md) | [日本語](README.ja.md) | [한국어](README.ko.md) |
| Bahasa Indonesia | | | |

</div>

---

## Tentang

PWDnow adalah pengelola kata sandi yang dibangun di atas prinsip sederhana: baik server, browser, maupun jaringan di antara keduanya tidak boleh pernah melihat rahasia dalam bentuk teks polos. Seluruh operasi kriptografi berjalan di dalam daemon Rust khusus yang terpasang pada mesin tempat brankas itu berada. Antarmuka web, baik dibuka secara lokal maupun disajikan ke browser, hanya bertukar blok data terenkripsi yang buram dengan daemon tersebut. Secara bawaan tidak ada sinkronisasi cloud, tidak ada telemetri, dan tidak ada vendor yang dapat dipaksa menyerahkan data Anda, karena vendor tersebut memang tidak pernah memilikinya.

Proyek ini terbagi menjadi dua lapisan yang berkomunikasi melalui kanal IPC lokal:

- **Daemon Brankas** (`daemon/`), ditulis dalam Rust: derivasi kunci, enkripsi, dekripsi, penyimpanan SQLCipher, penguncian memori, dan penghapusan aman. Ini adalah satu-satunya bagian sistem yang pernah menyentuh kunci atau kredensial dalam bentuk teks polos.
- **Antarmuka Web** (`web/`), aplikasi satu halaman berbasis React 19 yang disajikan oleh proses Express: merender antarmuka, meneruskan permintaan terenkripsi ke daemon melalui Unix domain socket, dan tidak pernah menyimpan materi kunci di luar token sesi berumur pendek yang hanya ada di memori.

PWDnow dapat berjalan sepenuhnya offline pada satu mesin, atau digelar di belakang Nginx dengan TLS untuk akses jaringan lokal atau server yang dihosting sendiri. Dalam kedua kasus tersebut, batas kepercayaannya tetap sama: kata sandi utama dan data Anda tidak pernah meninggalkan memori daemon yang terlindungi.

## Daftar Isi

- [Fitur](#fitur)
- [Arsitektur](#arsitektur)
- [Model Keamanan](#model-keamanan)
- [Platform yang Didukung](#platform-yang-didukung)
- [Memulai](#memulai)
  - [Instalasi Cepat](#instalasi-cepat)
  - [Membangun dari Kode Sumber](#membangun-dari-kode-sumber)
  - [Konfigurasi](#konfigurasi)
- [Penggunaan](#penggunaan)
- [Pengembangan](#pengembangan)
- [Pengujian](#pengujian)
- [Penggelaran](#penggelaran)
- [Kebijakan Keamanan](#kebijakan-keamanan)
- [Berkontribusi](#berkontribusi)
- [Lisensi](#lisensi)

## Fitur

**Brankas Inti**
- Pengorganisasian kredensial berbasis folder, dengan penyusunan ulang melalui seret dan lepas
- Penyimpanan kata sandi, secret TOTP, catatan, dan bidang khusus untuk setiap kredensial
- Penilaian kekuatan kata sandi, deteksi penggunaan ulang, dan deteksi kata sandi umum
- Pemeriksaan kebocoran offline melalui filter Cuckoo lokal yang dibangun dari korpus kata sandi bocor Have I Been Pwned, tanpa panggilan jaringan pada setiap pemeriksaan
- Tampilan pemegang aset: daftar terkonsolidasi dari setiap alamat email, nomor telepon, dan kunci keamanan perangkat keras yang terdaftar di seluruh kredensial Anda

**Autentikasi dan MFA**
- Dukungan WebAuthn dan FIDO2 untuk kunci keamanan perangkat keras dan autentikator platform (Touch ID, Windows Hello)
- Pembuatan TOTP (RFC 6238) dan HOTP (RFC 4226), dengan perlindungan replay
- Login tanpa kata sandi melalui passkey yang disinkronkan atau terikat perangkat
- Penerapan MFA yang dapat dikonfigurasi per akun

**Mode Keamanan**
- Mode paksaan: membuka kunci dengan kata sandi alternatif yang ditentukan akan memicu penghapusan forensik, bukan memberikan akses
- Mode perjalanan: menyembunyikan sebagian kredensial pilihan di balik kata sandi terpisah sebelum melintasi perbatasan atau menyerahkan perangkat
- Penguncian dengan backoff eksponensial setelah percobaan buka kunci yang gagal berulang kali
- Akses darurat: berikan kontak tepercaya akses tertunda ke brankas Anda jika Anda tidak dapat dihubungi

**Impor dan Ekspor**
- Format `.p2w` asli: ekspor terenkripsi ganda AEAD dengan padding dan penyamaran metadata, dirancang untuk menahan pemalsuan offline dan analisis lalu lintas
- Ekspor dan impor dalam JSON biasa, CSV, dan XML yang kompatibel dengan KeePass
- Impor dari ekspor Bitwarden, 1Password (CSV, 1PUX), dan NordPass

**Kriptografi Pasca-Kuantum dan Setara Standar**
- Enkapsulasi kunci hibrida X25519 + ML-KEM-768/1024 (aktif secara bawaan, bukan opsi terpisah yang harus diaktifkan)
- Tanda tangan pasca-kuantum ML-DSA-87
- Derivasi kunci Argon2id, enkripsi terautentikasi AES-256-GCM dan XChaCha20-Poly1305
- Mode ketat CNSA 2.0 opsional, yang membatasi daemon pada Commercial National Security Algorithm Suite milik NSA (HKDF-SHA-384, PBKDF2-SHA-512, serta menghapus BLAKE3, SHA3, XChaCha20, Ed25519, dan X25519 dari jalur kode aktif)

## Arsitektur

```
┌─────────────────────────────┐        soket Unix         ┌──────────────────────────────┐
│  Antarmuka Web (web/)       │  msgpack via /run/...     │  Daemon Brankas (daemon/)    │
│  React 19 + Express         │ ─────────────────────────▶│  Rust, SQLCipher, mlock()   │
│  Antarmuka zero-knowledge,   │◀─────────────────────────  │  Argon2id, AES-256-GCM,     │
│  hanya token sesi, tanpa     │      respons               │  XChaCha20-Poly1305,        │
│  kunci                       │      terenkripsi           │  KEM hibrida pasca-kuantum   │
└─────────────────────────────┘                            └──────────────────────────────┘
```

Daemon menyediakan protokol permintaan dan respons yang bertipe kuat (`daemon/src/ipc/protocol.rs`), ditransportasikan sebagai frame MessagePack melalui Unix domain socket. Setiap permintaan yang telah diautentikasi membawa token sesi yang divalidasi daemon sebelum menyentuh basis data. Daemon juga memverifikasi identitas proses yang terhubung pada tingkat sistem operasi (`SO_PEERCRED`), sehingga hanya proksi web tepercaya, yang berjalan sebagai pengguna sistem yang benar, yang dapat menjangkaunya.

Lapisan web tidak pernah menerima kunci utama, kunci enkripsi kunci, kunci utama brankas, atau kunci enkripsi data, dalam bentuk apa pun. Ia hanya menerima teks tersandi dan meneruskannya. Daemon pemantauan pendamping (`monitor/`) melacak pertumbuhan memori, penggunaan disk, dan kesehatan proses secara independen dari daemon brankas itu sendiri, sehingga kebocoran memori atau proses yang macet akan terdeteksi dan diberi peringatan, alih-alih membuat layanan menurun secara diam-diam.

Detail teknis lengkap, termasuk hierarki derivasi kunci, spesifikasi format berkas P2W, dan model ancaman, didokumentasikan di [`architecture.md`](../../architecture.md).

## Model Keamanan

PWDnow berasumsi bahwa jaringan, proses browser, dan sistem operasi host semuanya berpotensi bersifat bermusuhan, dan merancang arsitekturnya berdasarkan asumsi tersebut, bukan asumsi yang lebih bersahabat.

- **Zero-knowledge secara konstruksi**: browser tidak dapat membocorkan apa yang tidak pernah dimilikinya. Kunci utama dan kunci turunan hanya ada di dalam ruang memori daemon.
- **Perlindungan memori**: kunci utama brankas disimpan dalam wilayah memori terkunci (`mlock`) yang disegel dengan `mprotect(PROT_NONE)` saat tidak aktif, dan dihapus dengan crate `zeroize` segera setelah tidak lagi diperlukan.
- **Enkripsi saat diam**: basis data brankas dienkripsi end-to-end dengan SQLCipher. Ekspor menggunakan AEAD ganda (lapisan dalam AES-256-GCM dan lapisan luar XChaCha20-Poly1305), dengan header yang terikat ke kedua tag autentikasi.
- **Verifikasi independen**: proyek ini secara berkelanjutan menjalankan pengujian mutasi dan pengujian chaos dalam integrasi berkelanjutannya, selain rangkaian pengujian unit dan end-to-end yang biasa, khusus untuk menangkap pengujian yang lolos tanpa benar-benar memverifikasi perilaku yang diklaim tercakup.

Jika Anda menemukan kerentanan, silakan lihat [Kebijakan Keamanan](#kebijakan-keamanan) sebelum membuka tiket publik.

## Platform yang Didukung

PWDnow dikembangkan dan diuji terutama pada **Ubuntu 26.04 LTS (Resolute)**. Installer juga mendeteksi dan mendukung:

- Debian dan distribusi turunan Debian (Ubuntu, Linux Mint, Pop!_OS, Zorin, Kali)
- Fedora dan distribusi keluarga RHEL (Fedora, RHEL, CentOS, Rocky Linux, AlmaLinux)

Baik `x86_64` maupun `aarch64` didukung oleh toolchain Rust. Distribusi Linux lain mungkin dapat berjalan tetapi bukan bagian dari matriks pengujian reguler. Saat ini belum ada build untuk macOS atau Windows.

## Memulai

### Instalasi Cepat

```bash
git clone https://github.com/PWDnow/PWDnow-password-manager.git
cd PWDnow
./install.sh
```

Installer mendeteksi distribusi Anda, memeriksa dependensi yang hilang dan menawarkan untuk memasangnya, mengaudit konfigurasi SSH Anda, memeriksa konflik port, membangun daemon dan frontend web dari kode sumber, dan memasang keduanya sebagai layanan systemd yang berjalan di bawah pengguna sistem khusus tanpa hak istimewa. Tidak ada yang dipasang dengan hak istimewa tinggi di luar yang dibutuhkan oleh systemd, AppArmor, dan pemasangan paket, dan setiap langkah yang memerlukan hak istimewa ditampilkan sebelum dijalankan.

### Membangun dari Kode Sumber

Persyaratan: Node.js 24 atau lebih baru, Rust 1.94 atau lebih baru (ditetapkan di `daemon/rust-toolchain.toml`), `protoc`, serta header pengembangan untuk `libsodium`, `sqlcipher`, dan `libfido2`.

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

Atau, dari `deploy/`:

```bash
make build          # daemon + web, mode release
make test            # cargo test + vitest
make install          # memasang biner, unit systemd, profil AppArmor, dan konfigurasi nginx (memerlukan sudo)
```

Enkapsulasi kunci pasca-kuantum aktif secara bawaan. `make build-pq` dan `cargo build --release --features pq-hybrid-1024` tetap dipertahankan sebagai alias eksplisit dari build bawaan yang sama, demi kejelasan dan kompatibilitas dengan dokumentasi lama. Gunakan `--features cnsa-strict` untuk mode ketat CNSA 2.0.

### Konfigurasi

Salin `web/.env.example` ke `web/.env` dan sesuaikan sesuai kebutuhan:

| Variabel | Kegunaan |
|---|---|
| `DAEMON_GRPC_ADDR` | Alamat yang digunakan lapisan web untuk menjangkau daemon (bawaan `127.0.0.1:50051`) |
| `VAULT_ORIGIN` | Origin browser yang diizinkan di produksi, digunakan untuk pemeriksaan origin WebSocket |
| `BIND_HOST` | Antarmuka tempat server web terikat (bawaan `127.0.0.1`; atur ke `0.0.0.0` untuk akses jaringan lokal) |
| `SSL`, `SSL_PORT`, `SSL_DIR` | HTTPS self-signed opsional, dihasilkan oleh `web/scripts/generate-ssl.sh` |

## Penggunaan

Pada saat pertama kali dijalankan, `Setup.tsx` memandu pembuatan brankas: memilih kata sandi utama, secara opsional mendaftarkan kunci keamanan perangkat keras atau TOTP, dan daemon membuat basis data SQLCipher terenkripsi beserta berkas pendamping teks polos yang hanya mencatat apa yang dibutuhkan halaman login (metode MFA apa saja yang dikonfigurasi, apakah login kata sandi bahkan diaktifkan), sehingga tidak ada yang perlu didekripsi sebelum Anda terautentikasi.

Selanjutnya Anda dapat:

- Mengorganisasi kredensial ke dalam folder, menambahkan bidang khusus, dan menghasilkan kata sandi yang kuat langsung di tempat
- Mengaktifkan mode paksaan dan mode perjalanan dari Pengaturan jika Anda ingin dapat menunjukkan keadaan yang aman dan meyakinkan saat dipaksa atau saat melintasi perbatasan
- Menjalankan pemantau kebocoran bawaan untuk memeriksa kata sandi tersimpan Anda terhadap salinan lokal dan offline dari kata sandi bocor yang diketahui, tanpa kueri keluar untuk setiap kata sandi
- Mengekspor berkas `.p2w` untuk pencadangan, atau mengimpor dari pengelola kata sandi lain, tanpa pernah meninggalkan mesin Anda

## Pengembangan

Struktur repositori:

```
PWDnow/
├── daemon/     Daemon brankas dalam Rust. Semua kriptografi berada di sini.
├── web/        Frontend React 19 + Express dan proksi IPC.
├── monitor/    Proses Rust independen untuk pemantauan kesehatan dan kebocoran memori.
├── deploy/     Unit systemd, profil AppArmor, konfigurasi Nginx, Makefile.
├── proto/      Definisi gRPC/protobuf yang digunakan bersama oleh daemon dan web.
└── hibp/       Skrip yang membangun filter Cuckoo HIBP offline.
```

Lihat [`CLAUDE.md`](../../CLAUDE.md) untuk referensi arsitektur lengkap yang digunakan oleh kontributor dan perkakas otomatis, dan [`web/CLAUDE.md`](../../web/CLAUDE.md) untuk konvensi khusus frontend, termasuk registri kunci localStorage, daftar periksa IPC untuk menambahkan endpoint daemon baru, dan batas kriptografis yang tidak boleh pernah dilewati frontend.

## Pengujian

```bash
# Daemon
cd daemon && cargo test
cargo test -- <test_name>       # menjalankan satu pengujian

# Pengujian unit web
cd web && npm run test
npx vitest run src/utils/crypto.test.ts   # satu berkas

# End-to-end (Playwright)
cd web && npx playwright test
npx playwright test e2e/comprehensive-platform.spec.ts   # alur regresi lengkap
```

CI menjalankan pengujian unit, pengujian end-to-end, audit dependensi, pengujian mutasi, dan pengujian chaos pada setiap push dan pull request. `web/e2e/comprehensive-platform.spec.ts` adalah gerbang regresi: ia menelusuri autentikasi (jalur sukses dan gagal), navigasi, operasi CRUD folder dan kredensial, mode paksaan, dan penghancuran akun, dan harus lolos sebelum perubahan frontend atau autentikasi apa pun dirilis.

## Penggelaran

Untuk penggunaan di luar satu mesin lokal, tempatkan Nginx di depan proses Express:

- `deploy/nginx/vault.conf` menangani terminasi TLS, HSTS, dan pembatasan laju. Nginx tidak boleh mengatur header Content-Security-Policy-nya sendiri, karena server Express menyisipkan nonce baru pada setiap permintaan.
- `deploy/vault-daemon.service` menjalankan daemon di bawah pengguna sistem khusus `vault`, dengan `MemorySwapMax=0`, `NoNewPrivileges`, `PrivateTmp`, dan hanya kapabilitas `CAP_IPC_LOCK` yang dibutuhkan untuk penguncian memori.
- `deploy/apparmor.d/vault-daemon` membatasi akses daemon ke sistem berkas dan kapabilitas pada tingkat kernel, dan berlaku tanpa modifikasi baik di host `x86_64` maupun `aarch64`.

`make install` (atau `install.sh` untuk instalasi terpandu lengkap) menghubungkan semua ini, termasuk memuat profil AppArmor dan mengaktifkan unit systemd.

## Kebijakan Keamanan

PWDnow menangani kredensial, sehingga laporan kerentanan di sini lebih penting dibandingkan kebanyakan proyek lain. Jika Anda menemukan masalah keamanan, mohon jangan membuka tiket publik. Sebagai gantinya, gunakan fitur pelaporan kerentanan privat GitHub untuk repositori ini, atau hubungi pengelola secara langsung. Sertakan detail yang cukup untuk mereproduksi masalah tersebut dan, jika memungkinkan, penilaian dampaknya. Kami akan mengonfirmasi laporan dengan segera dan memberi kredit kepada pelapor yang menginginkannya setelah perbaikan dirilis.

## Berkontribusi

Tiket dan pull request sangat diterima. Sebelum mengirimkan perubahan:

- Jalankan `make lint` (`cargo clippy -D warnings` dan `tsc --noEmit`) dan `make test`
- Untuk perubahan frontend atau autentikasi, jalankan rangkaian regresi Playwright secara lengkap
- Jaga agar perubahan kriptografis hanya berada di daemon; lapisan web tidak boleh pernah mendapatkan akses ke materi kunci sebagai efek samping dari perubahan fitur
- Ikuti konvensi yang dijelaskan dalam `CLAUDE.md` dan `web/CLAUDE.md`

## Lisensi

PWDnow dirilis di bawah [Lisensi MIT](../../LICENSE).
