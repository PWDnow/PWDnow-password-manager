<div align="center">

# PWDnow

Gestor de contraseñas de conocimiento cero, local ante todo

[![CI](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/ci.yml)
[![Security Audit](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/security.yml)
[![Coverage](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/coverage.yml)
[![Mutation Testing](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml/badge.svg)](https://github.com/PWDnow/PWDnow-password-manager/actions/workflows/mutation.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

[Reportar un error](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[Solicitar una función](https://github.com/PWDnow/PWDnow-password-manager/issues) &middot;
[Política de seguridad](#politica-de-seguridad)

</div>

<div align="center">

**Leer en otro idioma**

| | | | |
|---|---|---|---|
| [English](../../README.md) | [Français](README.fr.md) | Español | [Deutsch](README.de.md) |
| [Italiano](README.it.md) | [Português](README.pt.md) | [Русский](README.ru.md) | [العربية](README.ar.md) |
| [हिन्दी](README.hi.md) | [中文](README.zh.md) | [日本語](README.ja.md) | [한국어](README.ko.md) |
| [Bahasa Indonesia](README.id.md) | | | |

</div>

---

## Acerca de

PWDnow es un gestor de contraseñas construido sobre una premisa simple: ni el servidor, ni el navegador, ni la red que hay entre ambos deben ver nunca un secreto en texto plano. Todas las operaciones criptográficas se ejecutan dentro de un daemon dedicado en Rust, instalado en la misma máquina donde reside la bóveda. La interfaz web, ya sea abierta localmente o servida a un navegador, solo intercambia con ese daemon bloques de datos cifrados y opacos. No hay sincronización en la nube por defecto, ninguna telemetría, y ningún proveedor que pueda ser obligado a entregar tus datos, sencillamente porque nunca los tiene.

El proyecto se divide en dos capas que se comunican mediante un canal IPC local:

- **Daemon de la bóveda** (`daemon/`), escrito en Rust: derivación de claves, cifrado, descifrado, almacenamiento SQLCipher, bloqueo de memoria y borrado seguro. Es la única parte del sistema que llega a manejar una clave o una credencial en texto plano.
- **Interfaz web** (`web/`), una aplicación de página única en React 19 servida por un proceso Express: renderiza la interfaz, reenvía las solicitudes cifradas al daemon a través de un socket Unix, y nunca conserva material de claves fuera de un token de sesión efímero, guardado únicamente en memoria.

PWDnow puede funcionar completamente sin conexión en una sola máquina, o desplegarse detrás de Nginx con TLS para acceso en red local o autoalojado. En cualquier caso, el límite de confianza es el mismo: tu contraseña maestra y tus datos nunca salen de la memoria protegida del daemon.

## Índice

- [Funciones](#funciones)
- [Arquitectura](#arquitectura)
- [Modelo de seguridad](#modelo-de-seguridad)
- [Plataformas compatibles](#plataformas-compatibles)
- [Primeros pasos](#primeros-pasos)
  - [Instalación rápida](#instalacion-rapida)
  - [Compilación desde el código fuente](#compilacion-desde-el-codigo-fuente)
  - [Configuración](#configuracion)
- [Uso](#uso)
- [Desarrollo](#desarrollo)
- [Pruebas](#pruebas)
- [Despliegue](#despliegue)
- [Política de seguridad](#politica-de-seguridad)
- [Contribuir](#contribuir)
- [Licencia](#licencia)

## Funciones

**Bóveda principal**
- Organización de credenciales por carpetas, con reordenamiento mediante arrastrar y soltar
- Almacenamiento por credencial de contraseña, secreto TOTP, notas y campos personalizados
- Puntuación de robustez de contraseñas, detección de reutilización y detección de contraseñas comunes
- Verificación de filtraciones sin conexión, mediante un filtro Cuckoo local construido a partir del corpus de contraseñas comprometidas de Have I Been Pwned, sin llamada de red por cada verificación
- Vista de titulares de activos: una lista consolidada de cada correo electrónico, número de teléfono y llave de seguridad física registrados entre tus credenciales

**Autenticación y MFA**
- Compatibilidad con WebAuthn y FIDO2 para llaves de seguridad físicas y autenticadores de plataforma (Touch ID, Windows Hello)
- Generación TOTP (RFC 6238) y HOTP (RFC 4226), con protección contra repetición
- Inicio de sesión sin contraseña mediante passkeys sincronizadas o vinculadas al dispositivo
- Aplicación de MFA configurable por cuenta

**Modos de seguridad**
- Modo coacción: desbloquear con una contraseña alternativa designada activa un borrado forense en lugar de conceder acceso
- Modo viaje: oculta un subconjunto elegido de credenciales tras una contraseña independiente antes de cruzar una frontera o entregar un dispositivo
- Bloqueo con retardo exponencial tras intentos de desbloqueo fallidos repetidos
- Acceso de emergencia: concede a un contacto de confianza acceso diferido en el tiempo a tu bóveda en caso de que quedes incomunicado

**Importación y exportación**
- Formato nativo `.p2w`: una exportación cifrada con doble AEAD, con relleno y ofuscación de metadatos, diseñada para resistir la manipulación sin conexión y el análisis de tráfico
- Exportación e importación en JSON plano, CSV y XML compatible con KeePass
- Importación desde exportaciones de Bitwarden, 1Password (CSV, 1PUX) y NordPass

**Criptografía postcuántica y de nivel normativo**
- Encapsulación de claves híbrida X25519 + ML-KEM-768/1024 (activada por defecto, no es una opción que haya que activar aparte)
- Firmas postcuánticas ML-DSA-87
- Derivación de claves Argon2id, cifrado autenticado AES-256-GCM y XChaCha20-Poly1305
- Modo estricto CNSA 2.0 opcional, que restringe el daemon al conjunto de algoritmos de seguridad nacional comercial de la NSA (HKDF-SHA-384, PBKDF2-SHA-512, y eliminación de BLAKE3, SHA3, XChaCha20, Ed25519 y X25519 de las rutas de código activas)

## Arquitectura

```
┌─────────────────────────────┐        socket Unix        ┌──────────────────────────────┐
│  Interfaz web (web/)        │  msgpack sobre /run/...   │  Daemon de la bóveda         │
│  React 19 + Express         │ ─────────────────────────▶│  (daemon/)                   │
│  Interfaz de conocimiento    │◀─────────────────────────  │  Rust, SQLCipher, mlock()   │
│  cero, solo token de sesión, │      respuestas cifradas  │  Argon2id, AES-256-GCM,     │
│  sin claves                  │                            │  XChaCha20-Poly1305,        │
└─────────────────────────────┘                            │  KEM híbrido postcuántico    │
                                                             └──────────────────────────────┘
```

El daemon expone un protocolo de solicitudes y respuestas fuertemente tipado (`daemon/src/ipc/protocol.rs`), transportado como tramas MessagePack sobre un socket Unix. Cada solicitud autenticada lleva un token de sesión que el daemon valida antes de tocar la base de datos. El daemon también verifica la identidad del proceso que se conecta a nivel del sistema operativo (`SO_PEERCRED`), de modo que solo el proxy web de confianza, ejecutándose bajo el usuario de sistema correcto, puede alcanzarlo.

La capa web nunca recibe una clave maestra, una clave de cifrado de clave, una clave maestra de la bóveda ni una clave de cifrado de datos, en ninguna forma. Recibe texto cifrado y lo reenvía. Un daemon de monitorización complementario (`monitor/`) rastrea el crecimiento de memoria, el uso de disco y el estado de los procesos de forma independiente al propio daemon de la bóveda, de modo que una fuga de memoria o un proceso bloqueado se detecte y se notifique en lugar de degradar el servicio en silencio.

El detalle técnico completo, incluida la jerarquía de derivación de claves, la especificación del formato de archivo P2W y el modelo de amenazas, está documentado en [`architecture.md`](../../architecture.md).

## Modelo de seguridad

PWDnow parte de la base de que la red, el proceso del navegador y el sistema operativo anfitrión son todos potencialmente hostiles, y diseña su arquitectura en función de esa suposición en lugar de una más favorable.

- **Conocimiento cero por construcción**: el navegador no puede filtrar lo que nunca tuvo. Las claves maestras y las claves derivadas solo existen dentro del espacio de memoria del daemon.
- **Protección de memoria**: la clave maestra de la bóveda se mantiene en una región de memoria bloqueada (`mlock`), sellada con `mprotect(PROT_NONE)` mientras está inactiva, y borrada con la crate `zeroize` en cuanto deja de ser necesaria.
- **Cifrado en reposo**: la base de datos de la bóveda está cifrada de extremo a extremo con SQLCipher. Las exportaciones usan doble AEAD (una capa interna AES-256-GCM y una capa externa XChaCha20-Poly1305), con la cabecera vinculada a ambas etiquetas de autenticación.
- **Verificación independiente**: el proyecto ejecuta continuamente pruebas de mutación y pruebas de caos en su integración continua, además de las suites habituales de pruebas unitarias y de extremo a extremo, específicamente para detectar pruebas que pasan sin verificar realmente el comportamiento que dicen cubrir.

Si encuentras una vulnerabilidad, consulta la [Política de seguridad](#politica-de-seguridad) antes de abrir un ticket público.

## Plataformas compatibles

PWDnow se desarrolla y se prueba principalmente en **Ubuntu 26.04 LTS (Resolute)**. El instalador además detecta y admite:

- Debian y distribuciones derivadas de Debian (Ubuntu, Linux Mint, Pop!_OS, Zorin, Kali)
- Fedora y distribuciones de la familia RHEL (Fedora, RHEL, CentOS, Rocky Linux, AlmaLinux)

Tanto `x86_64` como `aarch64` están soportados por la cadena de herramientas de Rust. Otras distribuciones de Linux pueden funcionar, pero no forman parte de la matriz de pruebas habitual. Actualmente no existe una compilación para macOS o Windows.

## Primeros pasos

### Instalación rápida

```bash
git clone https://github.com/PWDnow/PWDnow-password-manager.git
cd PWDnow
./install.sh
```

El instalador detecta tu distribución, comprueba las dependencias que falten y ofrece instalarlas, audita tu configuración de SSH, comprueba conflictos de puertos, compila el daemon y el frontend web desde el código fuente, y los instala a ambos como servicios systemd que se ejecutan bajo usuarios de sistema dedicados y sin privilegios. No se instala nada con privilegios elevados más allá de lo que requieren systemd, AppArmor y la instalación de paquetes, y cada paso privilegiado se muestra antes de ejecutarse.

### Compilación desde el código fuente

Requisitos: Node.js 20 o superior, Rust 1.94 o superior (fijado en `daemon/rust-toolchain.toml`), `protoc`, y las cabeceras de desarrollo de `libsodium`, `sqlcipher` y `libfido2`.

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

O, desde `deploy/`:

```bash
make build          # daemon + web, modo release
make test            # cargo test + vitest
make install          # instala el binario, las unidades systemd, el perfil AppArmor y la configuración de nginx (requiere sudo)
```

La encapsulación de claves postcuántica está activada por defecto. `make build-pq` y `cargo build --release --features pq-hybrid-1024` se mantienen como alias explícitos de esta misma compilación por defecto, por claridad y por compatibilidad con documentación anterior. Usa `--features cnsa-strict` para el modo estricto CNSA 2.0.

### Configuración

Copia `web/.env.example` a `web/.env` y ajusta según sea necesario:

| Variable | Función |
|---|---|
| `DAEMON_GRPC_ADDR` | Dirección que usa la capa web para alcanzar al daemon (por defecto `127.0.0.1:50051`) |
| `VAULT_ORIGIN` | Origen de navegador permitido en producción, usado para las comprobaciones de origen de WebSocket |
| `BIND_HOST` | Interfaz en la que escucha el servidor web (por defecto `127.0.0.1`; usa `0.0.0.0` para acceso en red local) |
| `SSL`, `SSL_PORT`, `SSL_DIR` | HTTPS autofirmado opcional, generado por `web/scripts/generate-ssl.sh` |

## Uso

En el primer arranque, `Setup.tsx` guía la creación de la bóveda: elección de una contraseña maestra, registro opcional de una llave de seguridad física o de un TOTP, y el daemon crea una base de datos SQLCipher cifrada además de un archivo auxiliar en texto plano que registra solo lo que la página de inicio de sesión necesita (qué métodos MFA están configurados, si el inicio de sesión con contraseña siquiera está habilitado), de modo que nada tenga que descifrarse antes de que te hayas autenticado.

A partir de ahí:

- Organiza las credenciales en carpetas, añade campos personalizados y genera contraseñas robustas directamente en el sitio
- Activa el modo coacción y el modo viaje desde Ajustes si quieres poder presentar un estado seguro y verosímil bajo coacción o al cruzar una frontera
- Ejecuta el monitor de filtraciones integrado para comprobar tus contraseñas guardadas frente a una copia local y sin conexión de contraseñas comprometidas conocidas, sin ninguna consulta saliente por contraseña
- Exporta un archivo `.p2w` como copia de seguridad, o importa desde otro gestor de contraseñas, sin salir nunca de tu equipo

## Desarrollo

Estructura del repositorio:

```
PWDnow/
├── daemon/     Daemon de la bóveda en Rust. Toda la criptografía vive aquí.
├── web/        Frontend en React 19 + Express y proxy IPC.
├── monitor/    Proceso Rust independiente de monitorización y detección de fugas de memoria.
├── deploy/     Unidades systemd, perfil AppArmor, configuración de Nginx, Makefile.
├── proto/      Definiciones gRPC/protobuf compartidas entre el daemon y el web.
└── hibp/       Script que construye el filtro de Cuckoo HIBP sin conexión.
```

Consulta [`CLAUDE.md`](../../CLAUDE.md) para la referencia arquitectónica completa usada por colaboradores y herramientas automatizadas, y [`web/CLAUDE.md`](../../web/CLAUDE.md) para las convenciones específicas del frontend, incluido el registro de claves de localStorage, la lista de comprobación IPC para añadir un nuevo comando al daemon, y los límites criptográficos que el frontend nunca debe cruzar.

## Pruebas

```bash
# Daemon
cd daemon && cargo test
cargo test -- <test_name>       # ejecutar una sola prueba

# Pruebas unitarias web
cd web && npm run test
npx vitest run src/utils/crypto.test.ts   # un solo archivo

# Extremo a extremo (Playwright)
cd web && npx playwright test
npx playwright test e2e/comprehensive-platform.spec.ts   # recorrido completo de regresión
```

La integración continua ejecuta pruebas unitarias, pruebas de extremo a extremo, auditoría de dependencias, pruebas de mutación y pruebas de caos en cada push y pull request. `web/e2e/comprehensive-platform.spec.ts` es la puerta de regresión: recorre la autenticación (rutas de éxito y fallo), la navegación, las operaciones CRUD de carpetas y credenciales, el modo coacción y la destrucción de cuenta, y debe pasar antes de publicar cualquier cambio de frontend o de autenticación.

## Despliegue

Para cualquier uso más allá de una sola máquina local, pon Nginx delante del proceso Express:

- `deploy/nginx/vault.conf` gestiona la terminación TLS, HSTS y la limitación de tasa. Nginx no debe establecer su propia cabecera Content-Security-Policy, ya que el servidor Express inyecta un nonce nuevo por cada solicitud.
- `deploy/vault-daemon.service` ejecuta el daemon bajo un usuario de sistema dedicado `vault`, con `MemorySwapMax=0`, `NoNewPrivileges`, `PrivateTmp`, y únicamente la capacidad `CAP_IPC_LOCK` que necesita para el bloqueo de memoria.
- `deploy/apparmor.d/vault-daemon` confina el acceso al sistema de archivos y a las capacidades del daemon a nivel de kernel, y se aplica sin modificaciones tanto en hosts `x86_64` como `aarch64`.

`make install` (o `install.sh` para una instalación guiada completa) conecta todo esto, incluida la carga del perfil AppArmor y la activación de las unidades systemd.

## Política de seguridad

PWDnow maneja credenciales, así que un informe de vulnerabilidad aquí importa más que en la mayoría de proyectos. Si encuentras un problema de seguridad, por favor no abras un ticket público. En su lugar, usa el informe privado de vulnerabilidades de GitHub para este repositorio, o contacta directamente con los mantenedores. Incluye suficiente detalle para reproducir el problema y, si es posible, una evaluación del impacto. Confirmaremos la recepción con prontitud y acreditaremos a quienes lo deseen una vez publicada la corrección.

## Contribuir

Los tickets y las pull requests son bienvenidos. Antes de enviar un cambio:

- Ejecuta `make lint` (`cargo clippy -D warnings` y `tsc --noEmit`) y `make test`
- Para cambios de frontend o de autenticación, ejecuta la suite completa de regresión de Playwright
- Mantén los cambios criptográficos únicamente en el daemon; la capa web nunca debe obtener acceso a material de claves como efecto secundario de un cambio de función
- Sigue las convenciones descritas en `CLAUDE.md` y `web/CLAUDE.md`

## Licencia

PWDnow se distribuye bajo la [licencia MIT](../../LICENSE).
