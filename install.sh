#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║                    PWDnow Installer v1.0                        ║
# ║          Zero-Knowledge Password Manager for Linux              ║
# ╚══════════════════════════════════════════════════════════════════╝
set -euo pipefail

# ── Colors & Symbols ──────────────────────────────────────────────
RED=$'\033[1;31m'; GRN=$'\033[1;32m'; YLW=$'\033[1;33m'; BLU=$'\033[1;34m'
MAG=$'\033[1;35m'; CYN=$'\033[1;36m'; WHT=$'\033[1;37m'; DIM=$'\033[2m'
BOLD=$'\033[1m'; RST=$'\033[0m'
CHECK="${GRN}✔${RST}"; CROSS="${RED}✘${RST}"; WARN="${YLW}⚠${RST}"
ARROW="${CYN}➜${RST}"; DOT="${DIM}•${RST}"

# ── Port Configuration ────────────────────────────────────────────
WEB_PORT=1234
DAEMON_PORT=51234

# ── State Variables ───────────────────────────────────────────────
OS_FAMILY=""        # debian | fedora
OS_NAME=""          # Ubuntu, Debian, Fedora, Rocky, etc.
OS_VERSION=""       # e.g. 26.04, 42
OS_CODENAME=""      # e.g. resolute, noble
FIPS_ACTIVE=""      # yes | no
FIPS_SUPPORTED=""   # yes | no
MISSING_DEPS=()
PORT_CONFLICTS=()
TERM_WIDTH=$(tput cols 2>/dev/null || echo 80)

# ══════════════════════════════════════════════════════════════════
#  TUI Drawing Helpers
# ══════════════════════════════════════════════════════════════════

draw_line() {
    local ch="${1:-─}"
    printf "${DIM}"
    printf '%*s' "$TERM_WIDTH" '' | tr ' ' "$ch"
    printf "${RST}\n"
}

draw_header() {
    clear
    echo ""
    draw_line "═"
    printf "${BLU}${BOLD}"
    cat << 'BANNER'

    ██████╗ ██╗    ██╗██████╗ ███╗   ██╗ ██████╗ ██╗    ██╗
    ██╔══██╗██║    ██║██╔══██╗████╗  ██║██╔═══██╗██║    ██║
    ██████╔╝██║ █╗ ██║██║  ██║██╔██╗ ██║██║   ██║██║ █╗ ██║
    ██╔═══╝ ██║███╗██║██║  ██║██║╚██╗██║██║   ██║██║███╗██║
    ██║     ╚███╔███╔╝██████╔╝██║ ╚████║╚██████╔╝╚███╔███╔╝
    ╚═╝      ╚══╝╚══╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝  ╚══╝╚══╝

BANNER
    printf "${RST}"
    printf "    ${DIM}Zero-Knowledge Password Manager${RST}  ${MAG}v1.0${RST}\n"
    printf "    ${DIM}Secure • Offline • Open Source${RST}\n\n"
    draw_line "═"
    echo ""
}

section() {
    echo ""
    printf "  ${BLU}${BOLD}▸ %s${RST}\n" "$1"
    draw_line "─"
}

result_line() {
    # $1 = label, $2 = value, $3 = icon (optional)
    local icon="${3:-$DOT}"
    printf "    %-28s %s  %s\n" "$1" "$icon" "$2"
}

press_enter() {
    echo ""
    printf "  ${DIM}Press Enter to continue...${RST}"
    read -r
}

# ══════════════════════════════════════════════════════════════════
#  Step 1: OS Detection
# ══════════════════════════════════════════════════════════════════

detect_os() {
    section "SYSTEM DETECTION"

    if [ ! -f /etc/os-release ]; then
        printf "    ${CROSS}  Cannot read /etc/os-release. Unsupported system.\n"
        exit 1
    fi

    # shellcheck source=/dev/null
    source /etc/os-release

    OS_NAME="${NAME:-Unknown}"
    OS_VERSION="${VERSION_ID:-Unknown}"
    OS_CODENAME="${VERSION_CODENAME:-N/A}"
    local id_like="${ID_LIKE:-$ID}"

    # Determine family
    case "$id_like" in
        *debian*|*ubuntu*) OS_FAMILY="debian" ;;
        *fedora*|*rhel*)   OS_FAMILY="fedora" ;;
        *)
            case "$ID" in
                debian|ubuntu|linuxmint|pop|elementary|zorin|kali|raspbian)
                    OS_FAMILY="debian" ;;
                fedora|rhel|centos|rocky|alma|ol)
                    OS_FAMILY="fedora" ;;
                *)
                    OS_FAMILY="unknown" ;;
            esac
            ;;
    esac

    local family_display
    case "$OS_FAMILY" in
        debian) family_display="${GRN}Debian-based${RST}" ;;
        fedora) family_display="${CYN}Fedora/RHEL-based${RST}" ;;
        *)      family_display="${RED}Unknown${RST}" ;;
    esac

    local arch
    arch=$(uname -m)
    local kernel
    kernel=$(uname -r)

    result_line "Distribution:" "${WHT}${OS_NAME}${RST}" "$CHECK"
    result_line "Version:" "${WHT}${OS_VERSION}${RST} (${OS_CODENAME})" "$CHECK"
    result_line "Family:" "$family_display" "$CHECK"
    result_line "Architecture:" "${WHT}${arch}${RST}" "$CHECK"
    result_line "Kernel:" "${WHT}${kernel}${RST}" "$CHECK"

    if [ "$OS_FAMILY" = "unknown" ]; then
        echo ""
        printf "    ${CROSS}  ${RED}Unsupported distribution.${RST}\n"
        printf "    ${DIM}   PWDnow requires a Debian or Fedora-based system.${RST}\n"
        exit 1
    fi
}

# ══════════════════════════════════════════════════════════════════
#  Step 2: FIPS Check
# ══════════════════════════════════════════════════════════════════

check_fips() {
    section "FIPS 140-2/3 STATUS"

    # Check if FIPS is currently active
    if [ -f /proc/sys/crypto/fips_enabled ]; then
        local fips_val
        fips_val=$(cat /proc/sys/crypto/fips_enabled)
        if [ "$fips_val" = "1" ]; then
            FIPS_ACTIVE="yes"
        else
            FIPS_ACTIVE="no"
        fi
    else
        FIPS_ACTIVE="no"
    fi

    # Check if FIPS CAN be enabled on this OS
    FIPS_SUPPORTED="no"
    case "$OS_FAMILY" in
        debian)
            case "$ID" in
                ubuntu)
                    # Ubuntu Pro provides FIPS on 20.04+ LTS
                    local major="${OS_VERSION%%.*}"
                    if [ "$major" -ge 20 ] 2>/dev/null; then
                        FIPS_SUPPORTED="yes (Ubuntu Pro required)"
                    fi
                    ;;
                debian)
                    local major="${OS_VERSION%%.*}"
                    if [ "$major" -ge 12 ] 2>/dev/null; then
                        FIPS_SUPPORTED="yes (manual kernel config)"
                    fi
                    ;;
            esac
            ;;
        fedora)
            case "$ID" in
                rhel|centos|rocky|alma|ol)
                    FIPS_SUPPORTED="yes (built-in)"
                    ;;
                fedora)
                    local major="${OS_VERSION%%.*}"
                    if [ "$major" -ge 38 ] 2>/dev/null; then
                        FIPS_SUPPORTED="yes (fips-mode-setup)"
                    fi
                    ;;
            esac
            ;;
    esac

    if [ "$FIPS_ACTIVE" = "yes" ]; then
        result_line "FIPS Enabled:" "${GRN}Yes — Active${RST}" "$CHECK"
    else
        result_line "FIPS Enabled:" "${YLW}No — Not active${RST}" "$WARN"
    fi

    if [ "$FIPS_SUPPORTED" = "no" ]; then
        result_line "FIPS Available:" "${DIM}Not supported on this OS${RST}" "$CROSS"
    else
        result_line "FIPS Available:" "${GRN}${FIPS_SUPPORTED}${RST}" "$CHECK"
    fi

    echo ""
    printf "    ${DIM}PWDnow uses AES-256-GCM + Argon2id regardless of FIPS mode.${RST}\n"
    printf "    ${DIM}FIPS is optional but recommended for government/enterprise.${RST}\n"
}

# ══════════════════════════════════════════════════════════════════
#  Step 3: Port Check
# ══════════════════════════════════════════════════════════════════

check_ports() {
    section "PORT AVAILABILITY"

    PORT_CONFLICTS=()
    local all_clear=true

    for port in $WEB_PORT $DAEMON_PORT; do
        local label
        if [ "$port" = "$WEB_PORT" ]; then
            label="Web Server"
        else
            label="Vault Daemon"
        fi

        local pid_info
        pid_info=$(ss -tlnp "sport = :$port" 2>/dev/null | tail -n +2 || true)

        if [ -z "$pid_info" ]; then
            result_line "Port ${port} (${label}):" "${GRN}Available${RST}" "$CHECK"
        else
            all_clear=false
            local proc_name
            proc_name=$(echo "$pid_info" | grep -oP 'users:\(\("\K[^"]+' || echo "unknown")
            local proc_pid
            proc_pid=$(echo "$pid_info" | grep -oP 'pid=\K[0-9]+' || echo "?")

            result_line "Port ${port} (${label}):" "${RED}IN USE${RST} by ${WHT}${proc_name}${RST} (PID ${proc_pid})" "$CROSS"
            PORT_CONFLICTS+=("${port}:${proc_name}:${proc_pid}")
        fi
    done

    if [ "$all_clear" = true ]; then
        echo ""
        printf "    ${CHECK}  All required ports are free.\n"
        return 0
    fi

    # Offer to kill conflicting services
    echo ""
    printf "    ${WARN}  ${YLW}Port conflict(s) detected.${RST}\n"
    printf "    ${DIM}   PWDnow needs these ports to run.${RST}\n"
    echo ""
    printf "    ${BOLD}Would you like to stop the conflicting services?${RST}\n"
    printf "    ${DIM}[y] Yes, stop them  [n] No, abort  [s] Skip (advanced)${RST}\n"
    printf "    ${ARROW} "
    read -r choice

    case "$choice" in
        y|Y|yes|YES)
            for conflict in "${PORT_CONFLICTS[@]}"; do
                IFS=':' read -r c_port c_name c_pid <<< "$conflict"
                printf "    ${ARROW}  Stopping ${WHT}${c_name}${RST} (PID ${c_pid}) on port ${c_port}..."
                if kill -TERM "$c_pid" 2>/dev/null; then
                    sleep 1
                    # Force kill if still alive
                    if kill -0 "$c_pid" 2>/dev/null; then
                        kill -9 "$c_pid" 2>/dev/null || true
                    fi
                    printf " ${CHECK}\n"
                else
                    printf " ${CROSS} ${RED}Permission denied. Try running with sudo.${RST}\n"
                    exit 1
                fi
            done
            echo ""
            printf "    ${CHECK}  Ports cleared successfully.\n"
            ;;
        s|S)
            printf "    ${WARN}  Skipping port check. Installation may fail.\n"
            ;;
        *)
            printf "    ${CROSS}  Aborting installation.\n"
            exit 1
            ;;
    esac
}

# ══════════════════════════════════════════════════════════════════
#  Step 4: Dependency Check
# ══════════════════════════════════════════════════════════════════

check_dependencies() {
    section "DEPENDENCY CHECK"

    MISSING_DEPS=()

    local deps=(
        "curl:curl"
        "python3:python3"
        "node:nodejs"
        "npm:npm"
        "cargo:rust/cargo"
        "git:git"
        "openssl:openssl"
        "make:make"
        "gcc:gcc"
        "pkg-config:pkg-config"
    )

    for entry in "${deps[@]}"; do
        IFS=':' read -r cmd pkg <<< "$entry"
        if command -v "$cmd" &>/dev/null; then
            local ver
            case "$cmd" in
                node)    ver=$(node --version 2>/dev/null || echo "?") ;;
                python3) ver=$(python3 --version 2>/dev/null | awk '{print $2}' || echo "?") ;;
                cargo)   ver=$(cargo --version 2>/dev/null | awk '{print $2}' || echo "?") ;;
                curl)    ver=$(curl --version 2>/dev/null | head -1 | awk '{print $2}' || echo "?") ;;
                gcc)     ver=$(gcc --version 2>/dev/null | head -1 | grep -oP '[0-9]+\.[0-9]+' | head -1 || echo "?") ;;
                *)       ver="installed" ;;
            esac
            result_line "${pkg}:" "${GRN}${ver}${RST}" "$CHECK"
        else
            result_line "${pkg}:" "${RED}Not found${RST}" "$CROSS"
            MISSING_DEPS+=("$pkg")
        fi
    done

    if [ ${#MISSING_DEPS[@]} -eq 0 ]; then
        echo ""
        printf "    ${CHECK}  All dependencies satisfied.\n"
        return 0
    fi

    echo ""
    printf "    ${WARN}  ${YLW}Missing ${#MISSING_DEPS[@]} dependency(s):${RST} ${MISSING_DEPS[*]}\n"
    echo ""
    printf "    ${BOLD}Install missing dependencies now?${RST} [y/n]\n"
    printf "    ${ARROW} "
    read -r choice

    if [[ "$choice" =~ ^[Yy] ]]; then
        install_missing_deps
    else
        printf "    ${CROSS}  Cannot proceed without required dependencies.\n"
        exit 1
    fi
}

install_missing_deps() {
    echo ""
    printf "    ${ARROW}  Installing missing packages...\n"

    # Build the package list with correct names for the OS
    local pkgs=()
    for dep in "${MISSING_DEPS[@]}"; do
        case "$dep" in
            nodejs)
                if [ "$OS_FAMILY" = "debian" ]; then pkgs+=("nodejs")
                else pkgs+=("nodejs"); fi
                ;;
            npm)        pkgs+=("npm") ;;
            rust/cargo)
                printf "    ${ARROW}  Rust will be installed via rustup...\n"
                curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
                # shellcheck source=/dev/null
                source "$HOME/.cargo/env"
                ;;
            python3)    pkgs+=("python3") ;;
            curl)       pkgs+=("curl") ;;
            git)        pkgs+=("git") ;;
            openssl)
                if [ "$OS_FAMILY" = "debian" ]; then pkgs+=("openssl" "libssl-dev")
                else pkgs+=("openssl" "openssl-devel"); fi
                ;;
            make)       pkgs+=("make") ;;
            gcc)
                if [ "$OS_FAMILY" = "debian" ]; then pkgs+=("build-essential")
                else pkgs+=("gcc" "gcc-c++"); fi
                ;;
            pkg-config)
                if [ "$OS_FAMILY" = "debian" ]; then pkgs+=("pkg-config")
                else pkgs+=("pkgconf-pkg-config"); fi
                ;;
        esac
    done

    if [ ${#pkgs[@]} -gt 0 ]; then
        case "$OS_FAMILY" in
            debian)
                sudo apt-get update -qq
                sudo apt-get install -y "${pkgs[@]}"
                ;;
            fedora)
                sudo dnf install -y "${pkgs[@]}"
                ;;
        esac
    fi

    printf "    ${CHECK}  Dependencies installed.\n"
}

# ══════════════════════════════════════════════════════════════════
#  Step 5: Summary & Confirm
# ══════════════════════════════════════════════════════════════════

show_summary() {
    section "INSTALLATION SUMMARY"

    local family_display
    case "$OS_FAMILY" in
        debian) family_display="${GRN}Debian${RST}" ;;
        fedora) family_display="${CYN}Fedora${RST}" ;;
    esac

    result_line "System:" "${WHT}${OS_NAME} ${OS_VERSION}${RST} (${family_display})" "$CHECK"

    if [ "$FIPS_ACTIVE" = "yes" ]; then
        result_line "FIPS:" "${GRN}Active${RST}" "$CHECK"
    else
        result_line "FIPS:" "${YLW}Inactive${RST}" "$WARN"
    fi

    result_line "Web Port:" "${WHT}${WEB_PORT}${RST}" "$CHECK"
    result_line "Daemon Port:" "${WHT}${DAEMON_PORT}${RST}" "$CHECK"
    result_line "Dependencies:" "${GRN}All satisfied${RST}" "$CHECK"

    echo ""
    printf "    ${DIM}Install location:  /opt/pwdnow${RST}\n"
    printf "    ${DIM}Data directory:    /var/lib/vault-daemon${RST}\n"
    printf "    ${DIM}Config directory:  /etc/vault-daemon${RST}\n"
    printf "    ${DIM}Services:          vault-daemon, pwdnow-web${RST}\n"

    echo ""
    draw_line "─"
    printf "\n    ${BOLD}Proceed with installation?${RST} [y/n]\n"
    printf "    ${ARROW} "
    read -r choice

    if [[ ! "$choice" =~ ^[Yy] ]]; then
        printf "\n    ${DIM}Installation cancelled.${RST}\n\n"
        exit 0
    fi
}

# ══════════════════════════════════════════════════════════════════
#  Step 6: Install
# ══════════════════════════════════════════════════════════════════

run_install() {
    section "INSTALLING PWDNOW"

    local INSTALL_DIR="/opt/pwdnow"
    local SCRIPT_DIR
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # ── Create system user ────────────────────────────────────────
    printf "    ${ARROW}  Creating system users..."
    if ! id -u vault &>/dev/null; then
        sudo useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/vault-daemon vault
    fi
    if ! id -u pwdnow &>/dev/null; then
        sudo useradd --system --shell /usr/sbin/nologin --home-dir "$INSTALL_DIR" pwdnow
    fi
    printf " ${CHECK}\n"

    # ── Create directories ────────────────────────────────────────
    printf "    ${ARROW}  Creating directories..."
    sudo mkdir -p "$INSTALL_DIR" /var/lib/vault-daemon /var/lib/vault-server
    sudo mkdir -p /etc/vault-daemon /var/log/pwdnow /run/vault-daemon
    printf " ${CHECK}\n"

    # ── Copy project files ────────────────────────────────────────
    printf "    ${ARROW}  Copying project files..."
    sudo cp -r "$SCRIPT_DIR/web" "$INSTALL_DIR/web"
    sudo cp -r "$SCRIPT_DIR/daemon" "$INSTALL_DIR/daemon"
    sudo cp -r "$SCRIPT_DIR/deploy" "$INSTALL_DIR/deploy"
    sudo cp -r "$SCRIPT_DIR/proto" "$INSTALL_DIR/proto"
    printf " ${CHECK}\n"

    # ── Build daemon ──────────────────────────────────────────────
    printf "    ${ARROW}  Building vault daemon (this may take a few minutes)...\n"
    (cd "$INSTALL_DIR/daemon" && sudo -u vault cargo build --release 2>&1 | while IFS= read -r line; do
        printf "\r    ${DIM}    %s${RST}" "${line:0:$((TERM_WIDTH - 12))}"
    done)
    printf "\r    %-${TERM_WIDTH}s\n" ""
    sudo install -m755 "$INSTALL_DIR/daemon/target/release/vault-daemon" /usr/local/bin/vault-daemon
    printf "    ${CHECK}  Daemon built and installed.\n"

    # ── Build web frontend ────────────────────────────────────────
    printf "    ${ARROW}  Installing web dependencies...\n"
    (cd "$INSTALL_DIR/web" && sudo npm install --production 2>&1 | tail -1)
    printf "    ${ARROW}  Building web frontend...\n"
    (cd "$INSTALL_DIR/web" && sudo npm run build 2>&1 | tail -1)
    printf "    ${CHECK}  Web frontend built.\n"

    # ── Generate gRPC auth token ──────────────────────────────────
    printf "    ${ARROW}  Generating gRPC auth token..."
    local grpc_token
    grpc_token=$(openssl rand -hex 32)
    echo "DAEMON_GRPC_TOKEN=${grpc_token}" | sudo tee /etc/vault-daemon/grpc.env >/dev/null
    sudo chmod 600 /etc/vault-daemon/grpc.env
    printf " ${CHECK}\n"

    # ── Install systemd services ──────────────────────────────────
    printf "    ${ARROW}  Installing systemd services..."
    sudo cp "$INSTALL_DIR/deploy/vault-daemon.service" /etc/systemd/system/
    sudo cp "$INSTALL_DIR/deploy/pwdnow-web.service" /etc/systemd/system/
    # Patch the web service to use our port
    sudo sed -i "s/PORT=1234/PORT=${WEB_PORT}/" /etc/systemd/system/pwdnow-web.service
    sudo systemctl daemon-reload
    printf " ${CHECK}\n"

    # ── Set permissions ───────────────────────────────────────────
    printf "    ${ARROW}  Setting permissions..."
    sudo chown -R vault:vault /var/lib/vault-daemon /run/vault-daemon
    sudo chown -R pwdnow:pwdnow /var/lib/vault-server /var/log/pwdnow "$INSTALL_DIR/web"
    sudo chmod 700 /var/lib/vault-daemon
    printf " ${CHECK}\n"

    # ── Enable & start services ───────────────────────────────────
    printf "    ${ARROW}  Starting services...\n"
    sudo systemctl enable vault-daemon pwdnow-web
    sudo systemctl start vault-daemon
    sleep 2
    sudo systemctl start pwdnow-web
    printf "    ${CHECK}  Services started.\n"
}

# ══════════════════════════════════════════════════════════════════
#  Step 7: Post-Install
# ══════════════════════════════════════════════════════════════════

show_complete() {
    echo ""
    draw_line "═"
    echo ""
    printf "${GRN}${BOLD}"
    cat << 'DONE'
     ___           _        _ _       _   _
    |_ _|_ __  ___| |_ __ _| | | __ _| |_(_) ___  _ __
     | || '_ \/ __| __/ _` | | |/ _` | __| |/ _ \| '_ \
     | || | | \__ \ || (_| | | | (_| | |_| | (_) | | | |
    |___|_| |_|___/\__\__,_|_|_|\__,_|\__|_|\___/|_| |_|
      ____                      _      _       _
     / ___|___  _ __ ___  _ __ | | ___| |_ ___| |
    | |   / _ \| '_ ` _ \| '_ \| |/ _ \ __/ _ \ |
    | |__| (_) | | | | | | |_) | |  __/ ||  __/_|
     \____\___/|_| |_| |_| .__/|_|\___|\__\___(_)
                          |_|
DONE
    printf "${RST}\n"
    draw_line "═"

    echo ""
    printf "    ${CHECK}  ${GRN}${BOLD}PWDnow has been installed successfully!${RST}\n"
    echo ""
    printf "    ${BOLD}Access your vault:${RST}\n"
    printf "      ${ARROW}  ${WHT}https://localhost:${WEB_PORT}${RST}\n"
    echo ""
    printf "    ${BOLD}Service management:${RST}\n"
    printf "      ${DOT}  ${DIM}sudo systemctl status vault-daemon${RST}\n"
    printf "      ${DOT}  ${DIM}sudo systemctl status pwdnow-web${RST}\n"
    printf "      ${DOT}  ${DIM}sudo journalctl -u pwdnow-web -f${RST}\n"
    echo ""
    printf "    ${BOLD}Uninstall:${RST}\n"
    printf "      ${DOT}  ${DIM}sudo systemctl disable --now vault-daemon pwdnow-web${RST}\n"
    printf "      ${DOT}  ${DIM}sudo rm -rf /opt/pwdnow${RST}\n"
    echo ""

    if [ "$FIPS_ACTIVE" != "yes" ] && [ "$FIPS_SUPPORTED" != "no" ]; then
        printf "    ${WARN}  ${YLW}FIPS is available but not active on this system.${RST}\n"
        printf "       ${DIM}For government/enterprise, enable FIPS with:${RST}\n"
        case "$OS_FAMILY" in
            fedora) printf "       ${DIM}  sudo fips-mode-setup --enable && reboot${RST}\n" ;;
            debian) printf "       ${DIM}  See Ubuntu Pro FIPS documentation${RST}\n" ;;
        esac
        echo ""
    fi

    draw_line "─"
    printf "    ${DIM}Thank you for choosing PWDnow.${RST}\n"
    printf "    ${DIM}Your passwords. Your hardware. Your rules.${RST}\n"
    echo ""
}

# ══════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════

main() {
    # Must not run as root directly (we use sudo where needed)
    if [ "$EUID" -eq 0 ]; then
        echo "Please run this installer as a normal user (not root)."
        echo "The installer will use sudo when elevated privileges are needed."
        exit 1
    fi

    draw_header
    detect_os
    check_fips
    press_enter
    check_ports
    check_dependencies
    press_enter
    show_summary
    run_install
    show_complete
}

main "$@"
