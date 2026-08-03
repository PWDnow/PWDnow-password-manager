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

# Vite 6 / React 19 need a current Node LTS. Distro-default apt/dnf packages
# are frequently years out of date (Ubuntu 22.04's "nodejs" is v12) and would
# fail the build silently late in the install — so a version floor is
# enforced below rather than just checking that `node` exists at all.
NODE_MIN_MAJOR=24

# ── State Variables ───────────────────────────────────────────────
OS_FAMILY=""        # debian | fedora
OS_NAME=""          # Ubuntu, Debian, Fedora, Rocky, etc.
OS_VERSION=""       # e.g. 26.04, 42
OS_CODENAME=""      # e.g. resolute, noble
FIPS_ACTIVE=""      # yes | no
FIPS_SUPPORTED=""   # yes | no
SSL_ENABLED="no"    # set in run_install(); read by show_complete()
MISSING_DEPS=()
PORT_CONFLICTS=()
SUDO_KEEPALIVE_PID=""  # set in main(); must be global — the EXIT trap that
                       # reads it fires after main() returns, once any
                       # 'local' copy would already be gone under set -u
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
#  Dual progress bars (run_install only) — WinRAR-style: one bar for
#  overall install progress across all steps, one for the current step's
#  own fine-grained progress (file copy %, crates compiled, ...).
# ══════════════════════════════════════════════════════════════════

INSTALL_TOTAL_STEPS=12
INSTALL_CURRENT_STEP=0

draw_progress_bar() {
    # $1=label $2=pct(0-100) $3=width(optional)
    local label="$1" pct="${2:-0}" width="${3:-32}"
    [[ "$pct" =~ ^[0-9]+$ ]] || pct=0
    [ "$pct" -gt 100 ] && pct=100
    local filled=$(( pct * width / 100 ))
    local empty=$(( width - filled ))
    printf "%-8s ${GRN}[" "$label"
    # tr is byte-oriented and mangles multi-byte UTF-8 chars like █/░ into
    # replacement characters — use printf's own format-string repetition
    # instead (each extra positional arg re-triggers the format, printing
    # the literal character intact rather than manipulating its bytes).
    [ "$filled" -gt 0 ] && printf '█%.0s' $(seq 1 "$filled")
    printf "${DIM}"
    [ "$empty" -gt 0 ] && printf '░%.0s' $(seq 1 "$empty")
    printf "${RST}${GRN}]${RST} %3d%%" "$pct"
}

# Prints the (static) overall bar for the step about to start, then the
# step's own arrow/label line. Call once at the top of each run_install step.
step_start() {
    INSTALL_CURRENT_STEP=$((INSTALL_CURRENT_STEP + 1))
    local overall_pct=$(( (INSTALL_CURRENT_STEP - 1) * 100 / INSTALL_TOTAL_STEPS ))
    echo ""
    printf "    "
    draw_progress_bar "Overall" "$overall_pct" 32
    printf "  Step %d/%d\n" "$INSTALL_CURRENT_STEP" "$INSTALL_TOTAL_STEPS"
    printf "    ${ARROW}  %s" "$1"
}

# Live-redraws a second "Current" bar on its own line via \r — call
# repeatedly while a step's real work is progressing (file copy, compiling).
step_progress() {
    local pct="$1" label="$2"
    printf "\r    "
    draw_progress_bar "Current" "$pct" 32
    printf "  %-50s" "$label"
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

# Checks fips-updates' *actual* status/availability via 'pro status --all'
# (the plain 'pro status' hides entitlements that aren't available on this
# machine, which is exactly the case we need to detect) and offers to enable
# it if it's available and not already on. Must only be called once Pro is
# known to be attached. Never deletes its own log on failure — leave it for
# the user to actually read.
offer_enable_fips_updates() {
    local json avail status
    json=$(sudo pro status --all --format=json 2>/dev/null || echo '{}')
    if command -v python3 &>/dev/null; then
        local parsed
        parsed=$(printf '%s' "$json" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    for s in (d.get("services") or []):
        if s.get("name") == "fips-updates":
            print(s.get("available",""), s.get("status",""))
            break
    else:
        print("", "")
except Exception:
    print("", "")')
        avail=$(printf '%s' "$parsed" | awk '{print $1}')
        status=$(printf '%s' "$parsed" | awk '{print $2}')
    else
        avail=""
        status=""
        printf '%s' "$json" | grep -qE '"name"[[:space:]]*:[[:space:]]*"fips-updates"[^}]*"status"[[:space:]]*:[[:space:]]*"enabled"' && status="enabled"
    fi

    if [ "$status" = "enabled" ]; then
        printf "    ${GRN}  FIPS-updates is already enabled.${RST} FIPS shows inactive above because\n"
        printf "    ${DIM}   it needs a reboot to actually take effect — reboot when convenient.${RST}\n"
        FIPS_SUPPORTED="yes (enabled, pending reboot)"
        return 0
    fi

    if [ "$avail" = "no" ]; then
        local arch
        arch=$(uname -m)
        printf "    ${CROSS}  ${YLW}FIPS-updates is entitled on your subscription but not available on\n"
        printf "    ${CROSS}  ${YLW}this machine's architecture (${arch}).${RST} Canonical currently only ships\n"
        printf "    ${DIM}   FIPS-certified crypto packages for x86_64/amd64 — there's nothing to\n"
        printf "    ${DIM}   enable here regardless of subscription tier.${RST}\n"
        return 1
    fi

    printf "    ${WARN}  ${YLW}Enabling FIPS replaces core crypto libraries system-wide and\n"
    printf "    ${WARN}  ${YLW}requires a REBOOT to take effect. It is not easily reversible.${RST}\n"
    printf "    ${BOLD}Enable FIPS-updates now?${RST} [y/n]\n"
    printf "    ${ARROW} "
    read -r fips_confirm
    if [[ "$fips_confirm" =~ ^[Yy] ]]; then
        printf "    ${ARROW}  Enabling FIPS-updates (this can take a minute)..."
        if sudo pro enable fips-updates --assume-yes &>/tmp/pwdnow-pro-fips.log; then
            printf " ${CHECK}\n"
            printf "    ${GRN}${BOLD}Reboot required${RST} before FIPS mode actually takes effect.\n"
            FIPS_SUPPORTED="yes (enabled, pending reboot)"
            rm -f /tmp/pwdnow-pro-fips.log
        else
            printf " ${CROSS}\n"
            printf "    ${DIM}   Details: /tmp/pwdnow-pro-fips.log (kept — not deleted on failure).${RST}\n"
        fi
    else
        printf "    ${DIM}  Skipped — enable it later with: sudo pro enable fips-updates${RST}\n"
    fi
}

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

    # Offer to enable it right now if this is Ubuntu and Pro is the missing piece.
    if [ "$FIPS_ACTIVE" != "yes" ] && [[ "$FIPS_SUPPORTED" == *"Ubuntu Pro"* ]]; then
        echo ""
        draw_line "─"
        echo ""

        # Check REAL attachment state before ever asking for a token —
        # FIPS_SUPPORTED above only reflects "this OS/version is capable of
        # it", not whether Pro is already attached on this box.
        local pro_attached="no"
        if command -v pro &>/dev/null; then
            local pro_json
            pro_json=$(sudo pro status --format=json 2>/dev/null || echo '{}')
            if command -v python3 &>/dev/null; then
                pro_attached=$(printf '%s' "$pro_json" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print("yes" if d.get("attached") else "no")
except Exception:
    print("no")' 2>/dev/null || echo "no")
            else
                printf '%s' "$pro_json" | grep -qE '"attached"[[:space:]]*:[[:space:]]*true' && pro_attached="yes"
            fi
        fi

        if [ "$pro_attached" = "yes" ]; then
            printf "    ${CHECK}  Ubuntu Pro is already attached on this machine — no token needed.\n"
            offer_enable_fips_updates || true
        else
            printf "    ${BOLD}${MAG}┌─ Ubuntu Pro ─────────────────────────────────────────────┐${RST}\n"
            printf "    ${BOLD}${MAG}│${RST} Unlocks FIPS 140-3 validated crypto modules + extended     ${BOLD}${MAG}│${RST}\n"
            printf "    ${BOLD}${MAG}│${RST} security patching. ${GRN}Free for personal use${RST} (up to 5 machines). ${BOLD}${MAG}│${RST}\n"
            printf "    ${BOLD}${MAG}└──────────────────────────────────────────────────────────┘${RST}\n\n"
            printf "    ${BOLD}Do you have an Ubuntu Pro subscription/token?${RST}\n"
            printf "    ${DIM}[1] Yes, I have a token   [2] Maybe later${RST}\n"
            printf "    ${ARROW} "
            read -r pro_choice

            if [ "$pro_choice" = "1" ]; then
                printf "\n    Ubuntu Pro token (from https://ubuntu.com/pro/dashboard), input hidden: "
                read -rs pro_token
                echo ""
                if [ -z "$pro_token" ]; then
                    printf "    ${WARN}  No token entered — skipping.\n"
                elif ! command -v pro &>/dev/null; then
                    printf "    ${CROSS}  'pro' (ubuntu-advantage-tools) not found on this system.\n"
                else
                    printf "    ${ARROW}  Attaching Ubuntu Pro..."
                    if sudo pro attach "$pro_token" &>/tmp/pwdnow-pro-attach.log; then
                        printf " ${CHECK}\n"
                        echo ""
                        offer_enable_fips_updates || true
                        rm -f /tmp/pwdnow-pro-attach.log
                    else
                        printf " ${CROSS}\n"
                        printf "    ${DIM}   Check the token and try 'sudo pro attach <token>' manually.\n"
                        printf "    ${DIM}   Details: /tmp/pwdnow-pro-attach.log (kept — not deleted on failure).${RST}\n"
                    fi
                fi
            else
                printf "\n    ${DIM}No problem — attach anytime with: sudo pro attach <token>${RST}\n"
            fi
        fi
    fi
}

# ══════════════════════════════════════════════════════════════════
#  Step 3: SSH Security Audit
# ══════════════════════════════════════════════════════════════════
#
# Read-only reporting, plus tiered fixes by risk:
#   - ML-KEM (PQ) KEX preference: additive drop-in, reload only -> auto-offered
#   - Extra SSH port: ADDS a port, never removes :22 -> auto-offered
#   - Disabling password auth: can lock you out if no key is set up -> advisory only, never auto-applied

# Aggressively frees a TCP port: SIGTERM, then SIGKILL, and — if the PID is
# tracked by a systemd unit that would just respawn it (Restart=on-failure
# etc.) — stops that unit too, since kill -9 alone can't out-run a supervisor.
# Retries a few times since a respawn or a slow-dying process can race the
# first attempt. Returns 0 once the port is confirmed free, 1 otherwise.
force_free_port() {
    local port="$1"
    local attempt
    for attempt in 1 2 3; do
        local pid_info
        pid_info=$(ss -tlnp "sport = :${port}" 2>/dev/null | tail -n +2 || true)
        [ -z "$pid_info" ] && return 0

        local pid
        pid=$(printf '%s' "$pid_info" | grep -oP 'pid=\K[0-9]+' | head -1)
        [ -z "$pid" ] && return 1

        local unit
        unit=$(sudo systemctl status "$pid" 2>/dev/null | awk '/●/{print $2; exit}')
        if [ -n "$unit" ]; then
            printf "    ${ARROW}  Stopping systemd unit ${WHT}${unit}${RST} (owns PID ${pid}, would respawn otherwise)...\n"
            sudo systemctl stop "$unit" 2>/dev/null || true
        fi

        sudo kill -TERM "$pid" 2>/dev/null || true
        sleep 1
        if kill -0 "$pid" 2>/dev/null; then
            sudo kill -9 "$pid" 2>/dev/null || true
            sleep 1
        fi
    done

    pid_info=$(ss -tlnp "sport = :${port}" 2>/dev/null | tail -n +2 || true)
    [ -z "$pid_info" ]
}

audit_ssh() {
    section "SSH SECURITY AUDIT"

    if ! command -v sshd &>/dev/null; then
        printf "    ${DOT}  No SSH server installed — nothing to audit.\n"
        return 0
    fi

    local effective
    effective=$(sudo sshd -T 2>/dev/null || true)

    local ssh_port ssh_pwauth ssh_kex ssh_ver
    ssh_port=$(printf '%s\n' "$effective" | awk 'tolower($1)=="port"{print $2; exit}')
    ssh_pwauth=$(printf '%s\n' "$effective" | awk 'tolower($1)=="passwordauthentication"{print $2; exit}')
    ssh_kex=$(printf '%s\n' "$effective" | awk 'tolower($1)=="kexalgorithms"{print $2; exit}')
    ssh_ver=$(ssh -V 2>&1 | grep -oP 'OpenSSH_\K[0-9]+\.[0-9]+' | head -1)
    [ -z "$ssh_port" ] && ssh_port="22"

    if [ "$ssh_port" = "22" ]; then
        result_line "SSH port:" "${YLW}22 (default)${RST}" "$WARN"
    else
        result_line "SSH port:" "${GRN}${ssh_port} (non-default)${RST}" "$CHECK"
    fi

    if [ "$ssh_pwauth" = "yes" ]; then
        result_line "Password auth:" "${YLW}Enabled${RST}" "$WARN"
    elif [ "$ssh_pwauth" = "no" ]; then
        result_line "Password auth:" "${GRN}Disabled (key-only)${RST}" "$CHECK"
    else
        result_line "Password auth:" "${DIM}Could not determine${RST}" "$DOT"
    fi

    result_line "OpenSSH version:" "${WHT}${ssh_ver:-unknown}${RST}" "$CHECK"

    local client_supports_mlkem="no"
    ssh -Q kex 2>/dev/null | grep -qx "mlkem768x25519-sha256" && client_supports_mlkem="yes"

    local mlkem_active="unknown"
    if [ -z "$ssh_kex" ]; then
        # No explicit override in sshd_config: OpenSSH's own compiled-in
        # default KexAlgorithms list applies, which is mlkem768x25519-sha256
        # first on 9.9+ (and sntrup761x25519-sha512 first on 8.5-9.8).
        if [ "$client_supports_mlkem" = "yes" ]; then
            mlkem_active="yes (built-in default)"
        else
            mlkem_active="no (OpenSSH too old for ML-KEM)"
        fi
    else
        if printf '%s' "$ssh_kex" | grep -q "mlkem768x25519-sha256"; then
            mlkem_active="yes (explicitly configured)"
        else
            mlkem_active="no (KexAlgorithms is explicitly restricted in config and excludes it)"
        fi
    fi

    case "$mlkem_active" in
        yes*) result_line "ML-KEM (PQ) KEX:" "${GRN}${mlkem_active}${RST}" "$CHECK" ;;
        *)    result_line "ML-KEM (PQ) KEX:" "${YLW}${mlkem_active}${RST}" "$WARN" ;;
    esac

    echo ""

    # ── Low-risk, additive: prefer ML-KEM without removing anything ────
    if [[ "$mlkem_active" == no* ]] && [ "$client_supports_mlkem" = "yes" ]; then
        printf "    ${BOLD}Enable ML-KEM post-quantum key exchange?${RST}\n"
        printf "    ${DIM}Adds it as the top-preferred algorithm via a drop-in config — nothing\n"
        printf "    ${DIM}is removed, older clients still negotiate normally. [y/N]${RST}\n"
        printf "    ${ARROW} "
        read -r kex_choice
        if [[ "$kex_choice" =~ ^[Yy] ]]; then
            local fallback_kex="${ssh_kex:-curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512}"
            echo "KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,${fallback_kex}" \
                | sudo tee /etc/ssh/sshd_config.d/99-pwdnow-pqkex.conf >/dev/null
            if sudo sshd -t 2>/tmp/pwdnow-sshd-test.log; then
                sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd 2>/dev/null || true
                printf "    ${CHECK}  ML-KEM hybrid KEX now preferred (existing sessions unaffected).\n"
            else
                sudo rm -f /etc/ssh/sshd_config.d/99-pwdnow-pqkex.conf
                printf "    ${CROSS}  Generated config failed sshd -t validation — reverted, nothing changed.\n"
                printf "    ${DIM}   Details: /tmp/pwdnow-sshd-test.log${RST}\n"
            fi
        fi
        echo ""
    fi

    # ── Medium-risk: offer to ADD a non-default port, never remove :22 ──
    printf "    ${DIM}Recommendation: also listen on a non-default port to cut down on\n"
    printf "    ${DIM}automated scanner noise. This only ${BOLD}adds${RST}${DIM} a port — :22 stays active,\n"
    printf "    ${DIM}so this alone can't lock you out. Add one now? [y/N]${RST}\n"
    printf "    ${ARROW} "
    read -r port_choice
    if [[ "$port_choice" =~ ^[Yy] ]]; then
        printf "    New SSH port to add (1024-65535): "
        read -r new_ssh_port

        # Check the chosen port isn't already in use before touching sshd_config.
        while [[ "$new_ssh_port" =~ ^[0-9]+$ ]] && [ "$new_ssh_port" -ge 1024 ] && [ "$new_ssh_port" -le 65535 ]; do
            local busy_info
            busy_info=$(ss -tlnp "sport = :${new_ssh_port}" 2>/dev/null | tail -n +2 || true)
            [ -z "$busy_info" ] && break

            local busy_name busy_pid
            busy_name=$(printf '%s' "$busy_info" | grep -oP 'users:\(\("\K[^"]+' || echo "unknown")
            busy_pid=$(printf '%s' "$busy_info" | grep -oP 'pid=\K[0-9]+' || echo "?")
            printf "    ${WARN}  ${YLW}Port ${new_ssh_port} is already in use by ${busy_name} (PID ${busy_pid}).${RST}\n"
            printf "    ${BOLD}[1]${RST} Pick a different port  ${BOLD}[2]${RST} Force it free and use this one anyway  ${BOLD}[3]${RST} Cancel\n"
            printf "    ${ARROW} "
            read -r busy_choice
            case "$busy_choice" in
                1)
                    printf "    New SSH port to add (1024-65535): "
                    read -r new_ssh_port
                    ;;
                2)
                    printf "    ${ARROW}  Freeing port ${new_ssh_port}..."
                    if force_free_port "$new_ssh_port"; then
                        printf " ${CHECK}\n"
                        break
                    else
                        printf " ${CROSS}  ${RED}Could not free it — try a different port.${RST}\n"
                        printf "    New SSH port to add (1024-65535): "
                        read -r new_ssh_port
                    fi
                    ;;
                *)
                    printf "    ${DIM}  Cancelled.\n"
                    new_ssh_port=""
                    break
                    ;;
            esac
        done

        if [[ "$new_ssh_port" =~ ^[0-9]+$ ]] && [ "$new_ssh_port" -ge 1024 ] && [ "$new_ssh_port" -le 65535 ]; then
            echo "Port ${new_ssh_port}" | sudo tee /etc/ssh/sshd_config.d/99-pwdnow-extra-port.conf >/dev/null
            if sudo sshd -t 2>/tmp/pwdnow-sshd-test.log; then
                # Restart (not reload) is required to bind the new listening
                # socket. Already-established sessions keep running — sshd
                # restart only affects the master listener, not the forked
                # per-session child processes.
                sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd 2>/dev/null || true
                command -v ufw &>/dev/null && sudo ufw allow "${new_ssh_port}/tcp" 2>/dev/null || true
                printf "    ${CHECK}  Port ${new_ssh_port} added — port 22 is still active too.\n"
                printf "    ${DIM}   Test the new port from a SEPARATE terminal before removing :22 yourself.${RST}\n"
            else
                sudo rm -f /etc/ssh/sshd_config.d/99-pwdnow-extra-port.conf
                printf "    ${CROSS}  Generated config failed sshd -t validation — reverted, nothing changed.\n"
                printf "    ${DIM}   Details: /tmp/pwdnow-sshd-test.log${RST}\n"
            fi
        elif [ -n "$new_ssh_port" ]; then
            printf "    ${CROSS}  Invalid port — skipped.\n"
        fi
    fi
    echo ""

    # ── Low-risk, additive: PermitRootLogin hardening ───────────────────
    local ssh_rootlogin
    ssh_rootlogin=$(printf '%s\n' "$effective" | awk 'tolower($1)=="permitrootlogin"{print $2; exit}')
    if [ "$ssh_rootlogin" != "no" ] && [ "$ssh_rootlogin" != "prohibit-password" ]; then
        printf "    ${WARN}  ${YLW}Root can log in over SSH with a password${RST} (PermitRootLogin: ${ssh_rootlogin:-yes}).\n"
        printf "    ${DIM}Restrict root SSH login to keys only (still allows key-based root\n"
        printf "    ${DIM}access, blocks password brute-forcing against root)? [y/N]${RST}\n"
        printf "    ${ARROW} "
        read -r rootlogin_choice
        if [[ "$rootlogin_choice" =~ ^[Yy] ]]; then
            echo "PermitRootLogin prohibit-password" | sudo tee /etc/ssh/sshd_config.d/99-pwdnow-rootlogin.conf >/dev/null
            if sudo sshd -t 2>/tmp/pwdnow-sshd-test.log; then
                sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd 2>/dev/null || true
                printf "    ${CHECK}  Root SSH login restricted to key-based auth.\n"
            else
                sudo rm -f /etc/ssh/sshd_config.d/99-pwdnow-rootlogin.conf
                printf "    ${CROSS}  Generated config failed sshd -t validation — reverted, nothing changed.\n"
                printf "    ${DIM}   Details: /tmp/pwdnow-sshd-test.log${RST}\n"
            fi
        fi
        echo ""
    fi

    # ── Password auth → key-only: opt-in, gated on a key actually existing ──
    if [ "$ssh_pwauth" != "no" ]; then
        local has_key="no"
        [ -s "$HOME/.ssh/authorized_keys" ] && has_key="yes"

        printf "    ${WARN}  ${YLW}Password authentication is enabled.${RST}\n"
        if [ "$has_key" = "yes" ]; then
            printf "    ${DIM}   A key is already authorized for ${USER} on this account.${RST}\n"
            printf "    ${BOLD}Switch to key-only login (extra security, not required)?${RST}\n"
            printf "    ${DIM}[1] Yes, disable password auth   [2] Maybe later${RST}\n"
            printf "    ${ARROW} "
            read -r pwauth_choice
            if [ "$pwauth_choice" = "1" ]; then
                printf "    ${WARN}  ${YLW}Before continuing: in a SEPARATE terminal, confirm\n"
                printf "    ${WARN}  ${YLW}'ssh -i <your-key> %s@<this-host>' logs in without a password.${RST}\n" "$USER"
                printf "    ${BOLD}Confirmed key login works — proceed? [y/N]${RST}\n"
                printf "    ${ARROW} "
                read -r pwauth_confirm
                if [[ "$pwauth_confirm" =~ ^[Yy] ]]; then
                    echo "PasswordAuthentication no" | sudo tee /etc/ssh/sshd_config.d/99-pwdnow-no-password.conf >/dev/null
                    if sudo sshd -t 2>/tmp/pwdnow-sshd-test.log; then
                        sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd 2>/dev/null || true
                        printf "    ${CHECK}  Password authentication disabled — key-only login now enforced.\n"
                    else
                        sudo rm -f /etc/ssh/sshd_config.d/99-pwdnow-no-password.conf
                        printf "    ${CROSS}  Generated config failed sshd -t validation — reverted, nothing changed.\n"
                        printf "    ${DIM}   Details: /tmp/pwdnow-sshd-test.log${RST}\n"
                    fi
                else
                    printf "    ${DIM}  Skipped for safety.\n"
                fi
            else
                printf "    ${DIM}  Maybe later — do it anytime with:\n"
                printf "    ${DIM}    echo 'PasswordAuthentication no' | sudo tee /etc/ssh/sshd_config.d/99-no-password.conf${RST}\n"
                printf "    ${DIM}    sudo sshd -t && sudo systemctl reload ssh${RST}\n"
            fi
        else
            printf "    ${DIM}   No authorized_keys found for ${USER} — set up a key first, then this\n"
            printf "    ${DIM}   installer (or you) can safely switch to key-only login:${RST}\n"
            printf "    ${DIM}     ssh-keygen -t ed25519 ; ssh-copy-id ${USER}@<this-host>${RST}\n"
            printf "    ${DIM}   Not offering to disable password auth until a key is present — doing\n"
            printf "    ${DIM}   so with no key would lock you out.${RST}\n"
        fi
        echo ""
    fi

    # ── A couple more things worth doing, not implemented here ──────────
    printf "    ${DOT}  ${DIM}Also worth considering: fail2ban (blocks repeat-offender IPs after\n"
    printf "    ${DOT}  ${DIM}failed attempts) and lowering ClientAliveCountMax/Interval to drop\n"
    printf "    ${DOT}  ${DIM}idle sessions sooner. Not applied here — both are policy calls that\n"
    printf "    ${DOT}  ${DIM}depend on how you actually use this box.${RST}\n"
}

# ══════════════════════════════════════════════════════════════════
#  Step 4: Port Check
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
#  Step 5: Dependency Check
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
        "protoc:protobuf-compiler"
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
                protoc)  ver=$(protoc --version 2>/dev/null | awk '{print $2}' || echo "?") ;;
                *)       ver="installed" ;;
            esac

            if [ "$cmd" = "node" ]; then
                local node_major="${ver#v}"; node_major="${node_major%%.*}"
                if ! [[ "$node_major" =~ ^[0-9]+$ ]] || [ "$node_major" -lt "$NODE_MIN_MAJOR" ]; then
                    result_line "${pkg}:" "${RED}${ver} — too old, need >=${NODE_MIN_MAJOR}${RST}" "$CROSS"
                    MISSING_DEPS+=("$pkg")
                    continue
                fi
            fi

            result_line "${pkg}:" "${GRN}${ver}${RST}" "$CHECK"
        else
            result_line "${pkg}:" "${RED}Not found${RST}" "$CROSS"
            MISSING_DEPS+=("$pkg")
        fi
    done

    # The daemon's build.rs links these native libraries directly (libsodium,
    # SQLCipher, libfido2) — none of them ship a CLI binary, so `command -v`
    # can't see them. Check via pkg-config (matching exactly what build.rs /
    # the crate's own build script probes) instead.
    local libs=(
        "libsodium:libsodium-dev"
        "sqlcipher:libsqlcipher-dev"
        "libfido2:libfido2-dev"
    )
    for entry in "${libs[@]}"; do
        IFS=':' read -r pcname pkg <<< "$entry"
        if pkg-config --exists "$pcname" 2>/dev/null; then
            local ver
            ver=$(pkg-config --modversion "$pcname" 2>/dev/null || echo "installed")
            result_line "${pkg}:" "${GRN}${ver}${RST}" "$CHECK"
        else
            result_line "${pkg}:" "${RED}Not found${RST}" "$CROSS"
            MISSING_DEPS+=("$pkg")
        fi
    done

    if command -v llvm-config &>/dev/null || find /usr/lib* /usr/local/lib* -name 'libclang.so*' 2>/dev/null | grep -q .; then
        result_line "libclang-dev:" "${GRN}installed${RST}" "$CHECK"
    else
        result_line "libclang-dev:" "${RED}Not found${RST}" "$CROSS"
        MISSING_DEPS+=("libclang-dev")
    fi

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

    # Build the package list with correct names for the OS. rustup itself
    # needs curl, so its install is deferred until after the apt/dnf pass
    # below — doing it inline here would fail on a system where curl is
    # ALSO missing (rustup's own bootstrap has nothing to fetch itself with).
    local pkgs=()
    local need_rust=false
    local need_node=false
    for dep in "${MISSING_DEPS[@]}"; do
        case "$dep" in
            # Distro apt/dnf "nodejs" is frequently ancient (Ubuntu 22.04 ships
            # v12) and too old for this project's Vite 6/React 19 toolchain —
            # installed via NodeSource below instead, which bundles npm too.
            nodejs|npm) need_node=true ;;
            rust/cargo) need_rust=true ;;
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
            protobuf-compiler)  pkgs+=("protobuf-compiler") ;;
            libsodium-dev)
                if [ "$OS_FAMILY" = "debian" ]; then pkgs+=("libsodium-dev")
                else pkgs+=("libsodium-devel"); fi
                ;;
            libsqlcipher-dev)
                if [ "$OS_FAMILY" = "debian" ]; then pkgs+=("libsqlcipher-dev")
                else pkgs+=("sqlcipher-devel"); fi
                ;;
            libfido2-dev)
                if [ "$OS_FAMILY" = "debian" ]; then pkgs+=("libfido2-dev")
                else pkgs+=("libfido2-devel"); fi
                ;;
            libclang-dev)
                if [ "$OS_FAMILY" = "debian" ]; then pkgs+=("libclang-dev")
                else pkgs+=("clang-devel"); fi
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

    # Deferred until after the apt/dnf pass above for the same reason as rustup
    # below: this needs curl, which that pass may have just installed.
    if [ "$need_node" = true ]; then
        printf "    ${ARROW}  Installing Node.js %s.x (LTS) via NodeSource...\n" "$NODE_MIN_MAJOR"
        case "$OS_FAMILY" in
            debian)
                curl --proto '=https' --tlsv1.2 -fsSL "https://deb.nodesource.com/setup_${NODE_MIN_MAJOR}.x" | sudo -E bash -
                sudo apt-get install -y nodejs
                ;;
            fedora)
                curl --proto '=https' --tlsv1.2 -fsSL "https://rpm.nodesource.com/setup_${NODE_MIN_MAJOR}.x" | sudo -E bash -
                sudo dnf install -y nodejs
                ;;
        esac
    fi

    if [ "$need_rust" = true ]; then
        printf "    ${ARROW}  Rust will be installed via rustup...\n"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        # shellcheck source=/dev/null
        source "$HOME/.cargo/env"
    fi

    printf "    ${CHECK}  Dependencies installed.\n"
}

# ══════════════════════════════════════════════════════════════════
#  Step 6: Summary & Confirm
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
#  Step 7: Install
# ══════════════════════════════════════════════════════════════════

run_install() {
    section "INSTALLING PWDNOW"

    local INSTALL_DIR="/opt/pwdnow"
    local SCRIPT_DIR
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    INSTALL_CURRENT_STEP=0

    # ── Create system user ────────────────────────────────────────
    step_start "Creating system users..."
    if ! id -u vault &>/dev/null; then
        sudo useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/vault-daemon vault
    fi
    if ! id -u pwdnow &>/dev/null; then
        sudo useradd --system --shell /usr/sbin/nologin --home-dir "$INSTALL_DIR" pwdnow
    fi
    printf " ${CHECK}\n"

    # ── Create directories ────────────────────────────────────────
    step_start "Creating directories..."
    sudo mkdir -p "$INSTALL_DIR" /var/lib/vault-daemon /var/lib/vault-server
    sudo mkdir -p /etc/vault-daemon /var/log/pwdnow /run/vault-daemon
    printf " ${CHECK}\n"

    # ── Copy project files ────────────────────────────────────────
    # Excludes build artifacts (target/, node_modules/) and stray dev-only
    # runtime files (*.db, grpc.token) — these get rebuilt/regenerated fresh
    # below anyway, and copying them wastes disk (a debug daemon/target/ can
    # easily be several GB) and can fail the whole install if the disk fills.
    step_start "Copying project files"
    echo ""
    # .env is excluded deliberately: this is a fresh production install, not
    # a copy of the developer's machine — carrying over a dev .env would
    # silently bring dev-only paths/secrets (e.g. SSL_DIR under $HOME) into
    # /opt/pwdnow. A production .env gets created from .env.example instead
    # (see the HTTPS step below).
    local rsync_excludes=(--exclude target --exclude node_modules --exclude .git
        --exclude '*.db' --exclude '*.db.meta' --exclude grpc.token --exclude .claude-flow
        --exclude .env)
    if command -v rsync &>/dev/null; then
        sudo rsync -a --info=progress2 "${rsync_excludes[@]}" \
            "$SCRIPT_DIR/web" "$SCRIPT_DIR/daemon" "$SCRIPT_DIR/deploy" "$SCRIPT_DIR/proto" \
            "$INSTALL_DIR/" 2>/tmp/pwdnow-rsync.log | while IFS= read -r line; do
            local pct
            pct=$(printf '%s' "$line" | grep -oP '\d+(?=%)' | head -1)
            [ -n "$pct" ] && step_progress "$pct" "Copying files..."
        done
        if [ -s /tmp/pwdnow-rsync.log ]; then
            printf "\n    ${WARN}  rsync reported warnings/errors — see /tmp/pwdnow-rsync.log${RST}\n"
        else
            rm -f /tmp/pwdnow-rsync.log
        fi
    else
        # No rsync: fall back to cp with the same exclusions honored manually.
        for sub in web daemon deploy proto; do
            step_progress "" "Copying ${sub}/..."
            sudo mkdir -p "$INSTALL_DIR/$sub"
            (cd "$SCRIPT_DIR/$sub" && sudo tar --exclude=target --exclude=node_modules --exclude=.git \
                --exclude='*.db' --exclude='*.db.meta' --exclude=grpc.token --exclude=.claude-flow --exclude=.env \
                -cf - .) | (cd "$INSTALL_DIR/$sub" && sudo tar -xf -)
        done
    fi
    printf "\n"
    # Hand the daemon source tree to the invoking user so cargo can build it
    # without sudo below. Building requires no elevated rights — it's just
    # compiling an artifact; only the *installed* binary and *runtime* data
    # need the locked-down 'vault' account, and those are handled later.
    sudo chown -R "$(id -un):$(id -gn)" "$INSTALL_DIR/daemon"
    printf "    ${CHECK}  Project files copied.\n"

    # ── Build daemon ──────────────────────────────────────────────
    step_start "Building vault daemon (release, this can take a while)"
    echo ""
    local total_crates=0 compiled=0 pct=0
    total_crates=$(grep -c '^name = ' "$INSTALL_DIR/daemon/Cargo.lock" 2>/dev/null || echo 0)
    [ "$total_crates" -le 0 ] && total_crates=1
    # Show every line's text (not just "Compiling" ones) so a real compiler
    # error stays visible on screen instead of being silently swallowed by
    # the progress redraw — only the percentage itself is Compiling-gated.
    (cd "$INSTALL_DIR/daemon" && cargo build --release 2>&1) | while IFS= read -r line; do
        if [[ "$line" == Compiling\ * ]]; then
            compiled=$((compiled + 1))
            pct=$(( compiled * 100 / total_crates ))
            [ "$pct" -gt 100 ] && pct=100
        fi
        step_progress "$pct" "${line:0:40}"
    done
    printf "\n"
    sudo install -m755 "$INSTALL_DIR/daemon/target/release/vault-daemon" /usr/local/bin/vault-daemon
    printf "    ${CHECK}  Daemon built and installed.\n"

    # ── Build web frontend ────────────────────────────────────────
    step_start "Installing web dependencies..."
    echo ""
    (cd "$INSTALL_DIR/web" && sudo npm install --production 2>&1 | tail -1)
    printf "    ${ARROW}  Building web frontend...\n"
    (cd "$INSTALL_DIR/web" && sudo npm run build 2>&1 | tail -1)
    printf "    ${CHECK}  Web frontend built.\n"

    # ── HTTPS (optional) ────────────────────────────────────────────
    step_start "HTTPS setup (optional)"
    echo ""
    printf "    Enable HTTPS with a self-signed certificate (dual RSA-4096 +\n"
    printf "    ECDSA P-384, optionally EV-style)? This installs the generated\n"
    printf "    CA into this system's trust store (asks separately for that).\n"
    printf "    Without it, the vault stays on plain HTTP, loopback-only. [y/N]\n"
    printf "    ${ARROW} "
    read -r ssl_choice
    if [[ "$ssl_choice" =~ ^[Yy] ]]; then
        if [ ! -f "$INSTALL_DIR/web/.env" ]; then
            cp "$INSTALL_DIR/web/.env.example" "$INSTALL_DIR/web/.env"
            printf "    ${DIM}   Created web/.env from .env.example (SSL_DIR already points at\n"
            printf "    ${DIM}   ${INSTALL_DIR}/ssl there — edit it first if you want different\n"
            printf "    ${DIM}   certificate details or EV fields before generating).${RST}\n"
        fi
        if bash "$INSTALL_DIR/web/scripts/generate-ssl.sh"; then
            SSL_ENABLED="yes"
            printf "    ${CHECK}  HTTPS certificate generated.\n"
        else
            printf "    ${CROSS}  Certificate generation failed — continuing with plain HTTP.\n"
        fi
    else
        printf "    ${DIM}  Skipped — plain HTTP only. Run web/scripts/generate-ssl.sh later to add it.\n"
    fi

    # ── Generate gRPC auth token ──────────────────────────────────
    step_start "Generating gRPC auth token..."
    local grpc_token
    grpc_token=$(openssl rand -hex 32)
    echo "DAEMON_GRPC_TOKEN=${grpc_token}" | sudo tee /etc/vault-daemon/grpc.env >/dev/null
    sudo chmod 600 /etc/vault-daemon/grpc.env
    printf " ${CHECK}\n"

    # ── Install systemd services ──────────────────────────────────
    step_start "Installing systemd services..."
    sudo cp "$INSTALL_DIR/deploy/vault-daemon.service" /etc/systemd/system/
    sudo cp "$INSTALL_DIR/deploy/pwdnow-web.service" /etc/systemd/system/
    # Patch the web service to use our port
    sudo sed -i "s/PORT=1234/PORT=${WEB_PORT}/" /etc/systemd/system/pwdnow-web.service
    # Patch both units to agree on the daemon's gRPC port
    sudo sed -i "s/127.0.0.1:50051/127.0.0.1:${DAEMON_PORT}/" /etc/systemd/system/vault-daemon.service
    sudo sed -i "s/127.0.0.1:50051/127.0.0.1:${DAEMON_PORT}/" /etc/systemd/system/pwdnow-web.service
    if [ "$SSL_ENABLED" = "yes" ]; then
        # 8443, not 443/.env's SSL_PORT: pwdnow-web.service runs as the
        # unprivileged 'pwdnow' user with no CAP_NET_BIND_SERVICE, so it
        # can't bind a port below 1024 — SSL=force also keeps plain HTTP
        # alive on WEB_PORT as a redirect-to-HTTPS server.
        sudo sed -i "/^\[Install\]/i Environment=SSL=force\nEnvironment=SSL_PORT=8443\nEnvironment=SSL_DIR=${INSTALL_DIR}/ssl" \
            /etc/systemd/system/pwdnow-web.service
    fi
    sudo systemctl daemon-reload
    printf " ${CHECK}\n"

    # ── Install AppArmor profile ────────────────────────────────────
    step_start "Installing AppArmor profile..."
    if command -v apparmor_parser &>/dev/null; then
        sudo install -Dm644 "$INSTALL_DIR/deploy/apparmor.d/vault-daemon" /etc/apparmor.d/vault-daemon
        sudo apparmor_parser -r /etc/apparmor.d/vault-daemon
        printf " ${CHECK}\n"
    else
        printf " ${WARN} ${YLW}AppArmor not present on this system — skipping (daemon will run unconfined by AppArmor; systemd sandboxing still applies).${RST}\n"
    fi

    # ── Set permissions ───────────────────────────────────────────
    step_start "Setting permissions..."
    sudo chown -R vault:vault /var/lib/vault-daemon /run/vault-daemon
    sudo chown -R pwdnow:pwdnow /var/lib/vault-server /var/log/pwdnow "$INSTALL_DIR/web"
    sudo chmod 700 /var/lib/vault-daemon
    printf " ${CHECK}\n"

    # ── Harden file permissions ────────────────────────────────────
    # Sweep everything this install touched for stray world-writable bits
    # (e.g. left over from a tarball, an editor, or a package default) and
    # strip them — without touching read/execute bits, so binaries and
    # scripts keep working. Then re-assert the handful of paths that must
    # never be group/world-readable regardless of what the sweep found.
    step_start "Auditing file permissions..."
    local loose_count=0
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        sudo chmod o-w "$f"
        loose_count=$((loose_count + 1))
    done < <(sudo find "$INSTALL_DIR" /etc/vault-daemon /var/lib/vault-daemon /var/lib/vault-server /var/log/pwdnow /run/vault-daemon -perm -o+w 2>/dev/null)
    sudo chmod 600 /etc/vault-daemon/grpc.env 2>/dev/null || true
    sudo chmod 700 /var/lib/vault-daemon 2>/dev/null || true
    sudo chmod 750 /var/lib/vault-server 2>/dev/null || true
    if [ "$loose_count" -gt 0 ]; then
        printf " ${CHECK}  Stripped world-writable bit from %d path(s).\n" "$loose_count"
    else
        printf " ${CHECK}  No world-writable files found.\n"
    fi

    # ── Enable & start services ───────────────────────────────────
    step_start "Starting services..."
    echo ""
    sudo systemctl enable vault-daemon pwdnow-web
    sudo systemctl start vault-daemon
    sleep 2
    sudo systemctl start pwdnow-web
    printf "    ${CHECK}  Services started.\n"
}

# ══════════════════════════════════════════════════════════════════
#  Step 8: Post-Install
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
    if [ "$SSL_ENABLED" = "yes" ]; then
        printf "      ${ARROW}  ${WHT}https://localhost:8443${RST}\n"
        printf "      ${DIM}   (self-signed cert — your browser will warn once; http://localhost:${WEB_PORT}\n"
        printf "      ${DIM}    now redirects here automatically.)${RST}\n"
    else
        printf "      ${ARROW}  ${WHT}http://localhost:${WEB_PORT}${RST}\n"
        printf "      ${DIM}   (plain HTTP, loopback-only — this install has no TLS/nginx in front.\n"
        printf "      ${DIM}    For LAN/production access, put deploy/nginx/vault.conf + a real\n"
        printf "      ${DIM}    cert in front instead of exposing this port directly.)${RST}\n"
    fi
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

    # Ask for the sudo password once, up front, then keep the sudo timestamp
    # alive in the background for the rest of the run — every later step that
    # needs root (apt/dnf, useradd, systemctl, apparmor_parser, ...) reuses it
    # instead of re-prompting mid-install.
    printf "  ${DIM}This installer needs sudo for system-level changes (packages, systemd,\n"
    printf "  ${DIM}users, permissions). You'll be asked for your password once.${RST}\n\n"
    if ! sudo -v; then
        printf "  ${CROSS}  Could not obtain sudo access. Aborting.\n"
        exit 1
    fi
    ( while true; do sudo -n true 2>/dev/null; sleep 60; kill -0 "$$" 2>/dev/null || exit; done ) &
    SUDO_KEEPALIVE_PID=$!
    trap 'kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true' EXIT

    detect_os
    check_fips
    press_enter
    audit_ssh
    press_enter
    check_ports
    check_dependencies
    press_enter
    show_summary
    run_install
    show_complete
}

main "$@"
