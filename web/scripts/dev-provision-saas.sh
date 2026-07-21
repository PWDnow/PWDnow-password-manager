#!/usr/bin/env bash
# dev-provision-saas.sh — interactive dev provisioning for the Postgres +
# KMS (HashiCorp Vault) stack used by the saas-p1-postgres-envelope-kms
# branch. Purely a local-dev convenience: nothing here is required for
# production. If you skip this entirely, the app keeps running on the
# existing file-store (VAULT_BACKEND=file) + local KMS (KMS_PROVIDER=local)
# fallback path — that fallback is the architecture's Plan B, not something
# this script has to implement.
set -uo pipefail

RED=$'\033[1;31m'; GRN=$'\033[1;32m'; YLW=$'\033[1;33m'; BLU=$'\033[1;34m'
CYN=$'\033[1;36m'; WHT=$'\033[1;37m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; RST=$'\033[0m'
CHECK="${GRN}✔${RST}"; ARROW="${CYN}➜${RST}"

ENV_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.env"

section() { echo ""; printf "${BLU}${BOLD}▸ %s${RST}\n" "$1"; printf "${DIM}%s${RST}\n" "$(printf -- '-%.0s' {1..60})"; }

# Prompt with a shown default; blank input keeps the default.
ask() {
    local __var="$1" __prompt="$2" __default="$3" __reply
    printf "    %s ${DIM}[%s]${RST}: " "$__prompt" "$__default"
    read -r __reply
    printf -v "$__var" '%s' "${__reply:-$__default}"
}

gen_secret() { openssl rand -base64 "${1:-18}" | tr -d '=+/\n' | cut -c1-24; }

# ══════════════════════════════════════════════════════════════════
#  Recommended defaults
# ══════════════════════════════════════════════════════════════════
PG_CONTAINER_DEFAULT="pwdnow-pg"
PG_USER_DEFAULT="postgres"
PG_DB_DEFAULT="pwdnow"
PG_PORT_DEFAULT="55432"
PG_PASSWORD_DEFAULT="$(gen_secret 18)"      # freshly generated, not a fixed "dev" password

VAULT_CONTAINER_DEFAULT="pwdnow-vault"
VAULT_PORT_DEFAULT="8200"
VAULT_IMAGE_DEFAULT="hashicorp/vault:1.19"  # matches the KMS provider pinned in the P1 plan
VAULT_TOKEN_DEFAULT="$(gen_secret 24)"

section "RECOMMENDED DEFAULTS"
cat <<EOF
    Postgres  container : ${PG_CONTAINER_DEFAULT}
    Postgres  user       : ${PG_USER_DEFAULT}
    Postgres  password   : ${PG_PASSWORD_DEFAULT}  ${DIM}(freshly generated — not "dev")${RST}
    Postgres  database   : ${PG_DB_DEFAULT}
    Postgres  port       : ${PG_PORT_DEFAULT}  ${DIM}(host port; container always uses 5432 internally)${RST}

    Vault     container : ${VAULT_CONTAINER_DEFAULT}
    Vault     image      : ${VAULT_IMAGE_DEFAULT}
    Vault     port       : ${VAULT_PORT_DEFAULT}
    Vault     root token : ${VAULT_TOKEN_DEFAULT}  ${DIM}(freshly generated)${RST}

    ${DIM}These are throwaway dev credentials for a local Docker container —
    not used anywhere in production. Everything below is editable.${RST}
EOF

printf "\n    Use the recommended defaults for everything? ${DIM}[Y/n]${RST} "
read -r use_defaults

PG_CONTAINER="$PG_CONTAINER_DEFAULT"; PG_USER="$PG_USER_DEFAULT"
PG_DB="$PG_DB_DEFAULT"; PG_PORT="$PG_PORT_DEFAULT"; PG_PASSWORD="$PG_PASSWORD_DEFAULT"
PROVISION_VAULT="n"
VAULT_CONTAINER="$VAULT_CONTAINER_DEFAULT"; VAULT_IMAGE="$VAULT_IMAGE_DEFAULT"
VAULT_PORT="$VAULT_PORT_DEFAULT"; VAULT_TOKEN="$VAULT_TOKEN_DEFAULT"

if [[ "$use_defaults" =~ ^[Nn] ]]; then
    section "POSTGRES CREDENTIALS"
    ask PG_CONTAINER "Container name"     "$PG_CONTAINER_DEFAULT"
    ask PG_USER      "Username"           "$PG_USER_DEFAULT"
    ask PG_PASSWORD  "Password"           "$PG_PASSWORD_DEFAULT"
    ask PG_DB        "Database name"      "$PG_DB_DEFAULT"
    ask PG_PORT      "Host port"          "$PG_PORT_DEFAULT"

    section "KMS (HASHICORP VAULT) — OPTIONAL"
    printf "    Provision a dev Vault Transit KMS too? ${DIM}[y/N]${RST} "
    read -r PROVISION_VAULT
    if [[ "$PROVISION_VAULT" =~ ^[Yy] ]]; then
        ask VAULT_CONTAINER "Container name" "$VAULT_CONTAINER_DEFAULT"
        ask VAULT_IMAGE     "Image:tag"      "$VAULT_IMAGE_DEFAULT"
        ask VAULT_PORT      "Host port"      "$VAULT_PORT_DEFAULT"
        ask VAULT_TOKEN     "Root token"     "$VAULT_TOKEN_DEFAULT"
    fi
fi

# ══════════════════════════════════════════════════════════════════
#  Edit Configuration
# ══════════════════════════════════════════════════════════════════
show_summary() {
    section "EDIT CONFIGURATION"
    echo "    1) Postgres container : $PG_CONTAINER"
    echo "    2) Postgres user      : $PG_USER"
    echo "    3) Postgres password  : $PG_PASSWORD"
    echo "    4) Postgres database  : $PG_DB"
    echo "    5) Postgres port      : $PG_PORT"
    echo "    6) Provision Vault?   : ${PROVISION_VAULT:-n}"
    if [[ "$PROVISION_VAULT" =~ ^[Yy] ]]; then
        echo "    7) Vault container    : $VAULT_CONTAINER"
        echo "    8) Vault image        : $VAULT_IMAGE"
        echo "    9) Vault port         : $VAULT_PORT"
        echo "   10) Vault root token   : $VAULT_TOKEN"
    fi
}

while true; do
    show_summary
    printf "\n    ${BOLD}[c]${RST}ontinue   ${BOLD}[e]${RST}dit a field   ${BOLD}[a]${RST}bort\n    ${ARROW} "
    read -r action
    case "$action" in
        c|C) break ;;
        a|A) printf "    Aborted. No containers started, no files changed.\n"; exit 0 ;;
        e|E)
            printf "    Field number to edit: "
            read -r n
            case "$n" in
                1) ask PG_CONTAINER  "Container name" "$PG_CONTAINER" ;;
                2) ask PG_USER       "Username"        "$PG_USER" ;;
                3) ask PG_PASSWORD   "Password"        "$PG_PASSWORD" ;;
                4) ask PG_DB         "Database name"   "$PG_DB" ;;
                5) ask PG_PORT       "Host port"       "$PG_PORT" ;;
                6) printf "    Provision Vault? [y/N] "; read -r PROVISION_VAULT ;;
                7) ask VAULT_CONTAINER "Container name" "$VAULT_CONTAINER" ;;
                8) ask VAULT_IMAGE     "Image:tag"      "$VAULT_IMAGE" ;;
                9) ask VAULT_PORT      "Host port"      "$VAULT_PORT" ;;
                10) ask VAULT_TOKEN    "Root token"     "$VAULT_TOKEN" ;;
                *) printf "    ${YLW}Not a valid field number.${RST}\n" ;;
            esac
            ;;
        *) printf "    ${YLW}Type c, e, or a.${RST}\n" ;;
    esac
done

# ══════════════════════════════════════════════════════════════════
#  Provision
# ══════════════════════════════════════════════════════════════════
if ! command -v docker &>/dev/null; then
    printf "\n    ${RED}docker not found.${RST} Falling back to Plan B: leave VAULT_BACKEND=file\n"
    printf "    and KMS_PROVIDER=local — no external DB/KMS required. Nothing to do.\n"
    exit 0
fi

section "PROVISIONING"

# start_or_create <container> <run_cmd...> — NEVER destroys an existing
# container/volume. If a container with this name already exists we just
# (re)start it, whatever state it's in, so any data in its volume survives.
# Recreating from scratch requires the user to explicitly delete it first.
start_or_create() {
    local name="$1"; shift
    if docker inspect "$name" &>/dev/null; then
        local status
        status=$(docker inspect "$name" --format '{{.State.Status}}')
        if [ "$status" = "running" ]; then
            printf "    ${CHECK}  ${WHT}%s${RST} already running — leaving it as-is.\n" "$name"
        else
            printf "    ${ARROW}  ${WHT}%s${RST} already exists (status: %s) — starting it, not recreating.\n" "$name" "$status"
            printf "    ${DIM}   Its existing data volume is preserved. Any credentials/ports you\n"
            printf "    ${DIM}   entered above are ignored for this container — it keeps whatever\n"
            printf "    ${DIM}   it was created with.${RST}\n"
            docker start "$name" >/dev/null
            printf "    ${CHECK}  %s started.\n" "$name"
        fi
        return 0
    fi
    printf "    ${ARROW}  Creating %s...\n" "$name"
    "$@"
    printf "    ${CHECK}  %s created and started.\n" "$name"
}

PG_PRE_EXISTED="no"; docker inspect "$PG_CONTAINER" &>/dev/null && PG_PRE_EXISTED="yes"

start_or_create "$PG_CONTAINER" \
    docker run -d --name "$PG_CONTAINER" \
        -e POSTGRES_USER="$PG_USER" -e POSTGRES_PASSWORD="$PG_PASSWORD" -e POSTGRES_DB="$PG_DB" \
        -p "${PG_PORT}:5432" postgres:16

if [ "$PG_PRE_EXISTED" = "yes" ]; then
    # This container already existed under its own creds/port — pull the
    # REAL values from it. Do not trust whatever was prompted/generated
    # above; using those would write a DATABASE_URL that silently points
    # at the wrong password/db and looks broken later.
    real_env="$(docker inspect "$PG_CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}')"
    PG_USER="$(printf '%s\n' "$real_env" | sed -n 's/^POSTGRES_USER=//p')"; PG_USER="${PG_USER:-postgres}"
    PG_PASSWORD="$(printf '%s\n' "$real_env" | sed -n 's/^POSTGRES_PASSWORD=//p')"
    PG_DB="$(printf '%s\n' "$real_env" | sed -n 's/^POSTGRES_DB=//p')"; PG_DB="${PG_DB:-postgres}"
    PG_PORT="$(docker inspect "$PG_CONTAINER" --format '{{(index (index .HostConfig.PortBindings "5432/tcp") 0).HostPort}}' 2>/dev/null)"
    printf "    ${DIM}   Using %s's actual user=%s db=%s port=%s (not the values entered above).${RST}\n" \
        "$PG_CONTAINER" "$PG_USER" "$PG_DB" "$PG_PORT"
fi
DATABASE_URL="postgres://${PG_USER}:${PG_PASSWORD}@127.0.0.1:${PG_PORT}/${PG_DB}"

if [[ "$PROVISION_VAULT" =~ ^[Yy] ]]; then
    VAULT_PRE_EXISTED="no"; docker inspect "$VAULT_CONTAINER" &>/dev/null && VAULT_PRE_EXISTED="yes"

    start_or_create "$VAULT_CONTAINER" \
        docker run -d --name "$VAULT_CONTAINER" --cap-add=IPC_LOCK \
            -p "${VAULT_PORT}:8200" "$VAULT_IMAGE" \
            server -dev -dev-root-token-id="$VAULT_TOKEN"

    if [ "$VAULT_PRE_EXISTED" = "yes" ]; then
        # Same reasoning as Postgres above: pull the real root token this
        # container was created with out of its stored launch command.
        real_token="$(docker inspect "$VAULT_CONTAINER" --format '{{json .Config.Cmd}}' | grep -oP -- '-dev-root-token-id=\K[^"]+' || true)"
        real_port="$(docker inspect "$VAULT_CONTAINER" --format '{{(index (index .HostConfig.PortBindings "8200/tcp") 0).HostPort}}' 2>/dev/null)"
        [ -n "$real_port" ] && VAULT_PORT="$real_port"
        if [ -n "$real_token" ]; then
            VAULT_TOKEN="$real_token"
            printf "    ${DIM}   Using %s's actual root token/port (not the values entered above).${RST}\n" "$VAULT_CONTAINER"
        else
            printf "    ${YLW}   Couldn't read %s's original root token — check \`docker logs %s\`\n" "$VAULT_CONTAINER" "$VAULT_CONTAINER"
            printf "    ${YLW}   for the \"Root Token:\" line rather than trusting the value entered above.${RST}\n"
        fi
    fi
fi

# ══════════════════════════════════════════════════════════════════
#  Write web/.env (idempotent — updates existing keys, appends new ones)
# ══════════════════════════════════════════════════════════════════
set_env_var() {
    local key="$1" value="$2"
    if [ -f "$ENV_FILE" ] && grep -q "^${key}=" "$ENV_FILE"; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
    else
        printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
    fi
}

if [ -f "$ENV_FILE" ]; then
    backup="${ENV_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$ENV_FILE" "$backup"
    printf "    ${DIM}   Backed up existing .env to %s before touching it.${RST}\n" "$backup"
else
    [ -f "${ENV_FILE}.example" ] && cp "${ENV_FILE}.example" "$ENV_FILE"
    touch "$ENV_FILE"
fi

set_env_var "DATABASE_URL" "$DATABASE_URL"
if [[ "$PROVISION_VAULT" =~ ^[Yy] ]]; then
    set_env_var "VAULT_ADDR" "http://127.0.0.1:${VAULT_PORT}"
    set_env_var "VAULT_TOKEN" "$VAULT_TOKEN"
fi

section "DONE"
cat <<EOF
    ${CHECK}  DATABASE_URL written to web/.env (VAULT_BACKEND left as "file" —
       flip it to "postgres" yourself once you're ready to cut over).
EOF
[[ "$PROVISION_VAULT" =~ ^[Yy] ]] && cat <<EOF
    ${CHECK}  VAULT_ADDR / VAULT_TOKEN written to web/.env (KMS_PROVIDER left
       as "local" — set it to "vault" and VAULT_TRANSIT_KEY yourself to
       actually route through Transit).
EOF
cat <<EOF

    Tear down when done:
      docker rm -f ${PG_CONTAINER}$( [[ "$PROVISION_VAULT" =~ ^[Yy] ]] && echo " ${VAULT_CONTAINER}" )
EOF
