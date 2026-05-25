#!/usr/bin/env bash
# PWDnow SSL Certificate Generator
# Generates dual RSA-4096 + ECDSA P-384 self-signed certificates from .env config.
# Installs the CA to the Ubuntu system trust store and Chrome NSS.
#
# Usage:
#   bash scripts/generate-ssl.sh
#   npm run ssl:generate
#
# Requires: openssl, sudo (for trust-store installation)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$WEB_DIR/.env"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[ssl]${NC} $*"; }
warn() { echo -e "${YELLOW}[ssl] WARN:${NC} $*"; }
ok()   { echo -e "${GREEN}[ssl] ✓${NC} $*"; }
die()  { echo -e "${RED}[ssl] ERROR:${NC} $*" >&2; exit 1; }
hdr()  { echo -e "\n${BOLD}${CYAN}=== $* ===${NC}"; }

# ── Load .env ─────────────────────────────────────────────────────────────────
[[ -f "$ENV_FILE" ]] || die ".env not found at $ENV_FILE"

while IFS='=' read -r raw_key raw_val; do
  [[ -z "$raw_key" || "$raw_key" =~ ^[[:space:]]*# ]] && continue
  key="${raw_key// /}"
  val="${raw_val%\"}"
  val="${val#\"}"
  val="${val%\'}"
  val="${val#\'}"
  [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] && export "$key=$val"
done < <(grep -v '^[[:space:]]*#' "$ENV_FILE" | grep -v '^[[:space:]]*$' | grep '=')

# ── Defaults ──────────────────────────────────────────────────────────────────
SSL_DIR="${SSL_DIR:-/opt/pwdnow/ssl}"
SSL_COMMON_NAME="${SSL_COMMON_NAME:-localhost}"
SSL_ORGANIZATION="${SSL_ORGANIZATION:-PWDnow}"
SSL_ORG_UNIT="${SSL_ORG_UNIT:-Security}"
SSL_COUNTRY="${SSL_COUNTRY:-CA}"
SSL_STATE="${SSL_STATE:-Quebec}"
SSL_CITY="${SSL_CITY:-Montreal}"
SSL_EMAIL="${SSL_EMAIL:-admin@example.com}"
SSL_SAN_DNS="${SSL_SAN_DNS:-localhost}"
SSL_SAN_IP="${SSL_SAN_IP:-127.0.0.1}"
SSL_PERIOD="${SSL_PERIOD:-90d}"
SSL_EV_OID="${SSL_EV_OID:-}"
SSL_PORT="${SSL_PORT:-443}"

# ── Period → days ─────────────────────────────────────────────────────────────
case "$SSL_PERIOD" in
  90d)  DAYS=90   ;;
  1y)   DAYS=365  ;;
  2y)   DAYS=730  ;;
  3y)   DAYS=1095 ;;
  5y)   DAYS=1825 ;;
  10y)  DAYS=3650 ;;
  *)    die "Invalid SSL_PERIOD '$SSL_PERIOD'. Valid: 90d, 1y, 2y, 3y, 5y, 10y" ;;
esac

RSA_DIR="$SSL_DIR/rsa"
ECDSA_DIR="$SSL_DIR/ecdsa"

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}${CYAN}PWDnow SSL Certificate Generator${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  CN:      ${BOLD}$SSL_COMMON_NAME${NC}"
echo -e "  Org:     $SSL_ORGANIZATION / $SSL_ORG_UNIT"
echo -e "  Subject: C=$SSL_COUNTRY, ST=$SSL_STATE, L=$SSL_CITY"
echo -e "  Email:   $SSL_EMAIL"
echo -e "  DNS SANs:$SSL_SAN_DNS"
echo -e "  IP SANs: $SSL_SAN_IP"
echo -e "  Period:  ${BOLD}$SSL_PERIOD${NC} ($DAYS days)"
echo -e "  EV OID:  ${SSL_EV_OID:-none (DV)}"
echo -e "  Output:  $SSL_DIR"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# ── Sudo helper (non-interactive: skip privileged steps with warning) ──────────
# Returns 0 if sudo is available non-interactively, 1 otherwise.
have_sudo() { sudo -n true 2>/dev/null; }

# ── Directory structure ───────────────────────────────────────────────────────
hdr "Creating directory structure"
if [[ ! -d "$SSL_DIR" ]]; then
  if have_sudo; then
    sudo mkdir -p "$RSA_DIR" "$ECDSA_DIR"
    sudo chown -R "$(id -u):$(id -g)" "$SSL_DIR"
  else
    mkdir -p "$RSA_DIR" "$ECDSA_DIR" || \
      die "Cannot create $SSL_DIR — either choose a user-writable SSL_DIR in .env or run: sudo mkdir -p $SSL_DIR && sudo chown \$(id -u):\$(id -g) $SSL_DIR"
  fi
else
  mkdir -p "$RSA_DIR" "$ECDSA_DIR"
fi
ok "Directories: $RSA_DIR, $ECDSA_DIR"

# ── Build SAN block for OpenSSL config ───────────────────────────────────────
build_san_block() {
  local dns_csv="$1" ip_csv="$2"
  local out="" i=1 j=1
  IFS=',' read -ra dns_arr <<< "$dns_csv"
  for entry in "${dns_arr[@]}"; do
    entry="${entry//[[:space:]]/}"
    [[ -n "$entry" ]] && { out+="DNS.${i} = ${entry}\n"; ((i++)); } || true
  done
  IFS=',' read -ra ip_arr <<< "$ip_csv"
  for entry in "${ip_arr[@]}"; do
    entry="${entry//[[:space:]]/}"
    [[ -n "$entry" ]] && { out+="IP.${j} = ${entry}\n"; ((j++)); } || true
  done
  printf '%b' "$out"
}

SAN_BLOCK="$(build_san_block "$SSL_SAN_DNS" "$SSL_SAN_IP")"

# ── Build certificatePolicies line ───────────────────────────────────────────
EV_POLICIES_LINE=""
if [[ -n "$SSL_EV_OID" ]]; then
  formatted_oids="$(echo "$SSL_EV_OID" | sed 's/,/, /g')"
  EV_POLICIES_LINE="certificatePolicies = ${formatted_oids}"
fi

# ── OpenSSL config writers ────────────────────────────────────────────────────

write_ca_cnf() {
  local dir="$1" algo_label="$2"
  cat > "$dir/ca.cnf" << CNF
[ req ]
distinguished_name = req_dn
x509_extensions    = ca_ext
prompt             = no
string_mask        = utf8only

[ req_dn ]
CN           = ${SSL_COMMON_NAME} ${algo_label} CA
O            = ${SSL_ORGANIZATION}
OU           = ${SSL_ORG_UNIT}
L            = ${SSL_CITY}
ST           = ${SSL_STATE}
C            = ${SSL_COUNTRY}
emailAddress = ${SSL_EMAIL}

[ ca_ext ]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
CNF
}

write_server_req_cnf() {
  local dir="$1"
  cat > "$dir/server_req.cnf" << CNF
[ req ]
distinguished_name = req_dn
prompt             = no
string_mask        = utf8only

[ req_dn ]
CN           = ${SSL_COMMON_NAME}
O            = ${SSL_ORGANIZATION}
OU           = ${SSL_ORG_UNIT}
L            = ${SSL_CITY}
ST           = ${SSL_STATE}
C            = ${SSL_COUNTRY}
emailAddress = ${SSL_EMAIL}
CNF
}

write_server_ext_cnf() {
  local dir="$1" key_usage="$2" ocsp_port="$3"
  local ev_line="${EV_POLICIES_LINE}"
  local san_block="${SAN_BLOCK}"
  # Write extension config — heredoc variables expand at write time
  {
    cat << EXTCNF
[ server_cert ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, ${key_usage}
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid, issuer
subjectAltName         = @alt_names
authorityInfoAccess    = OCSP;URI:http://127.0.0.1:${ocsp_port}
crlDistributionPoints  = URI:http://127.0.0.1/ca.crl
EXTCNF
    [[ -n "$ev_line" ]] && echo "$ev_line"
    cat << ALTNAMES

[ alt_names ]
ALTNAMES
    printf '%b' "$san_block"
  } > "$dir/server_ext.cnf"
}

# ── RSA certificate chain ─────────────────────────────────────────────────────
hdr "Generating RSA-4096 certificate chain"

write_ca_cnf       "$RSA_DIR" "RSA"
write_server_req_cnf "$RSA_DIR"
write_server_ext_cnf "$RSA_DIR" "digitalSignature, keyEncipherment" "8888"

log "Generating RSA-4096 CA key..."
openssl genrsa -out "$RSA_DIR/ca.key" 4096 2>/dev/null
ok "RSA CA key: $RSA_DIR/ca.key"

log "Signing RSA CA certificate (10-year validity)..."
openssl req -x509 -new -key "$RSA_DIR/ca.key" -sha384 -days 3650 \
  -config "$RSA_DIR/ca.cnf" \
  -out "$RSA_DIR/ca.crt" 2>/dev/null
ok "RSA CA cert: $RSA_DIR/ca.crt"

log "Generating RSA-4096 server key..."
openssl genrsa -out "$RSA_DIR/server.key" 4096 2>/dev/null
ok "RSA server key: $RSA_DIR/server.key"

log "Creating RSA server CSR..."
openssl req -new -key "$RSA_DIR/server.key" \
  -config "$RSA_DIR/server_req.cnf" \
  -out "$RSA_DIR/server.csr" 2>/dev/null

log "Signing RSA server certificate ($SSL_PERIOD = $DAYS days)..."
openssl x509 -req \
  -in "$RSA_DIR/server.csr" \
  -CA "$RSA_DIR/ca.crt" \
  -CAkey "$RSA_DIR/ca.key" \
  -CAcreateserial \
  -out "$RSA_DIR/server.crt" \
  -days "$DAYS" \
  -sha384 \
  -extfile "$RSA_DIR/server_ext.cnf" \
  -extensions server_cert 2>/dev/null
ok "RSA server cert: $RSA_DIR/server.crt"

# Create chain bundle (cert + CA for OCSP stapling)
cat "$RSA_DIR/server.crt" "$RSA_DIR/ca.crt" > "$RSA_DIR/chain.pem"
ok "RSA chain bundle: $RSA_DIR/chain.pem"

# OCSP index
: > "$RSA_DIR/index.txt"
echo "unique_subject = no" > "$RSA_DIR/index.txt.attr"

rm -f "$RSA_DIR/server.csr"

# ── ECDSA certificate chain ───────────────────────────────────────────────────
hdr "Generating ECDSA P-384 certificate chain"

write_ca_cnf       "$ECDSA_DIR" "ECDSA"
write_server_req_cnf "$ECDSA_DIR"
write_server_ext_cnf "$ECDSA_DIR" "digitalSignature" "8889"

log "Generating ECDSA P-384 CA key..."
openssl ecparam -genkey -name secp384r1 -noout -out "$ECDSA_DIR/ca.key" 2>/dev/null
ok "ECDSA CA key: $ECDSA_DIR/ca.key"

log "Signing ECDSA CA certificate (10-year validity)..."
openssl req -x509 -new -key "$ECDSA_DIR/ca.key" -sha384 -days 3650 \
  -config "$ECDSA_DIR/ca.cnf" \
  -out "$ECDSA_DIR/ca.crt" 2>/dev/null
ok "ECDSA CA cert: $ECDSA_DIR/ca.crt"

log "Generating ECDSA P-384 server key..."
openssl ecparam -genkey -name secp384r1 -noout -out "$ECDSA_DIR/server.key" 2>/dev/null
ok "ECDSA server key: $ECDSA_DIR/server.key"

log "Creating ECDSA server CSR..."
openssl req -new -key "$ECDSA_DIR/server.key" \
  -config "$ECDSA_DIR/server_req.cnf" \
  -out "$ECDSA_DIR/server.csr" 2>/dev/null

log "Signing ECDSA server certificate ($SSL_PERIOD = $DAYS days)..."
openssl x509 -req \
  -in "$ECDSA_DIR/server.csr" \
  -CA "$ECDSA_DIR/ca.crt" \
  -CAkey "$ECDSA_DIR/ca.key" \
  -CAcreateserial \
  -out "$ECDSA_DIR/server.crt" \
  -days "$DAYS" \
  -sha384 \
  -extfile "$ECDSA_DIR/server_ext.cnf" \
  -extensions server_cert 2>/dev/null
ok "ECDSA server cert: $ECDSA_DIR/server.crt"

cat "$ECDSA_DIR/server.crt" "$ECDSA_DIR/ca.crt" > "$ECDSA_DIR/chain.pem"
ok "ECDSA chain bundle: $ECDSA_DIR/chain.pem"

: > "$ECDSA_DIR/index.txt"
echo "unique_subject = no" > "$ECDSA_DIR/index.txt.attr"

rm -f "$ECDSA_DIR/server.csr"

# ── Set permissions ───────────────────────────────────────────────────────────
hdr "Setting file permissions"
chmod 700 "$RSA_DIR/ca.key" "$ECDSA_DIR/ca.key"
chmod 600 "$RSA_DIR/server.key" "$ECDSA_DIR/server.key"
chmod 644 "$RSA_DIR/ca.crt" "$RSA_DIR/server.crt" "$RSA_DIR/chain.pem"
chmod 644 "$ECDSA_DIR/ca.crt" "$ECDSA_DIR/server.crt" "$ECDSA_DIR/chain.pem"
ok "Keys: 600/700, Certs: 644"

# ── Ubuntu system trust store ─────────────────────────────────────────────────
hdr "Installing CA certificates to Ubuntu trust store"

TRUST_DIR="/usr/local/share/ca-certificates"
RSA_TRUST="$TRUST_DIR/pwdnow-rsa-ca.crt"
ECDSA_TRUST="$TRUST_DIR/pwdnow-ecdsa-ca.crt"

if ! command -v update-ca-certificates &>/dev/null; then
  warn "update-ca-certificates not found — skipping system trust store"
elif have_sudo; then
  sudo cp "$RSA_DIR/ca.crt"   "$RSA_TRUST"
  sudo cp "$ECDSA_DIR/ca.crt" "$ECDSA_TRUST"
  sudo chmod 644 "$RSA_TRUST" "$ECDSA_TRUST"
  sudo update-ca-certificates --fresh 2>&1 | grep -E 'added|removed|updated|PWDnow' || true
  ok "System trust store updated"
else
  warn "sudo not available non-interactively — run manually to install system trust:"
  warn "  sudo cp $RSA_DIR/ca.crt $RSA_TRUST"
  warn "  sudo cp $ECDSA_DIR/ca.crt $ECDSA_TRUST"
  warn "  sudo update-ca-certificates --fresh"
fi

# ── Chrome / Chromium NSS trust store ────────────────────────────────────────
hdr "Installing to Chrome/Chromium NSS trust store"

install_nss() {
  local db_dir="$1" label="$2"
  if [[ -d "$db_dir" ]]; then
    certutil -d "sql:$db_dir" -A -n "PWDnow RSA CA"   -t "CT,C,C" -i "$RSA_DIR/ca.crt"   2>/dev/null && ok "NSS [$label]: RSA CA added"   || warn "NSS [$label]: RSA CA install failed"
    certutil -d "sql:$db_dir" -A -n "PWDnow ECDSA CA" -t "CT,C,C" -i "$ECDSA_DIR/ca.crt" 2>/dev/null && ok "NSS [$label]: ECDSA CA added" || warn "NSS [$label]: ECDSA CA install failed"
  fi
}

if command -v certutil &>/dev/null; then
  install_nss "$HOME/.pki/nssdb" "Chrome"
  install_nss "$HOME/snap/chromium/current/.pki/nssdb" "Chromium snap"
  install_nss "$HOME/.mozilla/firefox/"*".default-release" "Firefox" 2>/dev/null || true
else
  warn "certutil not found — Chrome/Firefox NSS trust not installed"
  warn "To install: sudo apt-get install libnss3-tools"
  warn "Then re-run this script."
fi

# ── nginx /etc/ssl/vault symlinks ─────────────────────────────────────────────
hdr "Creating /etc/ssl/vault symlinks (nginx compatibility)"

if have_sudo; then
  sudo mkdir -p /etc/ssl/vault
  sudo ln -sf "$ECDSA_DIR/server.crt" /etc/ssl/vault/cert.pem
  sudo ln -sf "$ECDSA_DIR/server.key" /etc/ssl/vault/key.pem
  sudo ln -sf "$RSA_DIR/server.crt"   /etc/ssl/vault/cert-rsa.pem
  sudo ln -sf "$RSA_DIR/server.key"   /etc/ssl/vault/key-rsa.pem
  sudo ln -sf "$ECDSA_DIR/ca.crt"     /etc/ssl/vault/ca.crt
  ok "Symlinks created at /etc/ssl/vault/"
else
  warn "sudo not available — nginx symlinks skipped. Run manually:"
  warn "  sudo mkdir -p /etc/ssl/vault"
  warn "  sudo ln -sf $ECDSA_DIR/server.crt /etc/ssl/vault/cert.pem"
  warn "  sudo ln -sf $ECDSA_DIR/server.key /etc/ssl/vault/key.pem"
  warn "  sudo ln -sf $RSA_DIR/server.crt   /etc/ssl/vault/cert-rsa.pem"
  warn "  sudo ln -sf $RSA_DIR/server.key   /etc/ssl/vault/key-rsa.pem"
  warn "  sudo ln -sf $ECDSA_DIR/ca.crt     /etc/ssl/vault/ca.crt"
fi

# ── Verify certificates ───────────────────────────────────────────────────────
hdr "Certificate verification"

echo ""
log "RSA server certificate:"
openssl x509 -in "$RSA_DIR/server.crt" -noout -subject -issuer -dates 2>&1 | head -10

echo ""
log "ECDSA server certificate:"
openssl x509 -in "$ECDSA_DIR/server.crt" -noout -subject -issuer -dates 2>&1 | head -10

echo ""
log "RSA chain verification:"
openssl verify -CAfile "$RSA_DIR/ca.crt" "$RSA_DIR/server.crt" 2>&1 \
  && ok "RSA chain: OK" || warn "RSA chain verification failed"

log "ECDSA chain verification:"
openssl verify -CAfile "$ECDSA_DIR/ca.crt" "$ECDSA_DIR/server.crt" 2>&1 \
  && ok "ECDSA chain: OK" || warn "ECDSA chain verification failed"

# ── Expiry summary ────────────────────────────────────────────────────────────
echo ""
RSA_EXPIRY=$(openssl x509 -in "$RSA_DIR/server.crt" -noout -enddate | cut -d= -f2)
ECDSA_EXPIRY=$(openssl x509 -in "$ECDSA_DIR/server.crt" -noout -enddate | cut -d= -f2)

echo -e "\n${BOLD}${GREEN}✓ SSL certificates generated successfully!${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  RSA-4096  cert: $RSA_DIR/server.crt"
echo -e "  RSA-4096  key:  $RSA_DIR/server.key"
echo -e "  ECDSA-384 cert: $ECDSA_DIR/server.crt"
echo -e "  ECDSA-384 key:  $ECDSA_DIR/server.key"
echo -e ""
echo -e "  RSA expires:   ${BOLD}$RSA_EXPIRY${NC} ($SSL_PERIOD)"
echo -e "  ECDSA expires: ${BOLD}$ECDSA_EXPIRY${NC} ($SSL_PERIOD)"
echo -e ""
echo -e "  To enable HTTPS in .env:"
echo -e "    ${BOLD}SSL=force${NC}          (redirect HTTP → HTTPS)"
echo -e "    ${BOLD}SSL_PORT=443${NC}       (or 8443 for non-root)"
echo -e "    ${BOLD}SSL_DIR=$SSL_DIR${NC}"
echo -e ""
echo -e "  Restart server:  npm start  (or  pm2 restart all)"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
