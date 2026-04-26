#!/usr/bin/env bash
# detect-system.sh — PWDnow first-run system detection
# Outputs a single JSON object to stdout. Safe to run without root.
# Every command failure is caught locally; fields default to null/false.

# -u: treat unset vars as errors. No -e so individual probes can fail safely.
set -uo pipefail

# ── Helper: escape a string for JSON ─────────────────────────────────────────
esc() { printf '%s' "${1:-}" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# ── Defaults ──────────────────────────────────────────────────────────────────
OS="unknown"
OS_PRETTY="Unknown"
OS_LTS="false"
VERSION=""
KERNEL="unknown"
ARCH="unknown"
CPU_MODEL="unknown"
HOSTNAME_VAL="unknown"
UBUNTU_PRO="false"
FIPS_ENABLED="false"

TPM_PRESENT="false"
TPM_VERSION="unknown"
TPM_TYPE="unknown"

HSM_PRESENT="false"
HSM_TYPE=""

DRIVE_ENCRYPTED="false"
DRIVE_TECH=""
DRIVE_CIPHER=""
DRIVE_FIPS_140="false"
DRIVE_CSFC="false"
CRYPTSETUP_FIPS="false"

# ── Basic system info ─────────────────────────────────────────────────────────
HOSTNAME_VAL=$(hostname 2>/dev/null || echo "unknown")
KERNEL=$(uname -r 2>/dev/null || echo "unknown")
ARCH=$(uname -m 2>/dev/null || echo "unknown")

# CPU model — x86/x86_64 has "model name"; ARM has "Hardware" or "CPU part"
CPU_MODEL=$(grep -m1 "^model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2- | xargs || true)
if [ -z "${CPU_MODEL:-}" ]; then
  CPU_MODEL=$(grep -m1 "^Hardware" /proc/cpuinfo 2>/dev/null | cut -d: -f2- | xargs || true)
fi
if [ -z "${CPU_MODEL:-}" ]; then
  # ARM: build a synthetic string from implementer + part
  _IMP=$(grep -m1 "^CPU implementer" /proc/cpuinfo 2>/dev/null | awk '{print $NF}' || true)
  _ARC=$(grep -m1 "^CPU architecture" /proc/cpuinfo 2>/dev/null | awk '{print $NF}' || true)
  CPU_MODEL="ARM (implementer=${_IMP:-?}, arch=${_ARC:-?})"
fi

# ── OS detection ──────────────────────────────────────────────────────────────
if [ -f /etc/os-release ]; then
  # Pull the fields we need without sourcing the whole file
  _ID=$(     grep -E '^ID='          /etc/os-release | head -1 | cut -d= -f2- | tr -d '"')
  _LIKE=$(   grep -E '^ID_LIKE='     /etc/os-release | head -1 | cut -d= -f2- | tr -d '"')
  _VER=$(    grep -E '^VERSION_ID='  /etc/os-release | head -1 | cut -d= -f2- | tr -d '"')
  _PRETTY=$( grep -E '^PRETTY_NAME=' /etc/os-release | head -1 | cut -d= -f2- | tr -d '"')

  OS="${_ID:-unknown}"
  OS_PRETTY="${_PRETTY:-$OS}"
  VERSION="${_VER:-}"

  # LTS: Canonical always puts "LTS" in PRETTY_NAME for LTS releases
  echo "$OS_PRETTY" | grep -qi "LTS" && OS_LTS="true"

  # Raspbian / Raspberry Pi OS
  if echo "${_ID:-}${_LIKE:-}" | grep -qi "raspbian"; then
    OS="raspbian"
    OS_PRETTY="${_PRETTY:-Raspbian}"
  fi
fi

# Raspberry Pi OS fallback (rebranded from Raspbian, lacks ID=raspbian)
if [ -f /etc/rpi-issue ] && [ "$OS" != "raspbian" ]; then
  OS="raspbian"
  OS_PRETTY="Raspberry Pi OS"
fi

# ── Ubuntu Pro ────────────────────────────────────────────────────────────────
if [ "$OS" = "ubuntu" ]; then
  for _CMD in pro ubuntu-advantage; do
    if command -v "$_CMD" &>/dev/null; then
      _JSON=$("$_CMD" status --format json 2>/dev/null || echo "{}")
      echo "$_JSON" | grep -q '"attached"[[:space:]]*:[[:space:]]*true' && UBUNTU_PRO="true"
      break
    fi
  done

  # FIPS kernel mode
  if [ -f /proc/sys/crypto/fips_enabled ]; then
    _FVAL=$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo "0")
    [ "$_FVAL" = "1" ] && FIPS_ENABLED="true"
  fi
fi

# ── TPM 2.0 detection ────────────────────────────────────────────────────────
# Priority: sysfs device node → /dev nodes → tpm2_getcap → dmesg

for _IDX in 0 1; do
  _SYSFS="/sys/class/tpm/tpm${_IDX}"
  _DEV="/dev/tpm${_IDX}"
  _DEVR="/dev/tpmrm${_IDX}"

  if [ -d "$_SYSFS" ] || [ -c "$_DEV" ] || [ -c "$_DEVR" ]; then
    TPM_PRESENT="true"

    # Version from sysfs major version file
    if [ -f "${_SYSFS}/tpm_version_major" ]; then
      _VMAJ=$(cat "${_SYSFS}/tpm_version_major" 2>/dev/null || echo "")
      [ -n "$_VMAJ" ] && TPM_VERSION="${_VMAJ}.0"
    fi

    # Firmware vs discrete: inspect the device symlink path
    _DPATH=$(readlink -f "${_SYSFS}/device" 2>/dev/null || echo "")
    if echo "$_DPATH" | grep -qiE "MSFT0101|MSFT0200|MSFT0003|AMD0000|NVTPM|firmware"; then
      TPM_TYPE="firmware"
    elif echo "$_DPATH" | grep -qi "usb"; then
      TPM_TYPE="discrete_usb"
    elif echo "$_DPATH" | grep -qiE "spi|i2c"; then
      TPM_TYPE="discrete_spi"
    elif echo "$_DPATH" | grep -qi "pnp\|acpi"; then
      # ACPI-enumerated usually means fTPM
      TPM_TYPE="firmware"
    fi

    # CRB/FIFO driver → usually firmware TPM on modern hardware
    _DRV_PATH="${_SYSFS}/device/driver"
    if [ -L "$_DRV_PATH" ]; then
      _DRV=$(readlink "$_DRV_PATH" 2>/dev/null | awk -F/ '{print $NF}')
      case "${_DRV:-}" in
        tpm_crb)  TPM_TYPE="firmware" ;;   # CRB = Command/Response Buffer (fTPM)
        tpm_tis)  TPM_TYPE="discrete" ;;   # TIS = legacy LPC discrete chip
      esac
    fi

    break
  fi
done

# If present but type still unknown, infer from CPU vendor
if [ "$TPM_PRESENT" = "true" ] && [ "$TPM_TYPE" = "unknown" ]; then
  _VCPU=$(grep -m1 "^vendor_id" /proc/cpuinfo 2>/dev/null | awk '{print $NF}' || true)
  case "${_VCPU:-}" in
    GenuineIntel) TPM_TYPE="firmware_intel_ptt" ;;
    AuthenticAMD) TPM_TYPE="firmware_amd_ftpm" ;;
  esac
fi

# tpm2_getcap gives authoritative 2.0 confirmation
if [ "$TPM_PRESENT" = "true" ] && command -v tpm2_getcap &>/dev/null; then
  _T2=$(tpm2_getcap properties-fixed 2>/dev/null | head -5 || echo "")
  [ -n "$_T2" ] && TPM_VERSION="2.0"
fi

# Last resort: dmesg (may be restricted on hardened kernels)
if [ "$TPM_PRESENT" = "false" ]; then
  _DMESG=$(dmesg 2>/dev/null | grep -i "tpm\b" | head -5 || true)
  if echo "$_DMESG" | grep -qi "tpm_crb\|tpm_tis\|MSFT0101\|AMD fTPM\|Intel PTT"; then
    TPM_PRESENT="true"
    TPM_VERSION="2.0"
    echo "$_DMESG" | grep -qi "Intel PTT\|MSFT0101" && TPM_TYPE="firmware_intel_ptt"
    echo "$_DMESG" | grep -qi "AMD fTPM\|AMD0000"   && TPM_TYPE="firmware_amd_ftpm"
  fi
fi

# ── HSM detection ─────────────────────────────────────────────────────────────

# USB-connected HSMs
if command -v lsusb &>/dev/null; then
  _USB=$(lsusb 2>/dev/null || echo "")

  # YubiHSM 2 (Yubico 1050:0030)
  if echo "$_USB" | grep -qi "1050:0030\|YubiHSM"; then
    HSM_PRESENT="true"; HSM_TYPE="YubiHSM 2"
  # Thales/SafeNet Luna (VID 0529)
  elif echo "$_USB" | grep -qi "0529:\|Luna.*HSM\|SafeNet"; then
    HSM_PRESENT="true"; HSM_TYPE="Thales Luna"
  # Nitrokey HSM 2 (20a0:4230)
  elif echo "$_USB" | grep -qiE "20a0:4230|Nitrokey HSM"; then
    HSM_PRESENT="true"; HSM_TYPE="Nitrokey HSM 2"
  # nCipher/Entrust nShield (0b73)
  elif echo "$_USB" | grep -qi "0b73:\|nCipher\|nShield"; then
    HSM_PRESENT="true"; HSM_TYPE="nCipher nShield"
  # Utimaco (0529 or 047f)
  elif echo "$_USB" | grep -qi "Utimaco"; then
    HSM_PRESENT="true"; HSM_TYPE="Utimaco"
  fi
fi

# Network/PCIe HSMs — check for PKCS#11 libraries and management tools
if [ "$HSM_PRESENT" = "false" ]; then
  for _LIB in \
    /usr/lib/libsofthsm2.so \
    /usr/local/lib/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/libsofthsm2.so \
    /usr/lib/aarch64-linux-gnu/libsofthsm2.so \
    /usr/lib64/libsofthsm2.so \
    /usr/lib/libyubihsm.so /usr/local/lib/libyubihsm.so \
    /usr/lib/libykcs11.so  /usr/local/lib/libykcs11.so \
    /usr/lib/opensc-pkcs11.so \
    /usr/lib/libCryptoki2_64.so \
    /usr/lib/libnethsm.so; do
    if [ -f "$_LIB" ]; then
      HSM_PRESENT="true"
      case "$_LIB" in
        *softhsm*) HSM_TYPE="SoftHSM2 (software emulation)" ;;
        *yubihsm*) HSM_TYPE="YubiHSM" ;;
        *ykcs11*)  HSM_TYPE="YubiKey (PKCS#11)" ;;
        *Cryptoki*) HSM_TYPE="Thales/Gemalto" ;;
        *nethsm*)  HSM_TYPE="Nitrokey NetHSM" ;;
        *)         HSM_TYPE="PKCS#11 library ($(basename "$_LIB"))" ;;
      esac
      break
    fi
  done
fi

# p11-kit module registry
if [ "$HSM_PRESENT" = "false" ] && command -v p11-kit &>/dev/null; then
  _P11=$(p11-kit list-modules 2>/dev/null | grep -iE "hsm|yubikey|luna|nitro|thales" | head -1 || true)
  if [ -n "$_P11" ]; then
    HSM_PRESENT="true"
    HSM_TYPE="$(echo "$_P11" | awk '{print $1}') (p11-kit)"
  fi
fi

# ── Drive encryption detection ────────────────────────────────────────────────

# 1. LUKS / dm-crypt via lsblk (no root needed)
if command -v lsblk &>/dev/null; then
  _CRYPT_N=$(lsblk -o TYPE 2>/dev/null | grep -c "^crypt$" || true)
  _CRYPT_N=${_CRYPT_N:-0}
  if [ "$_CRYPT_N" -gt 0 ] 2>/dev/null; then
    DRIVE_ENCRYPTED="true"
    DRIVE_TECH="LUKS"
  fi
fi

# 2. Detailed cipher/version via cryptsetup status (works on open volumes w/o root)
if [ "$DRIVE_ENCRYPTED" = "true" ] && command -v cryptsetup &>/dev/null; then
  # All active mapper devices of type crypt
  _CNAMES=$(lsblk -o NAME,TYPE 2>/dev/null \
    | awk '$2=="crypt"{print $1}' \
    | tr -d '├─└─│ ' || echo "")

  for _CN in $_CNAMES; do
    _ST=$(cryptsetup status "/dev/mapper/$_CN" 2>/dev/null || true)
    if [ -n "$_ST" ]; then
      # Cipher (e.g. aes-xts-plain64)
      _CI=$(echo "$_ST" | awk '/cipher:/{print $2}' | head -1)
      [ -n "${_CI:-}" ] && DRIVE_CIPHER="$_CI"

      # Key size in bits
      _KS=$(echo "$_ST" | awk '/keysize:/{print $2}' | head -1)

      # LUKS version from type field
      _LV=$(echo "$_ST" | awk '/^\s+type:/{print $2}' | head -1)
      echo "${_LV:-}" | grep -qi "LUKS2" && DRIVE_TECH="LUKS2"
      echo "${_LV:-}" | grep -qi "LUKS1" && DRIVE_TECH="LUKS1"

      # FIPS 140-2 approved: AES-XTS with 512-bit key (= AES-256-XTS, two 256-bit subkeys)
      if echo "${_CI:-}" | grep -qi "aes.*xts\|xts.*aes"; then
        if echo "${_KS:-}" | grep -qE "^512$|^256$"; then
          DRIVE_FIPS_140="true"
        fi
      fi
      break
    fi
  done

  # Check if cryptsetup itself was built with FIPS support
  cryptsetup --version 2>/dev/null | grep -q "FIPS" && CRYPTSETUP_FIPS="true"
fi

# 3. VeraCrypt volumes
if command -v veracrypt &>/dev/null; then
  _VC=$(veracrypt --text --list 2>/dev/null | grep -c "." || echo "0")
  if [ "${_VC:-0}" -gt 0 ]; then
    DRIVE_ENCRYPTED="true"
    DRIVE_TECH="${DRIVE_TECH:+${DRIVE_TECH}+}VeraCrypt"
  fi
fi

# 4. ZFS native encryption
if command -v zfs &>/dev/null; then
  _ZE=$(zfs get -H -o value encryption 2>/dev/null | grep -v "^off$" | grep -v "^-$" | head -1 || true)
  if [ -n "${_ZE:-}" ]; then
    DRIVE_ENCRYPTED="true"
    DRIVE_TECH="${DRIVE_TECH:+${DRIVE_TECH}+}ZFS-Enc(${_ZE})"
  fi
fi

# 5. TCG OPAL / SED (Self-Encrypting Drive)
OPAL_PRESENT="false"
if command -v sedutil-cli &>/dev/null; then
  _OPAL=$(sedutil-cli --scan 2>/dev/null || true)
  if echo "${_OPAL:-}" | grep -qi "OPAL\|YES"; then
    DRIVE_ENCRYPTED="true"
    OPAL_PRESENT="true"
    DRIVE_TECH="${DRIVE_TECH:+${DRIVE_TECH}+}OPAL-SED"
  fi
fi

# 6. Refine FIPS 140 flag: also requires FIPS kernel mode when LUKS is involved
if [ "$DRIVE_FIPS_140" = "true" ] && [ "$FIPS_ENABLED" = "false" ]; then
  # AES-XTS cipher is present but kernel FIPS mode is off — flag as "capable" not "active"
  DRIVE_FIPS_140="capable"
fi

# 7. CSfC: requires two independent encryption layers (NSA CSfC Volume Encryption Annex)
_LAYERS=0
echo "${DRIVE_TECH:-}" | grep -qi "LUKS"      && _LAYERS=$((_LAYERS+1))
echo "${DRIVE_TECH:-}" | grep -qi "OPAL"      && _LAYERS=$((_LAYERS+1))
echo "${DRIVE_TECH:-}" | grep -qi "VeraCrypt" && _LAYERS=$((_LAYERS+1))
echo "${DRIVE_TECH:-}" | grep -qi "ZFS"       && _LAYERS=$((_LAYERS+1))
[ "$_LAYERS" -ge 2 ] && DRIVE_CSFC="true"

# ── Emit JSON ─────────────────────────────────────────────────────────────────
printf '{\n'
printf '  "os": "%s",\n'              "$(esc "$OS")"
printf '  "os_pretty": "%s",\n'       "$(esc "$OS_PRETTY")"
printf '  "os_lts": %s,\n'            "$OS_LTS"
printf '  "version": "%s",\n'         "$(esc "$VERSION")"
printf '  "kernel": "%s",\n'          "$(esc "$KERNEL")"
printf '  "arch": "%s",\n'            "$(esc "$ARCH")"
printf '  "cpu_model": "%s",\n'       "$(esc "$CPU_MODEL")"
printf '  "hostname": "%s",\n'        "$(esc "$HOSTNAME_VAL")"
printf '  "ubuntu_pro": %s,\n'        "$UBUNTU_PRO"
printf '  "fips_enabled": %s,\n'      "$FIPS_ENABLED"
printf '  "tpm": {\n'
printf '    "present": %s,\n'         "$TPM_PRESENT"
printf '    "version": "%s",\n'       "$(esc "$TPM_VERSION")"
printf '    "type": "%s"\n'           "$(esc "$TPM_TYPE")"
printf '  },\n'
printf '  "hsm": {\n'
printf '    "present": %s,\n'         "$HSM_PRESENT"
printf '    "type": "%s"\n'           "$(esc "$HSM_TYPE")"
printf '  },\n'
printf '  "drive_encryption": {\n'
printf '    "encrypted": %s,\n'       "$DRIVE_ENCRYPTED"
printf '    "technology": "%s",\n'    "$(esc "$DRIVE_TECH")"
printf '    "cipher": "%s",\n'        "$(esc "$DRIVE_CIPHER")"
printf '    "fips_140": "%s",\n'      "$(esc "$DRIVE_FIPS_140")"
printf '    "csfc": %s\n'             "$DRIVE_CSFC"
printf '  }\n'
printf '}\n'
