#!/bin/bash
# PWDnow Senior Dev Recovery Script
# Target: Resolve system instability and GNOME Settings Daemon failures.

echo "==> Diagnosing System Integrity..."

# 1. Memory Pressure Audit
FREE_MEM=$(free -m | awk '/^Mem:/{print $4}')
TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
SWAP_USED=$(free -m | awk '/^Swap:/{print $3}')

echo "    Memory: ${FREE_MEM}MB free / ${TOTAL_MEM}MB total"
echo "    Swap:   ${SWAP_USED}MB used"

if [ "$FREE_MEM" -lt 300 ]; then
    echo "    [!] ALERT: Critical memory pressure detected."
    echo "    [!] Recommendation: Increasing swap or closing high-resource apps (e.g., Obsidian, Browsers)."
fi

# 2. GNOME Settings Daemon (GSD) Component Check
echo "==> Auditing GNOME Settings Daemon components..."
GSD_PROCS=$(pgrep -f /usr/libexec/gsd-)

if [ -z "$GSD_PROCS" ]; then
    echo "    [!] ALERT: No GSD components found running. GNOME environment may be degraded."
else
    echo "    [i] Found $(echo "$GSD_PROCS" | wc -l) GSD components."
fi

# 3. Targeted Recovery
echo "==> Attempting graceful recovery of key components..."

# Restart xsettings - handles DPI, fonts, and theme settings
if pkill -f gsd-xsettings; then
    echo "    [+] Restarted gsd-xsettings"
    /usr/libexec/gsd-xsettings &
fi

# Restart media-keys - handles volume/brightness keys
if pkill -f gsd-media-keys; then
    echo "    [+] Restarted gsd-media-keys"
    /usr/libexec/gsd-media-keys &
fi

# 4. IPC & Socket Audit for PWDnow
echo "==> Auditing PWDnow IPC sockets..."
if [ -S "/run/vault-daemon/vault.sock" ]; then
    echo "    [i] System vault socket present."
fi
if [ -S "/tmp/vault-dev.sock" ]; then
    echo "    [i] Dev vault socket present."
fi

echo "==> Recovery sequence complete."
echo "    If GUI issues persist, run 'journalctl -xe --user' for detailed error logs."
