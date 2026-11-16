#!/usr/bin/env bash
# Install the SysMonitor IP-blocker helper (run from the repo root as root).
# Idempotent. Does NOT enable blocking: set SYSMONITOR_BLOCK_MODE yourself
# (dry-run first). Backs up anything it replaces to *.bak-<timestamp>.
set -euo pipefail

SVC_USER="${SYSMON_USER:-sys-monitor}"
STAMP="$(date +%Y%m%d-%H%M%S)"
SRC="$(cd "$(dirname "$0")" && pwd)"

[[ $EUID -eq 0 ]] || { echo "run as root (sudo $0)" >&2; exit 1; }
id "$SVC_USER" >/dev/null 2>&1 || { echo "service user '$SVC_USER' not found (set SYSMON_USER)" >&2; exit 1; }
command -v nft >/dev/null || { echo "nft not installed (apt install nftables)" >&2; exit 1; }

backup() { [[ -e "$1" ]] && cp -a "$1" "$1.bak-$STAMP" || true; }

backup /usr/local/sbin/sysmon-block
install -o root -g root -m 0755 "$SRC/sysmon-block" /usr/local/sbin/sysmon-block

install -d -o root -g root -m 0700 /var/lib/sysmon-block
install -d -o root -g root -m 0755 /etc/sys-monitor
[[ -e /etc/sys-monitor/block-allowlist ]] || \
    install -o root -g root -m 0644 "$SRC/sysmon-block-allowlist.example" /etc/sys-monitor/block-allowlist

# sudoers: validate before installing so a typo can never lock out sudo.
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
sed "s/^sys-monitor /$SVC_USER /" "$SRC/sysmon-block.sudoers" > "$TMP"
visudo -cf "$TMP" >/dev/null
backup /etc/sudoers.d/sys-monitor-block
install -o root -g root -m 0440 "$TMP" /etc/sudoers.d/sys-monitor-block

install -d /etc/systemd/system/sys-monitor.service.d
backup /etc/systemd/system/sys-monitor.service.d/threats.conf
install -m 0644 "$SRC/sys-monitor-threats.conf" /etc/systemd/system/sys-monitor.service.d/threats.conf
install -m 0644 "$SRC/sysmon-block-restore.service" /etc/systemd/system/sysmon-block-restore.service
systemctl daemon-reload
systemctl enable sysmon-block-restore.service >/dev/null

echo "Installed. Next: set SYSMONITOR_BLOCK_MODE=dry-run (drop-in or /etc/sys-monitor/env)"
echo "and SYSMONITOR_PUBLIC_URL for the ntfy Block button, then: systemctl restart sys-monitor"
