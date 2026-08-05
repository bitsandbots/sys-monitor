#!/usr/bin/env bash
# install.sh — SysMonitor installer
# Works unmodified on Ubuntu/Debian PCs & servers and on Raspberry Pi boards —
# hardware is auto-detected at runtime, so there's nothing platform-specific
# to configure here.
#
# Usage:
#   sudo ./install.sh           # Install node agent only
#   sudo ./install.sh --hub     # Install node agent + hub
#   sudo ./install.sh --hub-only  # Install hub only
#   sudo ./install.sh --uninstall  # Remove everything
#
# CoreConduit Consulting Services — MIT License

set -euo pipefail

# Always operate relative to this script's own location, not the caller's cwd —
# needed so update.sh (which invokes install.sh via absolute path from an
# extracted tarball dir) and any other indirect invocation can find the files.
cd "$(dirname "$(readlink -f "$0")")"

# ── Constants ────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/sys-monitor"
NODE_SERVICE="sys-monitor"
HUB_SERVICE="sys-monitor-hub"
NODE_PORT=8585
HUB_PORT=8686

# Pre-unification fork (see MIGRATION.md) — same ports as the unified build,
# so a leftover install here will block sys-monitor from binding on install.
LEGACY_DIR="/opt/rpi-monitor"
LEGACY_SERVICES=("rpi-monitor" "rpi-monitor-hub")
PYTHON="${PYTHON:-python3}"

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLU}[INFO]${NC}  $*"; }
ok()    { echo -e "${GRN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YLW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }

# ── Helpers ─────────────────────────────────────────────────────────────────
# Install pip deps, with or without --break-system-packages (PEP 668)
_pip_install() {
  local req_file="$1"
  local break_flag=""
  if pip3 install --help 2>&1 | grep -q -- '--break-system-packages'; then
    break_flag="--break-system-packages"
  fi
  pip3 install --quiet $break_flag --ignore-installed -r "$req_file"
}

# Open a firewall port via ufw or firewalld (graceful no-op if neither present)
_open_port() {
  local port="$1"
  local proto="${2:-tcp}"

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    if ufw status 2>/dev/null | grep -q "${port}/${proto}"; then
      info "Firewall: port ${port}/${proto} already open (ufw)"
    else
      ufw allow "${port}/${proto}" >/dev/null 2>&1 \
        && ok "Firewall: opened port ${port}/${proto} (ufw)" \
        || warn "Firewall: failed to open ${port}/${proto} — check ufw manually"
    fi
  elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld &>/dev/null; then
    firewall-cmd --add-port="${port}/${proto}" --permanent >/dev/null 2>&1 \
      && firewall-cmd --reload >/dev/null 2>&1 \
      && ok "Firewall: opened port ${port}/${proto} (firewalld)" \
      || warn "Firewall: failed to open ${port}/${proto} — check firewalld manually"
  fi
}

# Remove a firewall port rule (ufw or firewalld)
_close_port() {
  local port="$1"
  local proto="${2:-tcp}"

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw delete allow "${port}/${proto}" >/dev/null 2>&1 || true
  elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld &>/dev/null; then
    firewall-cmd --remove-port="${port}/${proto}" --permanent >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}

# ── Argument parsing ─────────────────────────────────────────────────────────
INSTALL_NODE=true
INSTALL_HUB=false
DO_UNINSTALL=false
CHECK_ONLY=false

for arg in "$@"; do
  case "$arg" in
    --hub)        INSTALL_HUB=true ;;
    --hub-only)   INSTALL_NODE=false; INSTALL_HUB=true ;;
    --uninstall)  DO_UNINSTALL=true ;;
    --check)      CHECK_ONLY=true ;;
    --help|-h)
      sed -n '2,10p' "$0" | sed 's/^# //'
      exit 0
      ;;
    *) die "Unknown argument: $arg. Use --help for usage." ;;
  esac
done

# ── Preflight ────────────────────────────────────────────────────────────────
preflight() {
  [[ $EUID -eq 0 ]] || die "Run as root: sudo $0 $*"

  command -v "$PYTHON" >/dev/null 2>&1 || {
    info "python3 not found, installing..."
    apt-get update -qq && apt-get install -y -qq python3 || die "Failed to install python3"
  }

  if ! command -v pip3 >/dev/null 2>&1; then
    info "pip3 not found, installing python3-pip..."
    apt-get update -qq && apt-get install -y -qq python3-pip || die "Failed to install python3-pip"
  fi

  command -v systemctl >/dev/null 2>&1 || die "systemctl not found — systemd required"

  PYVER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
  PYMAJ=$(echo "$PYVER" | cut -d. -f1)
  PYMIN=$(echo "$PYVER" | cut -d. -f2)
  if [[ "$PYMAJ" -lt 3 || ("$PYMAJ" -eq 3 && "$PYMIN" -lt 11) ]]; then
    die "Python 3.11+ required, found $PYVER"
  fi

  ok "Preflight passed (Python $PYVER)"
}

# ── Uninstall ────────────────────────────────────────────────────────────────
do_uninstall() {
  info "Uninstalling SysMonitor..."

  for svc in "$NODE_SERVICE" "$HUB_SERVICE"; do
    if systemctl is-active "$svc" &>/dev/null; then
      systemctl stop "$svc"
      ok "Stopped $svc"
    fi
    if systemctl is-enabled "$svc" &>/dev/null 2>&1; then
      systemctl disable "$svc"
      ok "Disabled $svc"
    fi
    if [[ -f "/etc/systemd/system/${svc}.service" ]]; then
      rm "/etc/systemd/system/${svc}.service"
      ok "Removed /etc/systemd/system/${svc}.service"
    fi
  done

  systemctl daemon-reload

  _close_port "$NODE_PORT"
  _close_port "$HUB_PORT"

  if [[ -d "$INSTALL_DIR" ]]; then
    rm -rf "$INSTALL_DIR"
    ok "Removed $INSTALL_DIR"
  fi

  ok "SysMonitor uninstalled."
}

# ── Remove pre-unification rpi-monitor fork ──────────────────────────────────
# rpi-monitor was a separate fork of this project (see MIGRATION.md) that
# shares the same ports as sys-monitor. A leftover install left running would
# block the new service from binding, so clean it up before installing.
remove_legacy_install() {
  local found_service=false

  for svc in "${LEGACY_SERVICES[@]}"; do
    if systemctl is-active "$svc" &>/dev/null; then
      systemctl stop "$svc"
      ok "Stopped legacy service: $svc"
      found_service=true
    fi
    if systemctl is-enabled "$svc" &>/dev/null 2>&1; then
      systemctl disable "$svc"
      ok "Disabled legacy service: $svc"
      found_service=true
    fi
    if [[ -f "/etc/systemd/system/${svc}.service" ]]; then
      rm "/etc/systemd/system/${svc}.service"
      ok "Removed /etc/systemd/system/${svc}.service"
      found_service=true
    fi
  done

  $found_service && systemctl daemon-reload

  if [[ -f "$LEGACY_DIR/services.json" && ! -f "$INSTALL_DIR/services.json" ]]; then
    mkdir -p "$INSTALL_DIR"
    cp "$LEGACY_DIR/services.json" "$INSTALL_DIR/services.json"
    info "Preserved monitored-service list from $LEGACY_DIR/services.json"
  fi

  if [[ -d "$LEGACY_DIR" ]]; then
    rm -rf "$LEGACY_DIR"
    ok "Removed legacy install: $LEGACY_DIR"
  fi
}

# ── Install node agent ────────────────────────────────────────────────────────
install_node() {
  info "Installing SysMonitor node agent → $INSTALL_DIR"

  mkdir -p "$INSTALL_DIR/templates"
  mkdir -p "$INSTALL_DIR/static/fonts"
  cp sys_monitor.py "$INSTALL_DIR/"
  # hiddenscope_scanner.py is optional (security monitoring degrades to
  # "unavailable" without it) but should always be installed alongside
  # sys_monitor.py when present in the source tree.
  [[ -f hiddenscope_scanner.py ]] && cp hiddenscope_scanner.py "$INSTALL_DIR/"
  cp templates/index.html "$INSTALL_DIR/templates/"
  # Copy static files (fonts for offline capability)
  if [[ -d static ]]; then
    cp -r static/* "$INSTALL_DIR/static/" 2>/dev/null || true
  fi
  cp requirements.txt "$INSTALL_DIR/"
  # Only seed the default service list — never overwrite a config already in
  # place (a live customized list, or one preserved from a legacy install).
  [[ -f "$INSTALL_DIR/services.json" ]] || cp services.json "$INSTALL_DIR/" 2>/dev/null || true
  [[ -f .env.example ]] && cp .env.example "$INSTALL_DIR/"

  _pip_install "$INSTALL_DIR/requirements.txt"
  ok "Dependencies installed"

  _open_port "$NODE_PORT"
  cp sys-monitor.service /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable "$NODE_SERVICE"
  systemctl start  "$NODE_SERVICE"

  # Wait for service to come up
  local retries=10
  while [[ $retries -gt 0 ]]; do
    if curl -sf "http://localhost:${NODE_PORT}/api/ping" >/dev/null 2>&1; then
      ok "Node agent running at http://localhost:${NODE_PORT}"
      return 0
    fi
    retries=$((retries - 1))
    sleep 1
  done
  ok "Service started but health check didn't respond on :${NODE_PORT} — check: journalctl -u $NODE_SERVICE"
}

# ── Install hub ───────────────────────────────────────────────────────────────
install_hub() {
  info "Installing SysMonitor Hub → $INSTALL_DIR/hub"

  mkdir -p "$INSTALL_DIR/hub/templates"
  mkdir -p "$INSTALL_DIR/hub/static/fonts"
  cp hub/sys_monitor_hub.py "$INSTALL_DIR/hub/"
  cp hub/templates/hub.html "$INSTALL_DIR/hub/templates/"
  # Copy static files (fonts for offline capability)
  if [[ -d static ]]; then
    cp -r static/* "$INSTALL_DIR/hub/static/" 2>/dev/null || true
  fi
  cp hub/requirements.txt "$INSTALL_DIR/hub/"
  [[ -f hub/HUB_README.md ]] && cp hub/HUB_README.md "$INSTALL_DIR/hub/"

  _pip_install "hub/requirements.txt"
  ok "Hub dependencies installed"

  _open_port "$HUB_PORT"
  cp hub/sys-monitor-hub.service /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable "$HUB_SERVICE"
  systemctl start  "$HUB_SERVICE"

  local retries=10
  while [[ $retries -gt 0 ]]; do
    if curl -sf "http://localhost:${HUB_PORT}/api/ping" >/dev/null 2>&1; then
      ok "Hub running at http://localhost:${HUB_PORT}"
      return 0
    fi
    retries=$((retries - 1))
    sleep 1
  done
  warn "Service started but health check didn't respond on :${HUB_PORT} — check: journalctl -u $HUB_SERVICE"
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
  echo ""
  echo "  Sys|Monitor  Installer"
  echo "  CoreConduit Consulting Services"
  echo ""

  if $DO_UNINSTALL; then
    [[ $EUID -eq 0 ]] || die "Run as root: sudo $0 --uninstall"
    do_uninstall
    exit 0
  fi

  preflight

  if $CHECK_ONLY; then
    ok "Preflight check passed — system is ready for installation."
    exit 0
  fi

  remove_legacy_install

  $INSTALL_NODE && install_node
  $INSTALL_HUB  && install_hub

  echo ""
  ok "Installation complete."
  $INSTALL_NODE && echo "    Node agent  → http://$(hostname -I | awk '{print $1}'):${NODE_PORT}"
  $INSTALL_HUB  && echo "    Hub         → http://$(hostname -I | awk '{print $1}'):${HUB_PORT}"
  echo ""
}

main "$@"
