#!/usr/bin/env bash
# update.sh — SysMonitor auto-updater
# Checks GitHub for the latest release, compares against installed version,
# downloads + verifies the tarball, and reinstalls if newer.
#
# Usage:
#   sudo ./update.sh              # Check and update if newer version found
#   sudo ./update.sh --check      # Dry-run: report version diff, no install
#   sudo ./update.sh --force      # Reinstall even if version matches
#   sudo ./update.sh --hub        # Also update the hub component
#   sudo ./update.sh --hub-only   # Update hub only
#   sudo ./update.sh --no-verify  # Skip SHA-256 checksum verification
#
# Cron (daily at 3am):
#   0 3 * * * root /opt/sys-monitor/update.sh --hub >> /var/log/sys-monitor-update.log 2>&1
#
# CoreConduit Consulting Services — MIT License

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
REPO="bitsandbots/sys-monitor"
INSTALL_DIR="/opt/sys-monitor"
NODE_SERVICE="sys-monitor"
HUB_SERVICE="sys-monitor-hub"
API_URL="https://api.github.com/repos/${REPO}/releases/latest"
LOG_FILE="/var/log/sys-monitor-update.log"
WORK_DIR="/tmp/sys-monitor-update-$$"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLU}[INFO]${NC}  $*"; }
ok()    { echo -e "${GRN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YLW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }

# ── Argument parsing ──────────────────────────────────────────────────────────
CHECK_ONLY=false
FORCE=false
INSTALL_HUB=false
HUB_ONLY=false
VERIFY=true

for arg in "$@"; do
  case "$arg" in
    --check)     CHECK_ONLY=true ;;
    --force)     FORCE=true ;;
    --hub)       INSTALL_HUB=true ;;
    --hub-only)  HUB_ONLY=true; INSTALL_HUB=true ;;
    --no-verify) VERIFY=false ;;
    --help|-h)
      sed -n '2,12p' "$0" | sed 's/^# //'
      exit 0
      ;;
    *) die "Unknown argument: $arg. Use --help for usage." ;;
  esac
done

# ── Preflight ─────────────────────────────────────────────────────────────────
preflight() {
  if ! $CHECK_ONLY; then
    [[ $EUID -eq 0 ]] || die "Run as root: sudo $0 $*"
  fi
  command -v curl    >/dev/null 2>&1 || die "curl not found. Install with: apt install curl"
  command -v python3 >/dev/null 2>&1 || die "python3 not found."
  $VERIFY && { command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found."; }
}

# ── Version helpers ───────────────────────────────────────────────────────────

# Read VERSION from an installed sys_monitor.py (node or hub)
read_installed_version() {
  local file="$1"
  if [[ -f "$file" ]]; then
    grep '^VERSION = ' "$file" | sed 's/VERSION = "\(.*\)"/\1/'
  else
    echo "0.0.0"
  fi
}

# Compare two semver strings: returns 0 if $1 < $2 (update available)
semver_lt() {
  python3 -c "
import sys
a = tuple(int(x) for x in '$1'.split('.'))
b = tuple(int(x) for x in '$2'.split('.'))
sys.exit(0 if a < b else 1)
"
}

# ── GitHub release query ──────────────────────────────────────────────────────
fetch_latest_release() {
  local response
  response=$(curl -fsSL --connect-timeout 10 --max-time 30 \
    -H "Accept: application/vnd.github+json" \
    "$API_URL") || die "Failed to reach GitHub API: $API_URL"

  LATEST_TAG=$(echo "$response" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data['tag_name'])
" 2>/dev/null) || die "Could not parse tag_name from GitHub API response."

  LATEST_VERSION="${LATEST_TAG#v}"  # strip leading 'v'

  # Find tarball asset URL (matches sys-monitor-<version>.tar.gz)
  TARBALL_URL=$(echo "$response" | python3 -c "
import sys, json
data = json.load(sys.stdin)
assets = data.get('assets', [])
for a in assets:
    if a['name'].endswith('.tar.gz'):
        print(a['browser_download_url'])
        break
" 2>/dev/null) || true

  # Find checksum asset URL
  CHECKSUM_URL=$(echo "$response" | python3 -c "
import sys, json
data = json.load(sys.stdin)
assets = data.get('assets', [])
for a in assets:
    if a['name'].endswith('.sha256'):
        print(a['browser_download_url'])
        break
" 2>/dev/null) || true

  # Fallback: construct URLs from release tag if assets list is empty
  # (for repos that use source archives rather than uploaded assets)
  if [[ -z "$TARBALL_URL" ]]; then
    TARBALL_URL="https://github.com/${REPO}/archive/refs/tags/${LATEST_TAG}.tar.gz"
    VERIFY=false  # no checksum available for source archives
    warn "No release assets found — falling back to source archive (checksum disabled)"
  fi
}

# ── Download + verify ─────────────────────────────────────────────────────────
download_and_verify() {
  local archive_name="sys-monitor-${LATEST_VERSION}.tar.gz"
  local archive_path="${WORK_DIR}/${archive_name}"

  mkdir -p "$WORK_DIR"
  info "Downloading $archive_name..."
  curl -fsSL --connect-timeout 15 --max-time 120 \
    -o "$archive_path" "$TARBALL_URL" \
    || die "Download failed: $TARBALL_URL"
  ok "Downloaded $(du -sh "$archive_path" | cut -f1)"

  if $VERIFY && [[ -n "$CHECKSUM_URL" ]]; then
    local checksum_path="${WORK_DIR}/release.sha256"
    info "Verifying SHA-256 checksum..."
    curl -fsSL --connect-timeout 10 --max-time 30 \
      -o "$checksum_path" "$CHECKSUM_URL" \
      || die "Checksum download failed: $CHECKSUM_URL"

    # sha256sum file references the tarball by name — run from WORK_DIR
    (cd "$WORK_DIR" && sha256sum -c "release.sha256") \
      || die "Checksum mismatch — aborting install. The downloaded file may be corrupt."
    ok "Checksum verified"
  elif $VERIFY; then
    warn "No checksum URL available — skipping verification"
  fi

  ARCHIVE_PATH="$archive_path"
}

# ── Install from tarball ──────────────────────────────────────────────────────
run_install() {
  local install_flags=()
  if $HUB_ONLY; then
    install_flags+=("--hub-only")
  elif $INSTALL_HUB; then
    install_flags+=("--hub")
  fi

  info "Extracting archive..."
  tar -xzf "$ARCHIVE_PATH" -C "$WORK_DIR"

  # Find extracted directory (sys-monitor-<version>/ or sys-monitor-<tag>/)
  local extract_dir
  extract_dir=$(find "$WORK_DIR" -mindepth 1 -maxdepth 1 -type d -name "sys-monitor-*" | head -1)
  [[ -n "$extract_dir" ]] || die "Could not find extracted directory in $WORK_DIR"

  info "Running install.sh ${install_flags[*]:-}..."
  bash "${extract_dir}/install.sh" "${install_flags[@]}" \
    || die "install.sh failed — services may be in a partial state. Check journalctl -u ${NODE_SERVICE}."
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  echo ""
  echo "  Sys|Monitor  Auto-Updater"
  echo "  CoreConduit Consulting Services"
  echo ""

  preflight

  # Read installed versions
  local node_installed hub_installed
  node_installed=$(read_installed_version "${INSTALL_DIR}/sys_monitor.py")
  hub_installed=$(read_installed_version "${INSTALL_DIR}/hub/sys_monitor_hub.py")

  info "Installed: node v${node_installed}  hub v${hub_installed}"
  info "Checking GitHub for latest release..."

  fetch_latest_release

  info "Latest:    v${LATEST_VERSION}  (${LATEST_TAG})"
  echo ""

  # Determine which component(s) to consider
  local needs_update=false
  if ! $HUB_ONLY; then
    if $FORCE || semver_lt "$node_installed" "$LATEST_VERSION"; then
      needs_update=true
      info "Node agent: v${node_installed} → v${LATEST_VERSION}"
    else
      ok "Node agent: already up to date (v${node_installed})"
    fi
  fi
  if $INSTALL_HUB; then
    if $FORCE || semver_lt "$hub_installed" "$LATEST_VERSION"; then
      needs_update=true
      info "Hub:        v${hub_installed} → v${LATEST_VERSION}"
    else
      ok "Hub:        already up to date (v${hub_installed})"
    fi
  fi

  if ! $needs_update; then
    ok "Nothing to update."
    exit 0
  fi

  if $CHECK_ONLY; then
    warn "Update available — re-run without --check to install."
    exit 0
  fi

  download_and_verify
  run_install

  # Confirm post-install version
  local node_after hub_after
  node_after=$(read_installed_version "${INSTALL_DIR}/sys_monitor.py")
  hub_after=$(read_installed_version "${INSTALL_DIR}/hub/sys_monitor_hub.py")

  echo ""
  ok "Update complete."
  ok "  Node: v${node_installed} → v${node_after}"
  $INSTALL_HUB && ok "  Hub:  v${hub_installed} → v${hub_after}"
  echo ""
}

main "$@"
