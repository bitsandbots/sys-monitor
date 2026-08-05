#!/usr/bin/env bash
# release.sh — SysMonitor release packager
# Run from the repo root on your dev machine (not on the Pi).
#
# Usage:
#   ./release.sh                  # Package current VERSION from sys_monitor.py
#   ./release.sh 2.1.0            # Bump to 2.1.0, tag, and package
#   ./release.sh 2.1.0 --clean    # Clean dist/ before building
#
# Produces:
#   dist/sys-monitor-<version>.tar.gz  — release tarball
#   dist/sys-monitor-<version>.sha256  — checksum file
#
# CoreConduit Consulting Services — MIT License

set -euo pipefail

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

DRY=false
CLEAN=false
NEW_VERSION=""

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=true ;;
    --clean)   CLEAN=true ;;
    --help|-h)
      sed -n '2,10p' "$0" | sed 's/^# //'
      exit 0
      ;;
    [0-9]*) NEW_VERSION="$arg" ;;
    *) die "Unknown argument: $arg" ;;
  esac
done

# ── Read current version ──────────────────────────────────────────────────────
CURRENT_VERSION=$(grep '^VERSION = ' sys_monitor.py | sed 's/VERSION = "\(.*\)"/\1/')
[[ -n "$CURRENT_VERSION" ]] || die "Could not read VERSION from sys_monitor.py"

TARGET_VERSION="${NEW_VERSION:-$CURRENT_VERSION}"

echo ""
echo "  Sys|Monitor  Release"
echo "  CoreConduit Consulting Services"
echo ""
info "Current version : $CURRENT_VERSION"
info "Target version  : $TARGET_VERSION"
$DRY && warn "DRY RUN — no files will be changed"
echo ""

# ── Preflight ────────────────────────────────────────────────────────────────
[[ -f sys_monitor.py ]]           || die "Run from repo root"
command -v git    >/dev/null 2>&1 || die "git not found"
command -v tar    >/dev/null 2>&1 || die "tar not found"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"

# Require clean working tree (skip in dry-run)
if ! $DRY; then
  if ! git diff --quiet || ! git diff --cached --quiet; then
    die "Working tree is dirty. Commit or stash changes before releasing."
  fi
fi

# ── Bump version if requested ─────────────────────────────────────────────────
bump_version() {
  local v="$1"
  info "Bumping VERSION to $v in sys_monitor.py and hub/sys_monitor_hub.py"

  if ! $DRY; then
    sed -i "s/^VERSION = \".*\"/VERSION = \"$v\"/" sys_monitor.py
    sed -i "s/^VERSION = \".*\"/VERSION = \"$v\"/" hub/sys_monitor_hub.py
    # Also update banner line in sys_monitor.py if present
    sed -i "s/v[0-9]\+\.[0-9]\+\.[0-9]\+ /v${v} /g" sys_monitor.py
    ok "Version bumped to $v"
  else
    ok "[dry] Would bump VERSION → $v in sys_monitor.py, hub/sys_monitor_hub.py"
  fi
}

if [[ -n "$NEW_VERSION" && "$NEW_VERSION" != "$CURRENT_VERSION" ]]; then
  # Validate semver format
  [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || die "Version must be semver: X.Y.Z (got '$NEW_VERSION')"
  bump_version "$NEW_VERSION"
fi

# ── Build release tarball ─────────────────────────────────────────────────────
DIST_DIR="dist"
ARCHIVE_NAME="sys-monitor-${TARGET_VERSION}"
ARCHIVE_PATH="${DIST_DIR}/${ARCHIVE_NAME}.tar.gz"
CHECKSUM_PATH="${DIST_DIR}/${ARCHIVE_NAME}.sha256"

# Files to include in release (relative to repo root)
RELEASE_FILES=(
  sys_monitor.py
  hiddenscope_scanner.py
  requirements.txt
  services.json
  templates/index.html
  static
  sys-monitor.service
  install.sh
  update.sh
  release.sh
  .env.example
  README.md
  docs
  hub/sys_monitor_hub.py
  hub/requirements.txt
  hub/templates/hub.html
  hub/sys-monitor-hub.service
  hub/HUB_README.md
)

if ! $DRY; then
  mkdir -p "$DIST_DIR"

  if $CLEAN; then
    info "Cleaning dist/ directory..."
    rm -f "${DIST_DIR}"/*.tar.gz "${DIST_DIR}"/*.sha256
    ok "dist/ cleaned"
  fi

  # Build tarball with directory prefix inside archive
  tar -czf "$ARCHIVE_PATH" \
    --transform "s|^|${ARCHIVE_NAME}/|" \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.env' \
    "${RELEASE_FILES[@]}"

  # Checksum — reference the archive by basename only, since update.sh verifies
  # it from a bare temp dir containing just the downloaded tarball
  (cd "$DIST_DIR" && sha256sum "${ARCHIVE_NAME}.tar.gz") > "$CHECKSUM_PATH"
  ok "Archive  : $ARCHIVE_PATH ($(du -sh "$ARCHIVE_PATH" | cut -f1))"
  ok "Checksum : $CHECKSUM_PATH"
else
  ok "[dry] Would create: $ARCHIVE_PATH"
  ok "[dry] Files included:"
  for f in "${RELEASE_FILES[@]}"; do
    echo "         $f"
  done
fi

# ── Git tag ───────────────────────────────────────────────────────────────────
TAG="v${TARGET_VERSION}"

tag_and_commit() {
  if git rev-parse "$TAG" >/dev/null 2>&1; then
    warn "Tag $TAG already exists — skipping tag"
    return
  fi

  if [[ -n "$NEW_VERSION" && "$NEW_VERSION" != "$CURRENT_VERSION" ]]; then
    info "Committing version bump..."
    git add sys_monitor.py hub/sys_monitor_hub.py
    git commit -m "chore: bump version to ${TARGET_VERSION}"
  fi

  git tag -a "$TAG" -m "SysMonitor v${TARGET_VERSION}"
  ok "Tagged $TAG"
  info "Push with: git push origin main && git push origin $TAG"
}

if ! $DRY; then
  tag_and_commit
else
  ok "[dry] Would tag: $TAG"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
ok "Release v${TARGET_VERSION} ready."
if ! $DRY; then
  echo ""
  echo "  Next steps:"
  echo "    1. git push origin main && git push origin $TAG"
  echo "    2. Upload dist/${ARCHIVE_NAME}.tar.gz to GitHub release"
  echo "    3. Attach dist/${ARCHIVE_NAME}.sha256 as checksum"
  echo ""
  echo "  On target system:"
  echo "    curl -O <release-url>/${ARCHIVE_NAME}.tar.gz"
  echo "    tar -xzf ${ARCHIVE_NAME}.tar.gz"
  echo "    cd ${ARCHIVE_NAME} && sudo ./install.sh"
fi
echo ""
