#!/usr/bin/env bash
# push-wiki.sh — Push wiki source pages to the GitHub wiki repo.
#
# Run this AFTER creating the first wiki page via the GitHub UI:
#   https://github.com/bitsandbots/sys-monitor/wiki/_new
#
# Usage: ./push-wiki.sh
#
# CoreConduit Consulting Services — MIT License

set -euo pipefail

REPO="https://github.com/bitsandbots/sys-monitor.wiki.git"
WIKI_DIR="/tmp/sys-monitor-wiki-push"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'; GRN='\033[0;32m'; BLU='\033[0;34m'; NC='\033[0m'
info() { echo -e "${BLU}[INFO]${NC}  $*"; }
ok()   { echo -e "${GRN}[ OK ]${NC}  $*"; }
die()  { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }

# Embed wiki content inline so the script is self-contained
PAGES_DIR="$SCRIPT_DIR/wiki"

[[ -d "$PAGES_DIR" ]] || die "wiki/ directory not found next to push-wiki.sh"

info "Cloning wiki repo..."
rm -rf "$WIKI_DIR"
git clone "$REPO" "$WIKI_DIR" || die "Could not clone wiki. Did you create the first page at https://github.com/bitsandbots/sys-monitor/wiki/_new ?"

info "Copying pages..."
cp "$PAGES_DIR"/*.md "$WIKI_DIR/"

info "Committing..."
cd "$WIKI_DIR"
git config user.email "bitsandbots@users.noreply.github.com"
git config user.name "bitsandbots"
git add .
git diff --cached --stat
git commit -m "docs: publish wiki pages v$(grep '^VERSION' "$SCRIPT_DIR/sys_monitor.py" | sed 's/VERSION = "\(.*\)"/\1/')"

info "Pushing..."
git push origin HEAD

ok "Wiki published: https://github.com/bitsandbots/sys-monitor/wiki"
