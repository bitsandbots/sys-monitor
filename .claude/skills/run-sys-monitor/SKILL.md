---
name: run-sys-monitor
description: Build, run, and drive SysMonitor's node agent and Fleet Hub. Use when asked to start sys-monitor, run the dashboard, take a screenshot of it, verify a UI change, or interact with the running node/hub apps.
---

Two standalone Flask apps, no build step, no JS framework. Drive them with the Playwright REPL driver at `.claude/skills/run-sys-monitor/driver.py` — this environment has no `chromium-cli`, so the driver scripts the system Chromium binary directly (`/usr/bin/chromium`) via Python Playwright.

All paths below are relative to the repo root (`sys-monitor/`).

**A production instance may already be running on this host** — check with `systemctl is-active sys-monitor sys-monitor-hub` before picking ports. Never launch a dev instance on 8585/8686 if the systemd services own them; use `SYSMONITOR_PORT` / `SYSHUB_PORT` to pick free ports instead (both apps read these env vars, default 8585/8686).

## Prerequisites

Already present in this container — nothing to install:

```bash
python3 -c "import flask, playwright" && echo ok   # flask 3.1.x, playwright 1.58.x
/usr/bin/chromium --version                          # system Chromium, used via executable_path
```

If starting from a bare container, this is what's actually needed:

```bash
sudo apt-get update && sudo apt-get install -y chromium
pip install flask requests playwright --break-system-packages
```

(`playwright install chromium` / browser download is **not** needed — the driver points `executable_path` at the system `/usr/bin/chromium` instead, matching this project's offline-first, no-extra-downloads posture.)

## Setup

The node agent's `static/fonts/` (self-hosted WOFF2 fonts) only get copied into `hub/static/` by `install.sh` at install time. Running `hub/sys_monitor_hub.py` directly from a checkout — as this skill does — skips that step, so the Hub dashboard 404s on 3 font requests unless you symlink it first:

```bash
ln -sfn ../static hub/static
```

One-time per checkout. Harmless if it already exists (`-f`). This symlink is dev-only scaffolding — don't commit it (it isn't in the repo; `install.sh` is what populates the real thing on a target host).

No env vars are required — both apps run with sane defaults (no auth, no webhook) unless you're specifically testing those paths (`SYSMONITOR_TOKEN`, `SYSHUB_TOKEN`, `SYSHUB_ALERT_WEBHOOK_URL`).

## Build

No build step — single-file Flask backends, self-contained HTML templates.

## Run (agent path)

Launch whichever app your change touches, on a port that doesn't collide with a live systemd instance, then drive it:

```bash
# Node agent
SYSMONITOR_PORT=8599 python3 sys_monitor.py > /tmp/node_dev.log 2>&1 &
timeout 15 bash -c 'until curl -sf http://localhost:8599/api/ping >/dev/null; do sleep 0.5; done'

# Hub (isolated node registry so it can't touch a real one)
cd hub
SYSHUB_PORT=8699 SYSHUB_NODES_FILE=/tmp/dev_hub_nodes.json python3 sys_monitor_hub.py > /tmp/hub_dev.log 2>&1 &
timeout 15 bash -c 'until curl -sf http://localhost:8699/api/ping >/dev/null; do sleep 0.5; done'
cd ..
```

Then pipe commands to the driver:

```bash
python3 .claude/skills/run-sys-monitor/driver.py <<'EOF'
nav http://localhost:8599
wait-for sel=#panel-overview
dom-order #panel-overview
screenshot overview
click .tab-btn[data-tab="services"]
wait-for sel=#panel-services
screenshot services
console-errors
quit
EOF
```

Screenshots land in `.claude/skills/run-sys-monitor/screenshots/<name>.png`. **Look at them** — a blank or error-page screenshot means the app didn't actually render, even if the driver reported `OK`.

Stop cleanly when done — don't `pkill -f python3` (too broad, can hit the agent's own session):

```bash
lsof -ti:8599 -sTCP:LISTEN | xargs -r kill
lsof -ti:8699 -sTCP:LISTEN | xargs -r kill
```

| driver command | what it does |
|---|---|
| `nav <url>` | navigate, waits for networkidle |
| `wait-for text=<substring>` | poll up to 10s for visible text |
| `wait-for sel=<css>` | poll up to 10s for a visible selector |
| `screenshot [name]` | full-page screenshot |
| `screenshot-el <css> [name]` | crop to one element — use for a single card/component |
| `click <css>` | click a selector |
| `fill <css> <text...>` | fill an input, through Playwright's input pipeline |
| `press <key>` | e.g. `Enter`, `Escape` |
| `eval <js>` | `page.evaluate`, prints the JSON result |
| `dom-order <parent-css>` | prints id/class of each direct child in DOM order — use this to verify card/element reordering instead of eyeballing a screenshot |
| `console-errors` | prints every `console.error` seen so far — check this before declaring success |
| `quit` | close the browser, exit |

## Run (human path)

```bash
python3 sys_monitor.py            # → http://localhost:8585
python3 hub/sys_monitor_hub.py    # → http://localhost:8686 (separate process)
```
Ctrl-C to stop. Useless headless — only relevant if a human has a browser pointed at this host.

## Test

No test suite in this repo (per `CLAUDE.md`) — this driver *is* the verification path.

---

## Gotchas

- **Font 404s on the Hub only, not the node agent.** The node agent's own `static/` lives at the repo root next to `sys_monitor.py`, so it resolves correctly straight from a checkout. The Hub's Flask `static_folder` resolves relative to `hub/sys_monitor_hub.py`'s own location (`hub/static/`), which doesn't exist in the repo — only `install.sh` populates it (by copying the root `static/` into both `$INSTALL_DIR/static/` and `$INSTALL_DIR/hub/static/`). Symlink it per Setup above, or the Hub page loads fine functionally but browser console shows 3 `404`s and falls back to system fonts.
- **Never launch a dev instance on 8585/8686 without checking first.** Both are the default ports and may already be owned by a live systemd `sys-monitor`/`sys-monitor-hub` service on a fleet host (e.g. `blueberry`). Binding to those ports isn't possible if the systemd service already has them (you'll get a clean "Address already in use" and nothing will be harmed) — but always check `systemctl is-active` first and use `SYSMONITOR_PORT`/`SYSHUB_PORT` rather than relying on the bind failure as your signal.
- **Don't drive `/api/power/reboot`, `/api/power/shutdown`, or service stop/restart/kill actions against a real node without monkeypatching first.** A prior session's verification script hit these unmocked against the real `blueberry` host and rebooted it twice. If a change touches these routes, monkeypatch the handler before scripting a `click` against the confirm-dialog button, the same way you'd isolate the Hub's node registry with `SYSHUB_NODES_FILE` above.

## Troubleshooting

- **`console-errors` shows 3 `Failed to load resource: 404` entries after `nav`-ing to the Hub, nothing else broken**: missing `hub/static` symlink — see Setup.
- **`curl` polling loop never succeeds / times out**: check the app's own log file (`/tmp/node_dev.log` or `/tmp/hub_dev.log`) — a stack trace there (e.g. `OSError: [Errno 98] Address already in use`) means the port you picked collides with something already running; pick a different `SYSMONITOR_PORT`/`SYSHUB_PORT`.
