# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

SysMonitor — a self-hosted Linux system monitor and service-control dashboard for CoreConduit's Pi/Ubuntu fleet. Single-file Flask backend per component, zero JS build step, stdlib-first. Runs unmodified on Ubuntu/Debian and Raspberry Pi OS — `detect_system()` branches hardware detection at startup, not the rest of the codebase.

Two independently-runnable Flask apps:
- **Node agent** (`sys_monitor.py`, port 8585) — runs on every monitored host, reads `/proc`/`/sys`, shells out to `systemctl`/`ss`/`vcgencmd`, serves the dashboard.
- **Fleet Hub** (`hub/sys_monitor_hub.py`, port 8686, optional) — aggregates multiple node agents, polls them in a background thread, proxies dashboard requests to the right node.

There is no test suite in this repo — verify changes by running the app and hitting the relevant endpoint/UI tab (see Running below).

## Commands

```bash
# Run the node agent (dev)
python3 sys_monitor.py                     # → http://localhost:8585

# Run the Fleet Hub (dev, separate process)
python3 hub/sys_monitor_hub.py             # → http://localhost:8686

# Install dependency only
pip install flask --break-system-packages

# Full install as systemd service (node, hub, or both)
sudo ./install.sh            # node agent only
sudo ./install.sh --hub      # node agent + hub
sudo ./install.sh --hub-only # hub only
sudo ./install.sh --uninstall

# Update an existing install in place
sudo ./update.sh

# Package a release tarball (run on dev machine, not on a Pi)
./release.sh                 # package current VERSION from sys_monitor.py
./release.sh 2.5.0           # bump version, tag, package
./release.sh 2.5.0 --clean   # clean dist/ first

# Standalone hiddenscope CLI (vendored scanner also works unmodified on its own)
python3 hiddenscope_scanner.py live|listeners|scan|watch|report
```

No lint/format/test tooling is configured in this repo — match existing style by hand (stdlib-heavy, type-hinted function signatures, Google-style docstrings per the global Python rules).

## Architecture

### One codebase, two platforms
`detect_system()` in `sys_monitor.py` runs once at startup, caches into `_BOOT_INFO`. It checks `/proc/device-tree/model` / `/proc/cpuinfo` for Raspberry Pi signatures; if found, decodes SoC from the revision code and reads GPU split via `vcgencmd`. Otherwise falls back to DMI (`/sys/devices/virtual/dmi/id/*`) for generic PC identification. Every downstream feature (temperature/power status, memory) reads from this same boot info — Pi-only fields are simply `None` on non-Pi hardware. **Never add platform `if` branches elsewhere in the code** — extend `detect_system()` and let fields degrade gracefully instead.

### Data collection pattern
All metrics are plain functions that read `/proc`/`/sys` directly or shell out to a single subprocess (`systemctl`, `ss -tuln`, `df -BM`, `ps aux`, `vcgencmd`) — no `psutil`. Differential metrics (CPU usage, network throughput) store the previous sample in a module-level dict guarded by `threading.Lock` and compute the delta on each poll (`_cpu_prev`, network's previous byte counts + timestamp). When adding a new differential metric, follow this same store-previous-compute-delta shape rather than introducing a new pattern.

### Route → function mapping
Each `/api/*` route in `sys_monitor.py` is a thin wrapper that calls one or more of the `get_*()` functions and returns JSON — keep business logic in the function, not the route handler. `/api/services-with-ports` is the merge point for three data sources: `get_services()` (systemd status), `get_open_ports()` (`ss` output), and the `_SERVICE_PORTS` hint table.

### Security integration (hiddenscope)
`hiddenscope_scanner.py` is vendored verbatim (MIT, same author) rather than pip-installed — it's stdlib-only and still works standalone as its original CLI. `sys_monitor.py` imports it and sets `HIDDENSCOPE_AVAILABLE`; every security code path checks this flag and reports "unavailable" instead of raising if the module is missing. `get_security_status()` scores live connections/listeners against `SUSPICIOUS_PORTS` and an allowlist persisted at `HIDDENSCOPE_ALLOWLIST_FILE`. The on-demand static scan (`POST /api/security/scan`) is **hard-restricted to a server-side-only path** (`HIDDENSCOPE_SCAN_PATH` env var) — this is intentional, not an oversight: the client can never supply a scan path, closing an arbitrary-filesystem-scan attack surface. Do not add a way to pass a path through the API or UI.

### LLM detection
`LLM_PORTS` maps well-known local-LLM server ports (Ollama, llama.cpp, vLLM, LM Studio, etc.) to probe logic in `_probe_llm_port()`, which uses stdlib `urllib` (not `requests`) to hit Ollama's native `/api/tags` or the OpenAI-compatible `/v1/models`. A port only counts as "serving" once its API returns a parseable model list — a merely-open port is not enough. This response-driven check avoids false positives; preserve it if you touch this path.

### Fleet Hub
`hub/sys_monitor_hub.py` maintains a node registry (`hub_nodes.json`) and a background `threading.Thread` poller (`_poller_loop` → `_poll_node()` per node via `ThreadPoolExecutor(max_workers=min(node_count, 8))`) that refreshes an in-memory cache every `SYSHUB_POLL_INTERVAL` seconds. `/api/fleet` always serves the cached snapshot instantly rather than blocking on live node polls — the dashboard stays responsive even when a node is slow/unreachable. Per-node proxy routes (`/api/nodes/<nid>/...`) forward to the node's own API via `_fetch_node()`. Uses `requests` (hub only — the node agent does not depend on it).

### Config and persistence
Everything is env-var configured with sane defaults — no required config files. Service whitelist, security allowlist, and hub node registry each persist to their own small JSON file (`services.json`, `hiddenscope_allowlist.json`, `hub_nodes.json`) so runtime edits via the dashboard UI survive restarts independent of env vars. `control_service()` rejects any service name not already in `CONFIG["services"]` before calling `systemctl` — preserve this whitelist check if you touch service control.

### Frontend
`templates/index.html` (node) and `hub/templates/hub.html` (hub) are single self-contained files — HTML/CSS/vanilla JS, Bootstrap 5, self-hosted WOFF2 fonts, no build step, no bundler. The root-level `index.html` is a duplicate/mirror of `templates/index.html` (used by `push-wiki.sh`/docs tooling) — when editing dashboard markup or JS, **edit `templates/index.html`** (the one Flask actually serves via `render_template`) and keep the root copy in sync only if asked.

### Auth
`require_auth` decorator gates mutating endpoints when `SYSMONITOR_TOKEN` (node) / `SYSHUB_TOKEN` (hub) is set — Bearer token, opt-in, designed for API-only access (the web UI itself doesn't send auth headers; put a reverse proxy with basic auth in front for UI-level auth).

## Reference docs

`docs/architecture.md` and `docs/tech-stack.md` have more detail than this file on data flow and system interfaces if you need it. `docs/api.md` documents the full `/api/*` request/response shapes. The `wiki/` directory mirrors the GitHub wiki content; `push-wiki.sh` pushes it — don't hand-edit the GitHub wiki directly, edit `wiki/*.md` and push.
