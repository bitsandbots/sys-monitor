# Sys**|Monitor** v2.4.0

A lightweight, self-hosted Linux system monitor and service control console written in Python. Single-file Flask backend, zero JavaScript dependencies, no build step.

**Runs unmodified on both Ubuntu/Debian PCs & servers and Raspberry Pi boards.** Hardware is auto-detected at boot — Pi-specific metrics (SoC, GPU memory split, undervoltage/throttle status) appear automatically when SysMonitor is running on a Pi, and are simply omitted on generic desktop/server Linux. One codebase, one dashboard, any Debian-family host.

Built for [CoreConduit Consulting Services](https://coreconduit.com) infrastructure.

## Features

### Monitoring
- **CPU** — differential usage sampling (accurate real-time %), per-core stats, load averages, current frequency
- **Temperature** — live reading with 60-second sparkline history
- **Memory** — RAM, cached, buffers, swap, plus GPU memory split on Raspberry Pi (via `vcgencmd`)
- **Storage** — all mounted filesystems with capacity bars
- **Network** — interface enumeration, throughput rates (bytes/sec delta tracking), RX/TX sparklines
- **Processes** — top processes by CPU with kill capability
- **Ports** — open ports (well-known + registered range) merged with services view

### AI / LLM Model Detection (new in v2.3.0)
- Scans listening ports for common local-LLM servers — **Ollama**, **llama.cpp** / **llamafile**, **vLLM**, **LM Studio**, **text-generation-webui**, **KoboldCpp**, **LocalAI**, **TGI**, **LiteLLM**, **GPT4All**, **Jan.ai**, and gradio-based chat UIs
- For each one found, queries its API (Ollama's native `/api/tags`, or the OpenAI-compatible `/v1/models` used by most of the others) to check whether it's **actually serving a model** — not just that the port is open
- Any host currently serving a model shows it front-and-center on the Overview tab, with the model name(s) it has loaded; the Services tab lists every detected LLM port with full detail
- Also picks up custom/self-hosted LLM servers on non-standard ports, as long as the monitored service name looks LLM-related (e.g. a systemd unit named `my-ollama`)
- The Fleet Hub aggregates this across every node — see a "🧠 N models serving" badge on any node in the fleet grid

### Security Monitoring (new in v2.4.0)
- Integrates [**hiddenscope**](https://coreconduit.com) — a stdlib-only Linux security scanner — vendored directly into the project (`hiddenscope_scanner.py`, MIT licensed, same author)
- **Live connection monitoring** — scores every active outbound connection and listening port; flags known C2/backdoor ports (Telnet, Metasploit defaults, IRC, Tor control ports, NetBus, Back Orifice, and more) and suspicious process/connection combinations
- Any actionable finding (high severity by default) shows a red **Security Alert** card on the Overview tab; a full **Security** tab breaks down every finding by severity, every flagged listener, and lets you manage an allowlist for known-good ports/processes/networks
- Flagged listeners that match a locally-known service (e.g. LM Studio on port 1234, which is also a "suspicious" port in other contexts) are annotated as such rather than hidden, so you can decide whether to allowlist them
- **On-demand static scan** — optionally scans a server-configured directory for hardcoded secrets and reverse-shell patterns (`POST /api/security/scan`); the scan path is set via `HIDDENSCOPE_SCAN_PATH` on the server only and can never be supplied by the client, to avoid an arbitrary-filesystem-scan attack surface
- The Fleet Hub aggregates security alerts across every node — a "🛡 N security alerts" badge appears on flagged nodes, plus a fleet-wide "Security Alerts" tile on the Hub dashboard
- Degrades gracefully: if `hiddenscope_scanner.py` isn't installed, the Security tab reports "unavailable" instead of breaking anything else

### Service Control
- View systemd service status (active/enabled state)
- Start, stop, restart services
- Enable/disable services at boot
- Configurable service whitelist (rejects unlisted services)

### System Control
- Reboot and shutdown with confirmation dialog
- Hardware detection at boot (model, SoC, revision, architecture) — Raspberry Pi model/SoC on Pi hardware, DMI vendor/product identification on generic PCs
- Event log (in-memory ring buffer, viewable in Logs tab)
- Connection-lost detection with automatic reconnect indicator

### Hardware Health
- **Temperature Alerts** — Automatic warnings at 70°C (warning), 80°C (critical), 85°C (throttling)
- **Power Status** — Undervoltage / frequency-capping detection via `vcgencmd` on Raspberry Pi; reports "unavailable" gracefully on generic Linux (no universal equivalent exists there)
- **Service Failure Detection** — Monitors critical services and reports failures
- **System Stability Checks** — Detects OOM events, kernel errors, and service restart loops

### UI
- Boot animation sequence showing detected hardware (adapts wording for Pi vs. generic Linux)
- CoreConduit branding (Exo 2 / Plus Jakarta Sans / IBM Plex Mono)
- 8-tab dashboard: Overview, Services, Processes, Network, Storage, System, Security, Logs
- Responsive layout (desktop and mobile)
- Toast notifications for all actions
- Single HTML file — no build tools required

## Quick Start

### One-command install (recommended)

```bash
git clone https://github.com/bitsandbots/sys-monitor
cd sys-monitor
sudo ./install.sh           # node agent only
sudo ./install.sh --hub     # node agent + hub
sudo ./install.sh --hub-only  # hub only
```

Works as-is on Ubuntu/Debian or Raspberry Pi OS — no flags or environment changes needed for either platform.

Access at `http://<host-ip>:8585` (node) or `http://<host-ip>:8686` (hub).

### Manual install

```bash
# Install dependency
pip install flask --break-system-packages

# Run directly
python3 sys_monitor.py
```

### Install as Service (manual)

```bash
sudo cp sys-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sys-monitor
```

Check status:
```bash
sudo systemctl status sys-monitor
journalctl -u sys-monitor -f
```

### Uninstall

```bash
sudo ./install.sh --uninstall
```

## v2.4.0 — Release Notes

**New: hiddenscope security integration:**
- Vendored [hiddenscope](https://coreconduit.com) (MIT, same author) into the project as `hiddenscope_scanner.py` — a stdlib-only Linux security scanner. It's used unmodified, so it also remains fully usable as a standalone CLI (`python3 hiddenscope_scanner.py live|listeners|scan|watch|report`)
- New `get_security_status()` scores live connections and listeners for known-suspicious ports/processes (Telnet, common C2 ports, Metasploit defaults, IRC, Tor control ports, NetBus, Back Orifice, and more)
- New `GET /api/security` endpoint; new red "Security Alert" card on the Overview tab (shown only when actionable findings exist) and a full **Security** tab with severity-ranked findings, flagged listeners, and an "show informational" toggle for full visibility
- New allowlist management: `GET/POST/DELETE /api/security/allowlist`, backed by a small JSON file (`HIDDENSCOPE_ALLOWLIST_FILE`) so you can silence known-good ports, processes, or networks
- New on-demand static scan: `POST /api/security/scan` runs hiddenscope's secret/reverse-shell detector against a **server-configured** path (`HIDDENSCOPE_SCAN_PATH` env var) — deliberately not a client-supplied path, to prevent an arbitrary-filesystem-scan vector via the API
- The Fleet Hub polls `/api/security` on every node, shows a "🛡 N security alerts" badge on flagged nodes, adds a Security section to the node detail modal, and adds a fleet-wide "Security Alerts" tile to the dashboard header
- Degrades gracefully everywhere: nodes without `hiddenscope_scanner.py` installed simply report security monitoring as unavailable

### v2.3.0 (previous)

**Unified platform support:**
- SysMonitor and RPiMonitor are now a single codebase. Hardware is auto-detected at startup (`detect_system()`) — Raspberry Pi devices get SoC identification, GPU memory reporting, and undervoltage/throttle monitoring via `vcgencmd`; generic Ubuntu/Debian PCs and servers get DMI-based hardware identification (vendor/product name) instead. Every other feature — CPU, memory, storage, network, services, ports, alerts — is identical across both.

**New: LLM model-serving detection:**
- `_SERVICE_PORTS` and the new `LLM_PORTS` table recognize common local-LLM ports: Ollama (11434), llama.cpp/llamafile/LocalAI/TGI/OpenWebUI (8080), LM Studio (1234), text-generation-webui (5000), KoboldCpp (5001), vLLM (8000), GPT4All (4891), LiteLLM (4000), Jan.ai (1337), and gradio chat UIs (7860)
- New `get_llm_services()` probes each candidate port's API (Ollama native, or OpenAI-compatible `/v1/models`) to check whether it's actually serving a model, and which one(s)
- New `GET /api/llm` endpoint; new "LLM Models" card on the dashboard Overview tab and a detailed AI/LLM Services list on the Services tab
- The Fleet Hub polls `/api/llm` on every node and surfaces a "🧠 serving" badge fleet-wide
- **Bugfix:** the open-ports scan previously capped out at port 9999, which silently excluded Ollama's default port 11434 from ever being recognized as a known service. The scan range now covers the full well-known + registered range (0–49151), fixing this and any other high-numbered service port.

**What's unchanged:**
- All existing API endpoints remain compatible
- Installation and upgrade process unchanged
- Configuration options unchanged (still zero required config — everything auto-detects or has a sane default)

### v2.2.0 (previous)

- Hardware Health Alerts — temperature, power, critical service, and stability monitoring with automatic alert cards
- New `GET /api/system-health` endpoint
- `GET /api/status` enhanced with `temperature_status` and `power_status` objects

### v2.1.0

- Services + Ports merged view
- System errors in Logs tab
- Self-hosted fonts for offline capability

## Configuration

All configuration is via environment variables — no config files to manage.

| Variable | Default | Description |
|---|---|---|
| `SYSMONITOR_HOST` | `0.0.0.0` | Bind address |
| `SYSMONITOR_PORT` | `8585` | Port |
| `SYSMONITOR_DEBUG` | `false` | Flask debug mode |
| `SYSMONITOR_TOKEN` | *(empty)* | Optional Bearer token for API auth |
| `SYSMONITOR_SERVICES` | `ssh,nginx,docker,ollama,mosquitto,cron,avahi-daemon` | Comma-separated service whitelist |
| `SYSMONITOR_REFRESH` | `2` | Frontend polling interval (seconds) |
| `SYSMONITOR_SERVICES_FILE` | `./services.json` | Path to persist the service list across restarts |
| `HIDDENSCOPE_MIN_SEVERITY` | `high` | Minimum finding severity that counts as "actionable" (drives the Security Alert card) — one of `info`, `low`, `medium`, `high`, `critical` |
| `HIDDENSCOPE_SCAN_PATH` | *(empty)* | Server-side-only directory for the on-demand static scan; leave unset to disable `/api/security/scan` |
| `HIDDENSCOPE_ALLOWLIST_FILE` | `./hiddenscope_allowlist.json` | Path to persist the security allowlist (ports/procs/networks) |

### Configuring Services

Option 1 — environment variable:
```bash
export SYSMONITOR_SERVICES="ssh,nginx,docker,ollama,mosquitto"
```

Option 2 — the dashboard UI (Services tab → "+ Add Service" / edit / remove icons); persists to `services.json`.

Option 3 — edit `CONFIG["services"]` in `sys_monitor.py` directly.

### LLM Detection

No configuration needed — SysMonitor automatically probes the well-known local-LLM ports (see `LLM_PORTS` in `sys_monitor.py`) whenever they're open, plus the port of any monitored service whose name looks LLM-related (e.g. `ollama`, `my-vllm-server`). To recognize a custom LLM server on a non-standard port, either add its systemd service name to the monitored list with a name containing a recognizable hint (`ollama`, `llama`, `vllm`, `gpt`, `llm`, etc.), or add an entry to `_SERVICE_PORTS` in `sys_monitor.py`.

### Security Monitoring

No configuration needed for live monitoring — SysMonitor automatically scores active connections and listeners on every poll, as long as `hiddenscope_scanner.py` is present alongside `sys_monitor.py` (it's installed automatically by `install.sh`). Tune `HIDDENSCOPE_MIN_SEVERITY` to control how noisy the alert card is. To enable the static secret/reverse-shell scan, set `HIDDENSCOPE_SCAN_PATH` to a directory on the server; this is intentionally not configurable from the dashboard or API to avoid exposing an arbitrary-filesystem-scan endpoint. Manage the allowlist either from the Security tab UI or by editing the file at `HIDDENSCOPE_ALLOWLIST_FILE` directly.

### Authentication

Set `SYSMONITOR_TOKEN` to require Bearer token auth on all API endpoints:

```bash
export SYSMONITOR_TOKEN=my-secret-token
```

The web UI currently does not send auth headers — token auth is designed for API-only access. For UI auth, place SysMonitor behind a reverse proxy with basic auth.

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/ping` | GET | Health check (connection-lost detection) |
| `/api/boot` | GET | Static hardware detection info (Pi model/SoC/GPU when applicable, DMI info otherwise) |
| `/api/status` | GET | CPU, temp, memory, uptime, network rates, temperature/power status |
| `/api/storage` | GET | Mounted filesystems |
| `/api/network` | GET | Interfaces, MAC, IP, throughput rates |
| `/api/processes` | GET | Top processes (`?limit=N`, max 50) |
| `/api/processes/<pid>` | DELETE | Kill process (`?signal=15` or `?signal=9`) |
| `/api/services` | GET | Systemd service statuses |
| `/api/services-with-ports` | GET | Services merged with open ports |
| `/api/services/<name>/<action>` | POST | Control service (start/stop/restart/enable/disable) |
| `/api/services/config` | GET/POST | List / add a monitored service |
| `/api/services/config/<svc>` | DELETE/PUT | Remove / rename a monitored service |
| `/api/ports` | GET | Open TCP/UDP ports (well-known + registered range, 0-49151) |
| `/api/llm` | GET | Detected LLM-serving ports and, for each, whether it's serving a model and which one(s) |
| `/api/security` | GET | hiddenscope security status — findings, actionable count, flagged listeners, summary |
| `/api/security/allowlist` | GET/POST/DELETE | View / add / remove an allowlisted port, process, or network |
| `/api/security/scan` | POST | Run the static secret/reverse-shell scan against `HIDDENSCOPE_SCAN_PATH` (server-configured, not client-supplied) |
| `/api/system-health` | GET | Critical service status + stability checks |
| `/api/system-errors` | GET | Recent journalctl error entries |
| `/api/power/<action>` | POST | Reboot or shutdown |
| `/api/logs` | GET | Event log (`?limit=N`, `?system=true`) |

## Sudoers (optional, for non-root)

If running as a non-root user, add scoped sudoers rules:

```bash
# /etc/sudoers.d/sys-monitor
# Restrict to specific services rather than wildcards
sysmonitor ALL=(ALL) NOPASSWD: /usr/bin/systemctl start ssh nginx docker ollama mosquitto
sysmonitor ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop ssh nginx docker ollama mosquitto
sysmonitor ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart ssh nginx docker ollama mosquitto
sysmonitor ALL=(ALL) NOPASSWD: /usr/bin/systemctl enable ssh nginx docker ollama mosquitto
sysmonitor ALL=(ALL) NOPASSWD: /usr/bin/systemctl disable ssh nginx docker ollama mosquitto
sysmonitor ALL=(ALL) NOPASSWD: /sbin/reboot
sysmonitor ALL=(ALL) NOPASSWD: /sbin/shutdown
```

**Important:** List each service explicitly rather than using wildcards to prevent privilege escalation.

## Architecture

```
sys-monitor/
├── sys_monitor.py          # Flask backend — data collection + API + boot/hardware detection + LLM probing + security status
├── hiddenscope_scanner.py  # Vendored hiddenscope scanner (MIT, CoreConduit Consulting) — stdlib-only security detection
├── templates/
│   └── index.html         # Self-contained frontend (HTML + CSS + JS, no build step)
├── hub/
│   ├── sys_monitor_hub.py # Optional Fleet Hub — aggregates multiple nodes, incl. LLM-serving + security status
│   └── templates/hub.html
├── services.json           # Persisted monitored-service list (seed default)
├── hiddenscope_allowlist.json  # Persisted security allowlist (created on first use)
├── sys-monitor.service     # Systemd unit file
├── requirements.txt        # Flask only
└── README.md
```

### Key Design Decisions

- **Platform auto-detection, one codebase** — `detect_system()` checks `/proc/device-tree/model` and `/proc/cpuinfo` for Raspberry Pi hardware; if found, it decodes the SoC from the revision code and reads GPU memory split via `vcgencmd`. If not, it falls back to DMI (`/sys/devices/virtual/dmi/id/*`) for generic PC/server identification. Every downstream feature (temperature alerts, power status, memory stats) reads from this same boot info and degrades gracefully — Pi-only fields are simply `None`/empty on non-Pi hardware.
- **Differential CPU sampling** — reads `/proc/stat` on each poll and computes usage from the delta since the previous read, giving accurate instantaneous CPU percentage
- **Network rate tracking** — stores previous byte counts per interface with timestamps; computes bytes/sec from the delta rather than showing cumulative totals
- **Service whitelist** — `control_service()` rejects any service name not in `CONFIG["services"]` before invoking systemctl
- **In-memory event log** — ring buffer (200 entries) captures service actions, kills, power events; no disk I/O
- **Single dependency** — Flask only; reads system data from `/proc` and `/sys` directly, no psutil required. LLM API probing uses the Python standard library (`urllib`) rather than adding `requests` as a dependency.
- **Response-driven LLM detection** — a port is confirmed "serving" only after its API actually returns a parseable model list; a merely-open port with no recognized API response is reported as open but not serving, avoiding false positives.
- **Vendored, not pip-installed, security scanner** — hiddenscope is a stdlib-only tool, so it's copied directly into the project as `hiddenscope_scanner.py` (unmodified, MIT license retained) rather than added as a dependency; it also still works standalone as its original CLI.
- **Signal over noise** — live connection scoring alone would flag every external connection (browsers, package managers, etc.) as an "info" finding. Only `high`/`critical` findings count as "actionable" by default and trigger the dashboard alert; all findings, including "info", remain available via the API and a "show informational" toggle on the Security tab.
- **No client-supplied scan paths** — the static secret/reverse-shell scan only ever scans a path set server-side via `HIDDENSCOPE_SCAN_PATH`; the API and UI cannot override it, closing off a path-traversal / arbitrary-filesystem-scan vector.

## Requirements

- Python 3.11+
- Flask 3.0+
- Ubuntu 24.04+ / Debian / Raspberry Pi OS (any Linux with `/proc` and `systemd`)
- `sudo` access for service control and power management
- (Raspberry Pi only, optional) `vcgencmd` for GPU memory and undervoltage/throttle reporting — included by default on Raspberry Pi OS

## License

MIT — CoreConduit Consulting Services
