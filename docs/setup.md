# SysMonitor — Setup & Usage

SysMonitor runs unmodified on either **Ubuntu/Debian PCs & servers** or **Raspberry Pi boards** — hardware is auto-detected at startup (see `docs/architecture.md`), so there's nothing platform-specific to configure below.

## Prerequisites

- Ubuntu 24.04 / Debian-based Linux, or Raspberry Pi OS (64-bit) on any Pi model
- Python 3.11+
- `pip3` (installed automatically if missing)
- `systemd` (required for service management)
- (Raspberry Pi only, optional) `vcgencmd` for GPU memory / undervoltage reporting — present by default on Raspberry Pi OS

---

## Quick Install

The `install.sh` script handles everything — dependency installation, service setup, and firewall configuration:

```bash
git clone https://github.com/bitsandbots/sys-monitor.git
cd sys-monitor
sudo ./install.sh           # Node agent only
sudo ./install.sh --hub     # Node agent + Fleet Hub
```

### What install.sh does

| Step | Detail |
|------|--------|
| Preflight | Verifies root, Python 3.11+, pip3, systemd |
| Dependencies | `pip3 install --break-system-packages --ignore-installed -r requirements.txt` |
| File copy | Copies `sys_monitor.py`, templates, static assets, and `hiddenscope_scanner.py` (if present) to `/opt/sys-monitor` |
| Firewall | Opens port 8585 (node) / 8686 (hub) via ufw or firewalld |
| Service | Installs and enables the systemd unit, waits for health check |

The `--ignore-installed` flag handles conflicts when system apt packages (e.g. `python3-blinker`) are older than pip requirements. It overwrites rather than attempting to uninstall apt-managed packages, avoiding RECORD-file errors.

### Other install.sh flags

| Flag | Purpose |
|------|---------|
| `--hub` | Install node agent + Fleet Hub |
| `--hub-only` | Install Fleet Hub only |
| `--uninstall` | Stop services, remove files, close firewall ports |
| `--help` | Show usage |

---

## Node Agent

### Run (development)

```bash
python3 sys_monitor.py
# Dashboard → http://<host-ip>:8585
```

### Run as a systemd service (production)

```bash
sudo ./install.sh
```

Or manually:

```bash
sudo cp sys-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sys-monitor
sudo systemctl status sys-monitor
```

Edit `/etc/systemd/system/sys-monitor.service` to set environment variables before enabling.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SYSMONITOR_HOST` | `0.0.0.0` | Bind address |
| `SYSMONITOR_PORT` | `8585` | Listen port |
| `SYSMONITOR_DEBUG` | `false` | Flask debug mode |
| `SYSMONITOR_TOKEN` | _(empty)_ | Bearer token for auth. Empty = auth disabled |
| `SYSMONITOR_SERVICES` | `ssh,nginx,docker,...` | Comma-separated list of systemd services to monitor |
| `SYSMONITOR_REFRESH` | `2` | Dashboard auto-refresh interval in seconds |
| `SYSMONITOR_SERVICES_FILE` | `./services.json` | Path to persist the service list |
| `HIDDENSCOPE_MIN_SEVERITY` | `high` | Minimum finding severity counted as "actionable" (drives the Security Alert card) |
| `HIDDENSCOPE_SCAN_PATH` | _(empty)_ | Server-side-only directory for the on-demand static scan; leave unset to disable `/api/security/scan` |
| `HIDDENSCOPE_ALLOWLIST_FILE` | `./hiddenscope_allowlist.json` | Path to persist the security allowlist |

### Authentication

Set `SYSMONITOR_TOKEN` to any secret string. All API requests must then include:

```
Authorization: Bearer <token>
```

The dashboard prompts for the token automatically if auth is enabled.

### Adding / Removing Monitored Services

Via the dashboard UI (Services tab → edit icon), or via API:

```bash
# Add
curl -X POST http://node:8585/api/services/config \
  -H "Content-Type: application/json" \
  -d '{"name": "myapp"}'

# Remove
curl -X DELETE http://node:8585/api/services/config/myapp
```

Changes persist to `services.json` and survive restarts.

### LLM Model Detection

No setup required. SysMonitor automatically probes well-known local-LLM ports (Ollama, llama.cpp, vLLM, LM Studio, text-generation-webui, KoboldCpp, LocalAI, TGI, LiteLLM, GPT4All, Jan.ai) whenever they're listening, and reports which model(s) each one is currently serving on the Overview and Services tabs. See `docs/api.md` for the full `/api/llm` response shape.

If you run an LLM server on a non-standard port, add it to the monitored services list with a name that hints at what it is (containing `ollama`, `llama`, `vllm`, `gpt`, `llm`, etc.) and SysMonitor will pick up its port automatically.

### Security Monitoring (hiddenscope)

No extra install steps — `install.sh` copies `hiddenscope_scanner.py` alongside `sys_monitor.py` as part of the same install, and live connection/listener monitoring works out of the box as soon as both files are present; nothing needs to be configured. Tune `HIDDENSCOPE_MIN_SEVERITY` to control how noisy the Security Alert card is. To enable the on-demand static secret/reverse-shell scan, set `HIDDENSCOPE_SCAN_PATH` to a directory on the server (see `docs/api.md` for `POST /api/security/scan`); this is intentionally not settable from the dashboard or API. If `hiddenscope_scanner.py` isn't present, the Security tab reports monitoring as unavailable rather than failing.

---

## Fleet Hub

The Hub is optional. Run it on any machine that can reach your nodes over the network.

### Install

```bash
sudo ./install.sh --hub-only
```

Or manually:

```bash
cd hub/
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### Run (development)

```bash
python3 hub/sys_monitor_hub.py
# Dashboard → http://<hub-ip>:8686
```

### Run as a systemd service

```bash
sudo cp hub/sys-monitor-hub.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sys-monitor-hub
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SYSHUB_HOST` | `0.0.0.0` | Bind address |
| `SYSHUB_PORT` | `8686` | Listen port |
| `SYSHUB_DEBUG` | `false` | Flask debug mode |
| `SYSHUB_TOKEN` | _(empty)_ | Bearer token for hub auth |
| `SYSHUB_POLL_INTERVAL` | `5` | Seconds between node polls |
| `SYSHUB_TIMEOUT` | `4` | Per-request timeout to nodes (seconds) |
| `SYSHUB_DISCOVERY_PORT` | `8585` | Port scanned during subnet discovery |
| `SYSHUB_NODES_FILE` | `./hub_nodes.json` | Path to persist node registry |

### Adding Nodes

Via the Hub dashboard UI, or via API:

```bash
# Add a node manually
curl -X POST http://hub:8686/api/nodes \
  -H "Content-Type: application/json" \
  -d '{"host": "192.168.1.42", "port": 8585, "label": "Living-Room"}'

# Trigger subnet auto-discovery
curl -X POST http://hub:8686/api/discover
```

### Node Authentication

If a node has `SYSMONITOR_TOKEN` set, provide it when registering:

```bash
curl -X POST http://hub:8686/api/nodes \
  -H "Content-Type: application/json" \
  -d '{"host": "192.168.1.42", "port": 8585, "label": "Secure-Node", "token": "secret"}'
```

The hub stores and uses the token for all requests to that node.

---

## Sudo Permissions

The node agent runs as `root` under systemd (required for `systemctl` control and `reboot`/`shutdown`). For development without root, service control and power actions will fail gracefully — metric reads still work.

To run as a non-root user with limited sudo, add to `/etc/sudoers.d/sys-monitor`:

```
sys-monitor ALL=(ALL) NOPASSWD: /bin/systemctl, /sbin/reboot, /sbin/shutdown
```

Then change `User=root` to `User=sys-monitor` in the service file and create the user.

## Firewall

`install.sh` automatically opens the required ports:

| Port | Protocol | Component |
|------|----------|-----------|
| 8585 | TCP | Node Agent |
| 8686 | TCP | Fleet Hub |

Both ufw and firewalld are supported. If neither is active, the firewall step is a no-op. On uninstall (`--uninstall`), the rules are removed.
