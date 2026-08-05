# SysMonitor — Tech Stack

## Runtime

| Layer | Technology | Version | Notes |
|-------|-----------|---------|-------|
| OS | Ubuntu 24.04 (also Debian-compatible), or Raspberry Pi OS | 64-bit | Same binary/codebase auto-detects the platform |
| Python | CPython | 3.11+ | 3.13 used in dev |
| Web framework | Flask | ≥ 3.0.0 | Node agent and hub both use Flask |
| HTTP client | Requests | ≥ 2.31 | Hub only — proxies to node APIs |
| HTTP client (LLM probing) | `urllib` (stdlib) | — | Node agent only — probes candidate LLM ports without adding a dependency |
| Security scanner | hiddenscope (`hiddenscope_scanner.py`) | vendored, unversioned | Vendored MIT-licensed, stdlib-only module (CoreConduit Consulting, same author) — copied into the project verbatim, **not** a pip dependency |

## Frontend

| Technology | Role |
|-----------|------|
| Vanilla JS (ES2020) | Dashboard polling, DOM updates, tab management |
| Bootstrap 5 | Layout, modals, utility classes |
| Self-hosted WOFF2 (Exo 2, Plus Jakarta Sans, IBM Plex Mono) | Typography — offline capable, no CDN dependency |
| CSS custom properties | Brand theming (navy/silver/blue/orange) |

No build step — the dashboard is a single self-contained `index.html`.

## System Interfaces

| Interface | Used By | Data |
|-----------|---------|------|
| `/proc/stat` | `get_cpu_usage()` | Per-core CPU jiffies (delta method) |
| `/proc/meminfo` | `get_memory()` | Total, free, available, cached RAM |
| `/proc/uptime` | `get_uptime()` | Seconds since boot |
| `/sys/class/net/<iface>/statistics/{rx,tx}_bytes` | `get_network()` | Interface RX/TX byte counters |
| `ps aux` (subprocess) | `get_top_processes()` | Top processes by CPU: user, PID, cpu%, mem%, command |
| `/sys/class/thermal/thermal_zone0/temp` | `get_cpu_temperature()` | CPU temp in millidegrees |
| `df -BM` (subprocess) | `get_storage()` | Mount points, sizes in MB, filesystem type, used/free space |
| `systemctl` (subprocess) | `get_services()`, `control_service()` | Service status, start/stop/restart/enable/disable |
| `sudo reboot / shutdown` (subprocess) | `system_power()` | Power actions |
| `ss -tuln` (subprocess) | `get_open_ports()` | Listening TCP/UDP ports, well-known + registered range (0-49151) |
| `vcgencmd get_throttled` / `get_mem gpu` (subprocess, Pi only) | `get_power_status()`, `get_temperature_status()`, `detect_system()` | Undervoltage/throttle flags, GPU memory split — no-op on non-Pi hardware |
| `http://127.0.0.1:<port>/api/tags`, `/v1/models` (via `urllib`) | `get_llm_services()` | Detects and identifies models served by local LLM APIs (Ollama / OpenAI-compatible) |
| `/proc/net/tcp*`, `/proc/net/udp*` (via hiddenscope's `_connections()`/`_listeners()`) | `get_security_status()` | Active connections and listening ports, scored against `SUSPICIOUS_PORTS` and the allowlist |

## Process Management (Node)

| Tool | Purpose |
|------|---------|
| `os.kill(pid, sig)` | Send signal to process (default SIGTERM=15) |
| `threading.Lock` | Guards CPU stat differential and event log |

## Concurrency (Hub)

| Tool | Purpose |
|------|---------|
| `threading.Thread` | Background poller loop |
| `concurrent.futures.ThreadPoolExecutor` | Parallel node polling (`max_workers=min(node_count, 8)`) |
| `threading.Lock` | Guards node registry dict |

## Persistence

| File | Location | Contents |
|------|----------|---------|
| `services.json` | `SYSMONITOR_SERVICES_FILE` (default: project root) | Ordered list of monitored service names |
| `hub_nodes.json` | `SYSHUB_NODES_FILE` (default: `hub/`) | Node registry (host, port, label, token) |
| `hiddenscope_allowlist.json` | `HIDDENSCOPE_ALLOWLIST_FILE` (default: project root) | Allowlisted procs/ports/networks/url_domains for security monitoring |

## Process Supervisor

| Tool | Config File |
|------|------------|
| systemd | `sys-monitor.service` / `hub/sys-monitor-hub.service` |
