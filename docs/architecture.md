# SysMonitor — Architecture

## High-Level Design

```
Browser
  │
  │  HTTP / polling (every 2s)
  ▼
┌─────────────────────────────────────────────┐
│  Node Agent  (sys_monitor.py : 8585)         │
│                                             │
│  Flask API ──► /proc, /sys, systemctl       │
│  In-memory ring buffer (200 events)         │
│  services.json  (persisted service list)    │
└─────────────────────────────────────────────┘

       ─ ─ ─ OR, with Hub ─ ─ ─

Browser
  │
  ▼
┌─────────────────────────────────────────────┐
│  Fleet Hub  (sys_monitor_hub.py : 8686)      │
│                                             │
│  Node registry  (hub_nodes.json)            │
│  Background poller  (ThreadPoolExecutor)    │
│    └─► polls each node every 5s             │
│  Proxy routes  ──► Node Agent APIs          │
└──────────────┬──────────────────────────────┘
               │  HTTP (per-node)
      ┌────────┴────────┐
      ▼                 ▼
 Node :8585       Node :8585
 (Node A)         (Node B)
```

## Node Agent — Data Flow

1. Browser loads `index.html` (served by Flask).
2. Dashboard JS polls `/api/status` every `SYSMONITOR_REFRESH` seconds (default 2s).
3. `/api/status` calls the metric functions:
   - `get_cpu_usage()` — reads `/proc/stat` and computes usage from the delta since the previous poll call (stored in `_cpu_prev`).
   - `get_cpu_temperature()` — reads `/sys/class/thermal/thermal_zone0/temp`.
   - `get_memory()` — parses `/proc/meminfo`.
   - `get_uptime()` — reads `/proc/uptime`.
4. On-demand endpoints (`/api/storage`, `/api/network`, `/api/processes`, `/api/services-with-ports`) are fetched only when the dashboard tab is active.
5. `/api/services-with-ports` merges:
   - `get_services()` — systemd service status via `systemctl is-active/is-enabled`
   - `get_open_ports()` — listening ports via `ss -tuln`, well-known + registered range (0-49151)
   - `_SERVICE_PORTS` mapping — common service→port associations
6. `/api/llm` (polled separately, every ~4th cycle since it makes live HTTP calls):
   - `get_llm_services()` intersects `get_open_ports()` with the `LLM_PORTS` hint table (Ollama, llama.cpp, vLLM, LM Studio, etc.), plus any monitored service whose name looks LLM-related
   - each candidate port is probed via `_probe_llm_port()` — tries Ollama's `/api/tags`, then the OpenAI-compatible `/v1/models` — to confirm it's actually serving a model and get its name
7. `/api/logs?system=true` merges:
   - In-memory event log (ring buffer)
   - `get_system_errors()` — journalctl error entries
8. `/api/security` (polled on every cycle, same as `/api/status`):
   - `get_security_status()` calls into the vendored `hiddenscope_scanner.py` module — `_connections()` and `_listeners()` enumerate active connections and listening ports, `score_connection()` scores each against `SUSPICIOUS_PORTS` and the `AllowList`, and the results are summarized into findings, an actionable count (severity `>=` `HIDDENSCOPE_MIN_SEVERITY`), and flagged listeners
   - `POST /api/security/scan` separately calls hiddenscope's `scan_tree()` against a directory read only from the server-side `HIDDENSCOPE_SCAN_PATH` env var — never from the request — for hardcoded-secret/reverse-shell detection
   - `GET/POST/DELETE /api/security/allowlist` reads/writes the `AllowList`, persisted to `HIDDENSCOPE_ALLOWLIST_FILE`
   - If `hiddenscope_scanner.py` can't be imported, `HIDDENSCOPE_AVAILABLE` is `False` and all of the above report "unavailable" instead of raising
9. Mutating actions (service control, process kill, power) require a POST and pass through `require_auth` middleware if `SYSMONITOR_TOKEN` is set.
10. All mutations are written to the in-memory event log (ring buffer, 200 entries, accessible via `/api/logs`).

## Platform Detection (Ubuntu/Debian vs. Raspberry Pi)

`detect_system()` runs once at startup and caches the result in `_BOOT_INFO`:

1. Reads `/proc/device-tree/model` and `/proc/cpuinfo` (`Hardware`, `Revision`, `Serial` lines).
2. If the model string contains "raspberry" or the hardware string contains "bcm", the host is flagged `is_raspberry_pi: true`; the SoC is then decoded from the revision code (`BCM2835`/`2836`/`2837`/`2711`/`2712`) and GPU memory split is read via `vcgencmd get_mem gpu`.
3. Otherwise, `model` falls back to DMI vendor/product strings (`/sys/devices/virtual/dmi/id/sys_vendor`, `product_name`) for generic PC/server identification.
4. `get_temperature_status()` and `get_power_status()` both attempt `vcgencmd get_throttled` unconditionally — on non-Pi hardware the command doesn't exist, `_run()` returns an empty string, and the Pi-only fields (`throttled_status`, undervoltage flags) simply stay `None`/unavailable. No platform branching is needed anywhere else in the codebase.

## Hub — Data Flow

1. At startup, `_load_nodes()` restores the node registry from `hub_nodes.json`.
2. `_start_poller()` launches a background thread that calls `_poll_node()` for every registered node on `SYSHUB_POLL_INTERVAL` (default 5s) using a `ThreadPoolExecutor(max_workers=min(node_count, 8))`.
3. Poll results are cached in the in-memory `_nodes` dict under a `_lock`.
4. Browser requests `/api/fleet` — returns the cached snapshot for all nodes instantly.
5. Proxy routes (e.g. `/api/nodes/<nid>/services`) forward to the corresponding node's API via `_fetch_node()` with per-request timeouts.
6. Network discovery (`/api/discover`) scans the local subnet in parallel using `ThreadPoolExecutor` — it probes `<ip>:SYSHUB_DISCOVERY_PORT/api/ping` for every host.

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| `/proc`/`/sys` reads over `psutil` | No extra dependency; works on stock Ubuntu |
| In-memory ring buffer for logs | Avoids disk I/O; survives service restarts (ephemeral by design) |
| Per-device `services.json` | Survives restarts; decoupled from env vars after first run |
| Hub caches polls, serves stale data | Dashboard stays responsive even when a node is slow or unreachable |
| `require_auth` decorator | Opt-in; safe to run token-free on a trusted LAN |
| `install.sh` firewall integration | Auto-opens ports via ufw/firewalld during install; removes on uninstall |
| One `detect_system()` for both platforms | Pi-only fields degrade to `None`/empty on generic Linux rather than branching the whole codebase |
| `urllib` (stdlib) for LLM probing | Avoids adding `requests` as a dependency to the node agent just for two GET requests per candidate port |
| Response-driven LLM detection | A port is "serving" only once its API returns a parseable model list — avoids false positives from a merely-open port |
| Vendored `hiddenscope_scanner.py`, not pip-installed | hiddenscope is stdlib-only, so it's copied into the project unmodified (MIT license retained) instead of added as a dependency; it still works standalone as its original CLI |
| `HIDDENSCOPE_SCAN_PATH` is server-side only | The static secret/reverse-shell scan (`POST /api/security/scan`) never accepts a path from the request — only from this server env var — to prevent an arbitrary-filesystem-scan vector via the API |
