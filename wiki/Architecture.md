# Architecture

## High-Level Diagram

```
Browser
  │
  │  HTTP polling (SYSMONITOR_REFRESH, default 2s)
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
       ┌───────┴────────┐
       ▼                ▼
  Node :8585       Node :8585
```

---

## Node Agent — Request Flow

1. Browser loads `index.html` (served by Flask's `render_template`).
2. Dashboard JS polls `/api/status` every `SYSMONITOR_REFRESH` seconds.
3. `/api/status` calls metric functions in sequence:
   - `get_cpu_usage()` — reads `/proc/stat`, computes delta from `_cpu_prev` (accurate instantaneous %)
   - `get_cpu_temperature()` — reads `/sys/class/thermal/thermal_zone0/temp`
   - `get_memory()` — parses `/proc/meminfo`
   - `get_uptime()` — reads `/proc/uptime`
4. On-demand endpoints (`/api/storage`, `/api/network`, `/api/processes`) are fetched only when their dashboard tab is active.
5. `/api/llm` is polled on its own slower interval since it makes live HTTP calls: `get_llm_services()` intersects `get_open_ports()` with the `LLM_PORTS` table, then `_probe_llm_port()` queries each candidate's API (Ollama's `/api/tags`, or the OpenAI-compatible `/v1/models`) to confirm it's serving a model.
6. `/api/security` calls `get_security_status()`, which delegates to the vendored `hiddenscope_scanner.py` module — `_connections()`/`_listeners()` for live enumeration, `score_connection()` against `SUSPICIOUS_PORTS` and the `AllowList` for scoring. `POST /api/security/scan` separately invokes `scan_tree()` against a directory read only from `HIDDENSCOPE_SCAN_PATH` on the server. If `hiddenscope_scanner.py` isn't importable, `HIDDENSCOPE_AVAILABLE` is `False` and these endpoints report "unavailable".
7. Mutating actions (service control, process kill, power) pass through `require_auth` middleware if `SYSMONITOR_TOKEN` is set.
8. All mutations are written to the in-memory event log (accessible via `/api/logs`).

---

## Platform Detection

`detect_system()` runs once at startup: it checks `/proc/device-tree/model` and `/proc/cpuinfo` for Raspberry Pi signatures (`raspberry` in the model string, or `bcm` in the hardware string). On a match, it decodes the SoC from the revision code and reads GPU memory split via `vcgencmd`. Otherwise it falls back to DMI (`/sys/devices/virtual/dmi/id/*`) for generic PC/server identification. `get_temperature_status()` and `get_power_status()` both call `vcgencmd get_throttled` unconditionally — it simply fails silently (empty string) on non-Pi hardware, so no platform branching is needed elsewhere in the code.

---

## Hub — Request Flow

1. At startup, `_load_nodes()` restores the node registry from `hub_nodes.json`.
2. `_start_poller()` launches a background thread that calls `_poll_node()` for every registered node every `SYSHUB_POLL_INTERVAL` seconds via `ThreadPoolExecutor(max_workers=min(node_count, 8))`.
3. Poll results are cached in the in-memory `_nodes` dict, protected by a `threading.Lock`.
4. `/api/fleet` returns the cached snapshot for all nodes instantly (no blocking).
5. Proxy routes forward live to the target node via `_fetch_node()` with per-request timeouts.
6. `/api/discover` scans the local /24 subnet in parallel, probing `<ip>:SYSHUB_DISCOVERY_PORT/api/ping`.

---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| `/proc` / `/sys` reads instead of `psutil` | Zero extra dependency; works on stock Linux without any pip install |
| Differential CPU sampling | Reads `/proc/stat` on each poll and computes from the **delta** since the last read — gives accurate instantaneous %, unlike cumulative totals |
| Differential network rate tracking | Stores previous byte counts + timestamp per interface; computes bytes/sec from the delta rather than showing raw cumulative RX/TX |
| In-memory ring buffer for logs | No disk I/O; events survive service restarts only if the process stays up — ephemeral by design |
| `services.json` persistence | Service list survives restarts and is decoupled from env vars after first run; editable live via API |
| Hub caches polls, serves stale data | Dashboard stays responsive even when a node is slow or temporarily unreachable |
| Service whitelist | `control_service()` rejects any service name not in `CONFIG["services"]` before invoking `systemctl` — prevents arbitrary service execution |
| Single-file frontend | `templates/index.html` is self-contained HTML + CSS + JS; no build step, no node_modules |
| Boot detection cached at startup | CPU model, vendor, and architecture from `/proc/cpuinfo` and `/sys` run once and are served from memory |
| Vendored `hiddenscope_scanner.py`, not pip-installed | Stdlib-only, MIT-licensed (CoreConduit Consulting, same author) — copied in unmodified rather than added as a dependency; still works standalone as its original CLI |
| `HIDDENSCOPE_SCAN_PATH` is server-side only | `POST /api/security/scan` never accepts a path from the request — only from this server env var — closing off an arbitrary-filesystem-scan vector |

---

## File Layout

```
sys-monitor/
├── sys_monitor.py             # Node agent — Flask API + all data collection
├── hiddenscope_scanner.py     # Vendored hiddenscope security scanner (MIT, CoreConduit Consulting)
├── hiddenscope_allowlist.json # Persisted security allowlist (created on first use)
├── templates/
│   └── index.html             # Single-file frontend (HTML + CSS + JS)
├── sys-monitor.service        # systemd unit
├── requirements.txt           # flask only
├── install.sh                 # Installer
├── release.sh                 # Release packager
├── .env.example               # All env vars documented
└── hub/
    ├── sys_monitor_hub.py     # Hub — fleet aggregation + proxy
    ├── templates/
    │   └── hub.html           # Hub frontend
    ├── sys-monitor-hub.service # systemd unit
    └── requirements.txt       # flask + requests
```
