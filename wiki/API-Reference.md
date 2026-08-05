# API Reference

All responses are JSON. If `SYSMONITOR_TOKEN` / `SYSHUB_TOKEN` is set, every request must include:

```
Authorization: Bearer <token>
```

---

## Node Agent API — port 8585

### `GET /api/ping`
Health check. Returns immediately.

```json
{"ok": true, "ts": 1713100000.0}
```

---

### `GET /api/boot`
Hardware identity detected once at startup and cached. `is_raspberry_pi`, `soc`, and `gpu_mb` are populated on Raspberry Pi hardware and empty/`null` otherwise; `model` falls back to DMI vendor/product identification on generic PCs and servers.

```json
{
  "platform": "linux",
  "is_raspberry_pi": false,
  "model": "Dell Inc. OptiPlex 7090",
  "soc": "",
  "gpu_mb": null,
  "hostname": "ubuntu-server",
  "kernel": "6.8.0-100-generic",
  "architecture": "x86_64",
  "os": "Ubuntu 24.04",
  "cpu_model": "12th Gen Intel Core i7-1260P",
  "cpu_vendor": "GenuineIntel",
  "cpu_max_freq": "4700 MHz",
  "serial": "",
  "python": "3.12.3",
  "boot_time": "2026-04-10T07:00:00"
}
```

---

### `GET /api/status`
Live CPU, memory, temperature, uptime, and network rates. Polled by the dashboard on every refresh cycle.

```json
{
  "cpu": {
    "usage": 12.4,
    "cores": [10.1, 14.7, 11.2, 13.6],
    "core_count": 4,
    "load_avg": [0.45, 0.38, 0.31],
    "freq_mhz": 2400
  },
  "memory": {
    "total_mb": 8192.0,
    "used_mb": 2048.3,
    "free_mb": 4096.1,
    "available_mb": 5900.2,
    "cached_mb": 512.4,
    "buffers_mb": 128.0,
    "swap_total_mb": 100.0,
    "swap_used_mb": 0.0,
    "percent": 25.0
  },
  "temperature": 52.3,
  "uptime": {
    "seconds": 345600,
    "formatted": "4d 0h 0m",
    "days": 4,
    "hours": 0,
    "minutes": 0
  },
  "network_rates": {
    "eth0": {"rx_rate": 15420, "tx_rate": 3210}
  },
  "timestamp": 1713100000.0
}
```

> `network_rates` values are **bytes/sec** since the previous poll.

---

### `GET /api/storage`
Mounted filesystem usage.

```json
[
  {
    "device": "/dev/mmcblk0p2",
    "mount": "/",
    "total_mb": 59000,
    "used_mb": 12000,
    "avail_mb": 44000,
    "percent": 21,
    "fstype": "ext4"
  }
]
```

---

### `GET /api/network`
Per-interface stats with throughput rates.

```json
{
  "interfaces": [
    {
      "name": "eth0",
      "state": "up",
      "mac": "d8:3a:dd:xx:xx:xx",
      "ip": "192.168.1.42",
      "rx_bytes": 1048576000,
      "tx_bytes": 524288000,
      "rx_mb": 1000.0,
      "tx_mb": 500.0
    }
  ],
  "rates": {
    "eth0": {"rx_rate": 15420, "tx_rate": 3210}
  }
}
```

---

### `GET /api/processes`
Top processes by CPU.

Query params: `?limit=N` (default 12, max 50)

```json
[
  {
    "user": "root",
    "pid": 1234,
    "cpu": 12.5,
    "mem": 1.3,
    "command": "python3 /opt/sys-monitor/sys_monitor.py"
  }
]
```

### `DELETE /api/processes/<pid>`
Send a signal to a process.

Query param: `?signal=N` (default 15 / SIGTERM, use 9 for SIGKILL)

```bash
curl -X DELETE "http://ubuntu-server:8585/api/processes/1234?signal=9"
```

```json
{"success": true, "pid": 1234, "signal": 9}
```

---

### `GET /api/services`
Status of all monitored services.

```json
[
  {
    "name": "ssh",
    "active": true,
    "active_state": "active",
    "enabled": true,
    "enabled_state": "enabled",
    "description": "OpenBSD Secure Shell server"
  }
]
```

### `POST /api/services/<name>/<action>`
Control a service. Actions: `start`, `stop`, `restart`, `enable`, `disable`.

```bash
curl -X POST http://ubuntu-server:8585/api/services/nginx/restart
```

```json
{"success": true, "service": "nginx", "action": "restart", "stderr": ""}
```

### Service List Management

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/services/config` | Return current service list |
| `POST` | `/api/services/config` | Add a service `{"name":"myapp"}` |
| `DELETE` | `/api/services/config/<name>` | Remove a service |
| `PUT` | `/api/services/config/<name>` | Rename `{"name":"new-name"}` |

---

### `GET /api/ports` (v2.3.0+)
Listening TCP/UDP ports in the well-known + registered range (0-49151). Prior to v2.3.0 this was capped at 9999, which excluded Ollama's default port (11434).

```json
[
  {"port": 22, "protocol": "tcp", "address": "0.0.0.0"},
  {"port": 11434, "protocol": "tcp", "address": "0.0.0.0"}
]
```

---

### `GET /api/llm` (v2.3.0+)
Detects common local-LLM ports (Ollama, llama.cpp/llamafile, vLLM, LM Studio, text-generation-webui, KoboldCpp, LocalAI, TGI, LiteLLM, GPT4All, Jan.ai, gradio chat UIs) among listening ports and checks whether each is actually serving a model.

```json
[
  {"port": 11434, "label": "Ollama", "serving": true, "api": "ollama", "models": ["llama3:8b"]},
  {"port": 8000, "label": "vLLM", "serving": false, "api": null, "models": []}
]
```

`serving` is only `true` once the port's API (Ollama's `/api/tags`, or the OpenAI-compatible `/v1/models`) returns a parseable, non-empty model list.

---

### `GET /api/security` (v2.4.0+)
Full hiddenscope security status — findings, actionable count, flagged listeners, and a summary. `available: false` (with empty/zero fields) if `hiddenscope_scanner.py` isn't present.

```json
{
  "available": true,
  "findings": [
    {"ts": 1713100000.0, "category": "suspicious_port", "severity": "high", "description": "Listener on known-suspicious port 4444", "detail": "proc=nc pid=5821", "source": "listener", "line": null}
  ],
  "actionable_count": 1,
  "flagged_listeners": [
    {"port": 1234, "protocol": "tcp", "proc": "lms-server", "known_local_service": true}
  ],
  "summary": {
    "total_connections": 42,
    "external_connections": 6,
    "total_listeners": 14,
    "findings_by_severity": {"info": 5, "low": 0, "medium": 0, "high": 1, "critical": 0}
  }
}
```

`actionable_count` counts findings with severity `>=` `HIDDENSCOPE_MIN_SEVERITY` (default `high`) — this drives the Security Alert card. `known_local_service: true` on a flagged listener means the port also matches a locally-known service (e.g. LM Studio on 1234); it's annotated, not suppressed.

### Security Allowlist

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/security/allowlist` | Return the current allowlist (`procs`, `ports`, `networks`, `url_domains`) |
| `POST` | `/api/security/allowlist` | Add an entry, e.g. `{"port": 1234}` — `port`/`proc`/`network` are all accepted, any combination in one request. Returns `{"success": true, "added": [...]}` |
| `DELETE` | `/api/security/allowlist` | Remove an entry (same body shape as `POST`). Returns `{"success": true, "removed": [...]}` |

Persists to `HIDDENSCOPE_ALLOWLIST_FILE` (default `./hiddenscope_allowlist.json`).

### `POST /api/security/scan` (v2.4.0+)
Runs hiddenscope's static scan (`scan_tree()`) for hardcoded secrets and reverse-shell patterns. The scan directory comes **only** from the server-side `HIDDENSCOPE_SCAN_PATH` env var — never from the request body — to prevent an arbitrary-filesystem-scan vector.

```bash
curl -X POST http://ubuntu-server:8585/api/security/scan
```

```json
{
  "success": true,
  "path": "/opt/sys-monitor",
  "findings": [
    {"category": "hardcoded_secret", "severity": "critical", "description": "Possible hardcoded API key", "source": "/opt/sys-monitor/config.py", "line": 14}
  ]
}
```

Returns `400` with `{"success": false, "error": "..."}` if `HIDDENSCOPE_SCAN_PATH` is unset or the path doesn't exist.

---

### `POST /api/power/<action>`
Actions: `reboot`, `shutdown`.

```bash
curl -X POST http://ubuntu-server:8585/api/power/reboot
```

```json
{"success": true, "action": "reboot"}
```

---

### `GET /api/logs`
In-memory event log (ring buffer, max 200 entries).

Query params: `?limit=50` (default 100)

```json
[
  {"ts": "14:22:01", "msg": "SysMonitor ready.", "level": "success"},
  {"ts": "14:23:10", "msg": "Service restarted: nginx", "level": "info"}
]
```

Log levels: `info`, `success`, `warning`, `error`

---

### `GET /api/system-health` (v2.2.0+)
System health status, including critical services and stability checks.

```json
{
  "stable": true,
  "issues": [],
  "critical_services_failed": [],
  "all_critical_ok": true
}
```

With issues:

```json
{
  "stable": false,
  "issues": [
    { "type": "oom", "severity": "critical", "message": "Out of memory condition detected" }
  ],
  "critical_services_failed": [
    { "name": "dbus", "state": "inactive", "critical": true }
  ],
  "all_critical_ok": false
}
```

### `GET /api/status` (v2.2.0+)
Now includes `temperature_status` and `power_status`:

```json
{
  "cpu": { "usage": 15.2, "cores": [12.3, 18.1, 14.0, 16.5], ... },
  "temperature": 52.3,
  "temperature_status": {
    "temp_c": 52.3,
    "level": "normal",           // "warning" | "critical" | "throttling"
    "message": null,
    "color": "var(--green)",
    "throttled_status": null
  },
  "power_status": {
    "available": true,
    "undervoltage_occurred": false,
    "frequency_capped_occurred": false,
    "undervoltage_now": false,
    "frequency_capped_now": false,
    "throttled_now": false,
    "throttled_raw": "throttled=0x0"
  },
  "memory": { ... },
  "uptime": { ... }
}
```

---

## Fleet Hub API — port 8686

### `GET /api/ping`
```json
{"ok": true, "hub": true, "ts": 1713100000.0}
```

### `GET /api/fleet`
Cached snapshot of all registered nodes.

```json
{
  "nodes": [
    {
      "id": "192-168-1-42-8585",
      "host": "192.168.1.42",
      "port": 8585,
      "label": "Node-Living-Room",
      "is_raspberry_pi": true,
      "online": true,
      "last_seen": 1713100000.0,
      "cpu_usage": 12.4,
      "temperature": 52.3,
      "memory_percent": 25.0,
      "uptime": "4d 0h 0m",
      "llm_services": [{"port": 11434, "label": "Ollama", "serving": true, "api": "ollama", "models": ["llama3:8b"]}],
      "llm_serving_count": 1,
      "security_actionable_count": 1,
      "security_flagged_listeners": [{"port": 1234, "protocol": "tcp", "proc": "lms-server", "known_local_service": true}]
    }
  ],
  "total": 1,
  "online": 1
}
```

> Status fields are `null` if the node has never been successfully polled. `llm_services`/`llm_serving_count` reflect that node's most recent `/api/llm` poll. `security_actionable_count`/`security_flagged_listeners` reflect its most recent `/api/security` poll and drive the "🛡 N security alerts" badge on the fleet grid.

### Node Registry

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/nodes` | Register `{"host":"...", "port":8585, "label":"...", "token":""}` |
| `DELETE` | `/api/nodes/<nid>` | Remove a node |
| `PUT` | `/api/nodes/<nid>` | Update label or token |

### Alerting

Not a route — outbound only. Set `SYSHUB_ALERT_WEBHOOK_URL` to have the Hub `POST` a JSON payload once per state transition it detects during polling (online↔offline, temperature/power/security alert↔recovered). Unset by default (disabled).

Events: `node_offline`/`node_online`, `temperature_alert`/`temperature_recovered`, `power_alert`/`power_recovered`, `security_alert`/`security_recovered`.

```json
{"event": "node_offline", "node_id": "192-168-1-42-8585", "node_label": "Node-A", "host": "192.168.1.42:8585", "timestamp": "2026-08-05T21:30:00", "message": "Node Node-A is now offline", "detail": {}}
```

Delivery failures are swallowed silently — a broken webhook receiver never stalls fleet polling.

### `POST /api/discover`
Scan the local /24 subnet for SysMonitor agents.

```json
{"subnet": "192.168.1.0/24", "port": 8585}
```

```json
{
  "found": [
    {
      "host": "192.168.1.42",
      "port": 8585,
      "hostname": "ubuntu-server",
      "model": "Intel NUC 12 Pro",
      "id": "192-168-1-42-8585",
      "already_registered": false
    }
  ],
  "count": 1
}
```

### Node Proxy Routes

All proxy routes forward to the corresponding node's API.

| Method | Hub Route | Forwards To |
|---|---|---|
| `GET` | `/api/nodes/<nid>/status` | `/api/status` |
| `GET` | `/api/nodes/<nid>/boot` | `/api/boot` |
| `GET` | `/api/nodes/<nid>/llm` | `/api/llm` |
| `GET` | `/api/nodes/<nid>/security` | `/api/security` |
| `POST` | `/api/nodes/<nid>/security/allowlist` | `/api/security/allowlist` |
| `GET` | `/api/nodes/<nid>/services` | `/api/services` |
| `POST` | `/api/nodes/<nid>/services/<svc>/<action>` | `/api/services/<svc>/<action>` |
| `GET` | `/api/nodes/<nid>/storage` | `/api/storage` |
| `GET` | `/api/nodes/<nid>/processes` | `/api/processes` |
| `GET` | `/api/nodes/<nid>/network` | `/api/network` |
| `GET` | `/api/nodes/<nid>/logs` | `/api/logs` |
| `POST` | `/api/nodes/<nid>/power/<action>` | `/api/power/<action>` |

Unreachable nodes return `502 {"error": "unreachable"}`.

---

## Error Codes

| Status | Meaning |
|---|---|
| `400` | Bad request — invalid parameters |
| `401` | Unauthorized — missing or invalid token |
| `404` | Not found — service, PID, or node doesn't exist |
| `409` | Conflict — duplicate service or node |
| `502` | Bad gateway — hub cannot reach the node |
