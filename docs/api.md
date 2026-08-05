# SysMonitor — API Reference

All responses are JSON. Authentication (if enabled) requires `Authorization: Bearer <token>` on every request.

---

## Node Agent API (`sys_monitor.py`, default port 8585)

### Health

#### `GET /api/ping`
Returns immediately. Use to check if the agent is up.

```json
{"ok": true, "ts": 1713100000.0}
```

---

### System

#### `GET /api/boot`
Hardware identity, detected once at startup and cached. Fields are populated appropriately for whichever platform SysMonitor is actually running on — Raspberry Pi fields (`soc`, `gpu_mb`, `revision`) are Pi-only and empty/`null` on generic Linux; `model` falls back to DMI vendor/product identification on non-Pi hardware.

Generic Ubuntu/Debian PC or server:

```json
{
  "platform": "linux",
  "is_raspberry_pi": false,
  "model": "Dell Inc. OptiPlex 7090",
  "revision": "",
  "soc": "",
  "gpu_mb": null,
  "serial": "",
  "hardware": "",
  "hostname": "ubuntu-server",
  "kernel": "6.8.0-100-generic",
  "architecture": "x86_64",
  "os": "Ubuntu 24.04 LTS",
  "cpu_model": "Intel Core i7-13700",
  "cpu_vendor": "GenuineIntel",
  "cpu_max_freq": "2400 MHz",
  "python": "3.13.0",
  "boot_time": "2026-04-10T07:00:00"
}
```

Raspberry Pi:

```json
{
  "platform": "raspberry_pi",
  "is_raspberry_pi": true,
  "model": "Raspberry Pi 5 Model B Rev 1.0",
  "revision": "d04170",
  "soc": "BCM2712",
  "gpu_mb": 76,
  "serial": "abcdef12",
  "hardware": "BCM2712",
  "hostname": "pi-livingroom",
  "kernel": "6.6.31-v8+",
  "architecture": "aarch64",
  "os": "Debian GNU/Linux 12 (bookworm)",
  "cpu_model": "ARMv8 Processor rev 1",
  "cpu_vendor": "",
  "cpu_max_freq": "2400 MHz",
  "python": "3.11.2",
  "boot_time": "2026-04-10T07:00:00"
}
```

> `serial` is the last 8 characters of the CPU serial number (Pi only).

#### `GET /api/status`
Live snapshot — CPU, memory, temperature, uptime, network rates. Polled by the dashboard on every refresh cycle.

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
    "eth0": {"rx_rate": 15420, "tx_rate": 3210},
    "wlan0": {"rx_rate": 0, "tx_rate": 0}
  },
  "timestamp": 1713100000.0
}
```

> `network_rates` values are bytes/sec since the previous poll.
> `timestamp` is a Unix float, not a formatted string.

---

### Storage

#### `GET /api/storage`
Mounted filesystem usage via `df -BM`. Returns an array.

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

### Network

#### `GET /api/network`
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

> `rates` values are bytes/sec since the previous call.

---

### Processes

#### `GET /api/processes`
Top processes by CPU usage (`ps aux --sort=-%cpu`).

Query params: `?limit=N` (default 12, max 50).

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

#### `DELETE /api/processes/<pid>`
Send a signal to a process.

Query param: `?signal=N` (default 15 / SIGTERM).

```bash
curl -X DELETE "http://node:8585/api/processes/1234?signal=9"
```

Response:
```json
{"success": true, "pid": 1234, "signal": 9}
```

Error (process not found):
```json
{"success": false, "error": "PID 1234 not found"}
```

---

### Services

#### `GET /api/services`
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

#### `POST /api/services/<name>/<action>`
Control a service. Valid actions: `start`, `stop`, `restart`, `enable`, `disable`.

```bash
curl -X POST http://node:8585/api/services/nginx/restart
```

Response:
```json
{"success": true, "service": "nginx", "action": "restart", "stderr": ""}
```

#### `GET /api/services/config`
Return the current persisted service list as a bare array.

```json
["ssh", "nginx", "docker"]
```

#### `POST /api/services/config`
Add a service to the monitored list.

```json
{"name": "myapp"}
```

#### `DELETE /api/services/config/<name>`
Remove a service from the list.

#### `PUT /api/services/config/<name>`
Rename a service entry.

```json
{"name": "myapp-v2"}
```

---

### Power

#### `POST /api/power/<action>`
Valid actions: `reboot`, `shutdown`.

```bash
curl -X POST http://node:8585/api/power/reboot
```

Response:
```json
{"success": true, "action": "reboot"}
```

---

### Logs

#### `GET /api/logs`
Retrieve the in-memory event log (ring buffer, max 200 entries).

Query params:
- `?limit=50` (default 100)
- `?system=true` — Include system errors from journalctl

```json
[
  {"ts": "14:22:01", "msg": "SysMonitor ready.", "level": "success"},
  {"ts": "14:23:10", "msg": "Service restarted: nginx", "level": "info"}
]
```

Log levels: `info`, `success`, `warning`, `error`.

---

### Ports

#### `GET /api/ports`
List all listening TCP/UDP ports in the well-known + registered range (0-49151). The IANA ephemeral/dynamic range (49152-65535) is excluded since it's never relevant to service discovery.

```json
[
  {"port": 22, "protocol": "tcp", "address": "0.0.0.0"},
  {"port": 80, "protocol": "tcp", "address": "*"},
  {"port": 111, "protocol": "tcp", "address": "0.0.0.0"},
  {"port": 111, "protocol": "udp", "address": "0.0.0.0"},
  {"port": 11434, "protocol": "tcp", "address": "0.0.0.0"}
]
```

Uses `ss -tuln` for fast enumeration (no port scanning). Note: prior to v2.3.0 this range was capped at 9999, which silently excluded Ollama's default port (11434) from ever appearing here or being matched to the `ollama` service in `/api/services-with-ports`.

---

### LLM Model-Serving Detection

#### `GET /api/llm`
Detect common local-LLM ports among currently listening ports, and for each one, check whether it's actually serving a model (not just that the port is open).

Recognized out of the box: Ollama (11434), llama.cpp / llamafile / LocalAI / TGI / OpenWebUI (8080), LM Studio (1234), text-generation-webui (5000), KoboldCpp (5001), vLLM (8000), GPT4All (4891), LiteLLM (4000), Jan.ai (1337), and gradio-based chat UIs (7860). Also probes the port of any monitored service whose name looks LLM-related (e.g. `ollama`, `my-vllm-server`), even on a non-standard port.

Detection works by querying each candidate port's API: Ollama's native `/api/tags`, or the OpenAI-compatible `/v1/models` endpoint used by most of the others. A port is only reported as `"serving": true` once its API returns a parseable, non-empty model list — a merely-open port with no recognized response is reported as not serving.

```json
[
  {
    "port": 11434,
    "label": "Ollama",
    "serving": true,
    "api": "ollama",
    "models": ["llama3:8b", "phi3:mini"]
  },
  {
    "port": 8000,
    "label": "vLLM",
    "serving": false,
    "api": null,
    "models": []
  }
]
```

---

### Security Monitoring (hiddenscope)

#### `GET /api/security`
Full hiddenscope security status: live findings, actionable count, flagged listeners, and a summary. If `hiddenscope_scanner.py` isn't present, `available` is `false` and the other fields report empty/zero rather than erroring.

```json
{
  "available": true,
  "findings": [
    {
      "ts": 1713100000.0,
      "category": "suspicious_port",
      "severity": "high",
      "description": "Listener on known-suspicious port 4444",
      "detail": "proc=nc pid=5821",
      "source": "listener",
      "line": null
    },
    {
      "ts": 1713100000.0,
      "category": "external_connection",
      "severity": "info",
      "description": "Outbound connection to 93.184.216.34:443",
      "detail": "proc=firefox pid=4410",
      "source": "connection",
      "line": null
    }
  ],
  "actionable_count": 1,
  "flagged_listeners": [
    {
      "port": 1234,
      "protocol": "tcp",
      "proc": "lms-server",
      "known_local_service": true
    }
  ],
  "summary": {
    "total_connections": 42,
    "external_connections": 6,
    "total_listeners": 14,
    "findings_by_severity": {"info": 5, "low": 0, "medium": 0, "high": 1, "critical": 0}
  }
}
```

> `actionable_count` counts findings with severity `>=` `HIDDENSCOPE_MIN_SEVERITY` (default `high`) — this is what drives the Security Alert card.
> `flagged_listeners` are listening ports matching hiddenscope's suspicious-port list that aren't allowlisted. `known_local_service: true` means the port also matches a locally-known service (e.g. LM Studio on 1234) — it's annotated, not suppressed, so you can decide whether to allowlist it.
> Live scoring alone only ever produces `high` or `info` findings; `medium`/`critical` findings come from the on-demand static scan (`POST /api/security/scan`).

#### `GET /api/security/allowlist`
Return the current allowlist.

```json
{
  "procs": ["lms-server"],
  "ports": [1234],
  "networks": ["192.168.1.0/24"],
  "url_domains": []
}
```

#### `POST /api/security/allowlist`
Add an allowlist entry. Body shape is roughly `{"type": "port"|"proc"|"network", "value": ...}` — see the route in `sys_monitor.py` for the exact accepted fields.

```bash
curl -X POST http://node:8585/api/security/allowlist \
  -H "Content-Type: application/json" \
  -d '{"type": "port", "value": 1234}'
```

```json
{"success": true, "allowlist": {"procs": [], "ports": [1234], "networks": [], "url_domains": []}}
```

#### `DELETE /api/security/allowlist`
Remove an allowlist entry (same body shape as `POST`).

```json
{"success": true, "allowlist": {"procs": [], "ports": [], "networks": [], "url_domains": []}}
```

Allowlist changes persist to `HIDDENSCOPE_ALLOWLIST_FILE` (default `./hiddenscope_allowlist.json`).

#### `POST /api/security/scan`
Run hiddenscope's static scan (`scan_tree()`) for hardcoded secrets and reverse-shell patterns against a directory. The path is **never** accepted from the request — it comes only from the server-side `HIDDENSCOPE_SCAN_PATH` environment variable, so a client can trigger a scan but can't choose what gets scanned.

```bash
curl -X POST http://node:8585/api/security/scan
```

```json
{
  "success": true,
  "path": "/opt/sys-monitor",
  "findings": [
    {
      "category": "hardcoded_secret",
      "severity": "critical",
      "description": "Possible hardcoded API key",
      "source": "/opt/sys-monitor/config.py",
      "line": 14
    }
  ]
}
```

If `HIDDENSCOPE_SCAN_PATH` is unset or doesn't exist:

```json
{"success": false, "error": "HIDDENSCOPE_SCAN_PATH is not configured"}
```
Returns `400`.

---

### Services with Ports

#### `GET /api/services-with-ports`
Return systemd services merged with open port information.

```json
[
  {
    "name": "ssh",
    "port": 22,
    "protocol": "tcp",
    "active": true,
    "enabled": true,
    "known": true,
    "description": "OpenBSD Secure Shell server"
  },
  {
    "name": null,
    "port": 3306,
    "protocol": "tcp",
    "address": "127.0.0.1",
    "known": false,
    "description": "Port 3306/tcp"
  }
]
```

- `known: true` — Service is in the monitored list
- `known: false` — Port is open but not mapped to a known service

---

### System Errors

#### `GET /api/system-errors`
Retrieve recent error-level journal entries.

Query params: `?limit=50` (default 50, max 200).

```json
[
  {
    "ts": "14:22:01",
    "unit": "nginx.service",
    "msg": "Failed to start nginx.service",
    "priority": "3"
  }
]
```

Uses `journalctl -p err` to filter for error priority.

---

### System Health

#### `GET /api/system-health`
Returns system health status, critical services, and stability checks. Added in v2.2.0.

```json
{
  "stable": true,
  "issues": [],
  "critical_services_failed": [],
  "all_critical_ok": true
}
```

When there are issues:

```json
{
  "stable": false,
  "issues": [
    { "type": "oom", "severity": "critical", "message": "Out of memory condition detected" },
    { "type": "kernel_error", "severity": "critical", "message": "Kernel oops detected" },
    { "type": "restart_loop", "severity": "warning", "message": "Service restart loop detected (7 restarts)" }
  ],
  "critical_services_failed": [
    { "name": "dbus", "state": "inactive", "critical": true }
  ],
  "all_critical_ok": false
}
```

Checks performed:
- Critical service status (`systemd-journald`, `dbus`, `cron`, `systemd-networkd`/`networking`)
- OOM events in journal
- Kernel errors in journal
- Service restart loops (>5 restarts in recent logs)

---

## Fleet Hub API (`hub/sys_monitor_hub.py`, default port 8686)

### Health

#### `GET /api/ping`
```json
{"ok": true, "hub": true, "ts": 1713100000.0}
```

---

### Fleet

#### `GET /api/fleet`
Cached snapshot of all registered nodes (updated every poll interval).

```json
{
  "nodes": [
    {
      "id": "192-168-1-42-8585",
      "host": "192.168.1.42",
      "port": 8585,
      "label": "Living-Room",
      "token_set": false,
      "added": "2026-04-10T07:00:00",
      "online": true,
      "last_seen": 1713100000.0,
      "hostname": "ubuntu-server",
      "model": "Dell Inc. OptiPlex 7090",
      "is_raspberry_pi": false,
      "soc": "",
      "architecture": "x86_64",
      "os": "Ubuntu 24.04 LTS",
      "kernel": "6.8.0-100-generic",
      "cpu_vendor": "GenuineIntel",
      "cpu_model": "Intel Core i7-13700",
      "cpu_usage": 12.4,
      "cpu_cores": 4,
      "temperature": 52.3,
      "memory_percent": 25.0,
      "memory_total_mb": 8192.0,
      "memory_used_mb": 2048.3,
      "uptime": "4d 0h 0m",
      "load_avg": [0.45, 0.38, 0.31],
      "llm_services": [
        {"port": 11434, "label": "Ollama", "serving": true, "api": "ollama", "models": ["llama3:8b"]}
      ],
      "llm_serving_count": 1
    }
  ],
  "total": 1,
  "online": 1
}
```

> `last_seen` is a Unix timestamp float.
> Status fields (`cpu_usage`, `temperature`, etc.) are `null` if the node has never been successfully polled.
> `llm_services`/`llm_serving_count` reflect the most recent `/api/llm` poll of that node; `llm_serving_count` is how many of the detected ports are currently serving a model.

---

### Node Registry

#### `POST /api/nodes`
Register a new node.

```json
{"host": "192.168.1.42", "port": 8585, "label": "Node-A", "token": ""}
```

#### `DELETE /api/nodes/<nid>`
Remove a node from the registry.

#### `PUT /api/nodes/<nid>`
Update a node's label or token.

---

### Discovery

#### `POST /api/discover`
Scan the local subnet for SysMonitor agents. Probes `<ip>:SYSHUB_DISCOVERY_PORT/api/ping` in parallel across the /24.

Request body (optional):
```json
{"subnet": "192.168.1.0/24", "port": 8585}
```

Response:
```json
{
  "found": [
    {
      "host": "192.168.1.42",
      "port": 8585,
      "hostname": "ubuntu-server",
      "model": "Generic Linux",
      "id": "192-168-1-42-8585",
      "already_registered": false
    }
  ],
  "count": 1
}
```

---

### Node Proxy Routes

All proxy routes forward to the corresponding node's API. Response shape matches the node API docs above.

| Method | Hub Route | Forwards To |
|--------|-----------|------------|
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

If a node is unreachable, proxy routes return `502` with `{"error": "unreachable"}`.

> The hub polls `/api/security` on every node the same way it polls `/api/llm`, caches `security_actionable_count` and flagged-listener details in the fleet snapshot (`GET /api/fleet`), and sums the actionable counts across all known nodes for the dashboard's "Security Alerts" tile — including nodes that are momentarily offline, so the tile doesn't blip to zero when a node briefly drops.

---

## Error Responses

| Status | Meaning |
|--------|---------|
| `400` | Bad request — invalid parameters |
| `401` | Unauthorized — missing or invalid token |
| `404` | Not found — service or node doesn't exist |
| `409` | Conflict — duplicate service name |
| `502` | Bad gateway — hub cannot reach the node |
