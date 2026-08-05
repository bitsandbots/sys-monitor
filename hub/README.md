# SysMonitor Hub — Fleet Management Console

> Aggregate dashboard for multiple SysMonitor nodes.

A central aggregation console for managing multiple [SysMonitor v2](https://coreconduit.com) instances across your network. Monitor CPU, temperature, memory, and services for your entire fleet of Linux devices from a single pane.

**CoreConduit Consulting Services** · MIT License

---

## Features

- **Fleet Overview** — Real-time aggregate metrics (avg CPU, max temp, avg RAM) across all connected nodes
- **Network Discovery (Signal Fires)** — Scan any /24 subnet to auto-detect SysMonitor instances via `/api/ping`
- **Node Drill-Down** — Click any node to view full details: system info, services, processes, storage, logs
- **Service Control** — Start/stop/restart services on remote nodes directly from the hub
- **Persistent Registry** — Node list saved to `hub_nodes.json`, survives restarts
- **Background Polling** — Parallel health checks via ThreadPoolExecutor, configurable interval
- **Auth Passthrough** — Per-node bearer token support for secured SysMonitor instances
- **LLM Fleet Visibility** — Polls each node's `/api/llm` and shows a "🧠 N models serving" badge on any node running a local LLM (Ollama, llama.cpp, vLLM, etc.)
- **Mixed fleets** — Ubuntu/Debian and Raspberry Pi nodes register the same way; each node's hardware auto-detection (Pi model/SoC/GPU vs. generic Linux/DMI) shows up in its detail view

## Quick Start

```bash
# Install
pip install flask requests

# Run
python3 sys_monitor_hub.py

# Open → http://localhost:8686
```

## Architecture

```
┌──────────────────────────┐
│    SysMonitor Hub :8686   │  ← You are here
│    (Flask + Poller)      │
└──────┬───────┬───────┬───┘
       │       │       │
       ▼       ▼       ▼
   ┌──────┐ ┌──────┐ ┌──────┐
   │Node 1│ │Node 2│ │Node N│  ← SysMonitor v2 instances
   │ :8585│ │ :8585│ │ :8585│
   └──────┘ └──────┘ └──────┘
```

The hub polls each registered node every N seconds (default 5) using `/api/ping` and `/api/status`. Boot info is cached after first successful fetch. The fleet overview displays cached data; drill-down views fetch live data on demand.

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|---|---|---|
| `SYSHUB_HOST` | `0.0.0.0` | Bind address |
| `SYSHUB_PORT` | `8686` | Listen port |
| `SYSHUB_TOKEN` | *(empty)* | Bearer token for hub API auth |
| `SYSHUB_POLL_INTERVAL` | `5` | Seconds between fleet polls |
| `SYSHUB_TIMEOUT` | `4` | HTTP timeout per node request |
| `SYSHUB_DISCOVERY_PORT` | `8585` | Default port to scan during discovery |
| `SYSHUB_NODES_FILE` | `./hub_nodes.json` | Path to persisted node registry |

## systemd

```bash
sudo cp sys-monitor-hub.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sys-monitor-hub
```

## API Reference

### Fleet
- `GET /api/fleet` — All nodes with cached status
- `GET /api/ping` — Hub health check

### Node CRUD
- `POST /api/nodes` — Register a node `{"host":"...", "port":8585, "label":"...", "token":"..."}`
- `PUT /api/nodes/<id>` — Update label/token
- `DELETE /api/nodes/<id>` — Unregister a node

### Discovery
- `POST /api/discover` — Scan subnet `{"subnet":"192.168.1.0/24", "port":8585}`

### Node Proxy
- `GET /api/nodes/<id>/status` — Live status from node
- `GET /api/nodes/<id>/boot` — Boot/hardware info
- `GET /api/nodes/<id>/llm` — LLM-serving detection (ports + models)
- `GET /api/nodes/<id>/services` — Service list
- `POST /api/nodes/<id>/services/<svc>/<action>` — Control service
- `GET /api/nodes/<id>/storage` — Disk usage
- `GET /api/nodes/<id>/processes` — Top processes
- `GET /api/nodes/<id>/network` — Network interfaces
- `GET /api/nodes/<id>/logs` — Event log
- `POST /api/nodes/<id>/power/<action>` — Reboot/shutdown

---

*"One Hub to find them all, and in the dashboard bind them."*
