# Hub Setup

The Hub (`sys_monitor_hub.py`) is an optional fleet layer that aggregates multiple SysMonitor node agents into a single dashboard — Ubuntu/Debian nodes and Raspberry Pi nodes can be mixed freely in the same fleet, since every node auto-detects its own hardware. The fleet grid also shows a "🧠 N models serving" badge on any node currently serving a local LLM model, and a "🛡 N security alerts" badge (tooltip lists the flagged listener labels/ports) on any node with actionable hiddenscope findings. The dashboard header has a fleet-wide "Security Alerts" tile summing the actionable count across all known nodes.

```
┌──────────────────────────┐
│    SysMonitor Hub :8686   │  ← central console
└──────┬───────┬───────┬───┘
       ▼       ▼       ▼
   Node A   Node B   Node N
   :8585    :8585    :8585
```

---

## Install the Hub

### On the same system as a node agent

```bash
sudo ./install.sh --hub
```

This installs both the node agent (`:8585`) and the hub (`:8686`). `install.sh` also copies `hiddenscope_scanner.py` to each node, if present in the source checkout, so security monitoring works out of the box with no extra install steps.

### On a dedicated machine (hub-only)

```bash
sudo ./install.sh --hub-only
```

### Manual

```bash
pip3 install flask requests --break-system-packages
python3 hub/sys_monitor_hub.py
```

Open `http://<hub-ip>:8686`

---

## Registering Nodes

### Option 1 — Network Discovery (Signal Fires)

In the hub dashboard, click **Discover** and enter your subnet (e.g. `192.168.1.0/24`). The hub will scan all 254 hosts in parallel and list any responding SysMonitor agents.

Via API:

```bash
curl -X POST http://hub:8686/api/discover \
  -H "Content-Type: application/json" \
  -d '{"subnet": "192.168.1.0/24", "port": 8585}'
```

### Option 2 — Manual Registration

```bash
curl -X POST http://hub:8686/api/nodes \
  -H "Content-Type: application/json" \
  -d '{"host": "192.168.1.42", "port": 8585, "label": "Node-Kitchen"}'
```

With a per-node token:

```bash
curl -X POST http://hub:8686/api/nodes \
  -H "Content-Type: application/json" \
  -d '{"host": "192.168.1.43", "port": 8585, "label": "Node-Garage", "token": "my-secret"}'
```

---

## Polling Behavior

The hub polls each registered node every `SYSHUB_POLL_INTERVAL` seconds (default 5). It uses a `ThreadPoolExecutor` with up to 8 concurrent workers, so polling scales across a large fleet without blocking.

Cached data is served to the browser instantly from `/api/fleet`. If a node goes offline, its last-known status is shown with an **offline** indicator until it recovers.

---

## Per-Node Authentication

If individual node agents have `SYSMONITOR_TOKEN` set, register them with a token:

```bash
curl -X PUT http://hub:8686/api/nodes/192-168-1-42-8585 \
  -H "Content-Type: application/json" \
  -d '{"token": "node-secret"}'
```

The hub stores tokens in `hub_nodes.json` and passes them as `Authorization: Bearer` headers when proxying requests.

---

## Node Drill-Down

Clicking any node card in the hub dashboard opens a detailed view with live data fetched directly from that node:

- System info and hardware identity
- Service status and control
- Top processes with kill capability
- Storage and filesystem usage
- Network interfaces and throughput
- Event log
- Security (hiddenscope) — connection/finding counts and flagged listener details, in a dedicated "SECURITY (hiddenscope)" section

All actions (service control, process kill, power) are proxied through the hub to the target node.

---

## Node Registry Persistence

Registered nodes are stored in `hub_nodes.json` (default `./hub_nodes.json`, override with `SYSHUB_NODES_FILE`). The file is written on every add/remove/update. To reset the registry, delete the file and restart the hub.

---

## Removing a Node

Via dashboard: click the **×** on the node card.

Via API:

```bash
curl -X DELETE http://hub:8686/api/nodes/192-168-1-42-8585
```
