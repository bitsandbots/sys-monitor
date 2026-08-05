#!/usr/bin/env python3
"""
SysMonitorHub — Fleet Management Console
Aggregate dashboard for multiple SysMonitor nodes — Ubuntu/Debian PCs,
servers, and Raspberry Pi boards alike.

A central aggregation console that discovers, monitors, and controls
multiple SysMonitor instances across the network, including which of them
are currently serving a local LLM model (Ollama, llama.cpp, vLLM, etc.) and
which have active hiddenscope security alerts (suspicious listeners or
connections) that need attention.

CoreConduit Consulting Services — https://coreconduit.com
License: MIT
"""

import json
import os
import re
import socket
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import wraps
from ipaddress import IPv4Network
from pathlib import Path

import requests
from flask import Flask, jsonify, render_template, request, abort

app = Flask(__name__)

VERSION = "2.4.0"

# ═══════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════
HUB_CONFIG = {
    "host": os.getenv("SYSHUB_HOST", "0.0.0.0"),
    "port": int(os.getenv("SYSHUB_PORT", "8686")),
    "debug": os.getenv("SYSHUB_DEBUG", "false").lower() == "true",
    "auth_token": os.getenv("SYSHUB_TOKEN", ""),
    "poll_interval": int(os.getenv("SYSHUB_POLL_INTERVAL", "5")),
    "request_timeout": int(os.getenv("SYSHUB_TIMEOUT", "4")),
    "discovery_port": int(os.getenv("SYSHUB_DISCOVERY_PORT", "8585")),
}

_NODES_FILE = Path(
    os.getenv(
        "SYSHUB_NODES_FILE",
        str(Path(__file__).parent / "hub_nodes.json"),
    )
)

# ═══════════════════════════════════════════════════════════════════════════
# Node Registry
# ═══════════════════════════════════════════════════════════════════════════
_nodes_lock = threading.Lock()
_nodes = {}  # keyed by node_id (user-assigned or auto-generated)


def _generate_id(host, port):
    """Generate a stable ID from host:port."""
    safe = re.sub(r"[^a-zA-Z0-9]", "-", f"{host}-{port}")
    return safe.strip("-")


def _load_nodes():
    """Load saved node registry from disk."""
    global _nodes
    if _NODES_FILE.exists():
        try:
            data = json.loads(_NODES_FILE.read_text())
            if isinstance(data, dict):
                with _nodes_lock:
                    for nid, info in data.items():
                        _nodes[nid] = {
                            "id": nid,
                            "host": info["host"],
                            "port": info.get("port", 8585),
                            "label": info.get("label", ""),
                            "token": info.get("token", ""),
                            "added": info.get("added", datetime.now().isoformat()),
                            # Runtime state (not persisted)
                            "online": False,
                            "last_seen": None,
                            "boot": None,
                            "status": None,
                        }
        except (json.JSONDecodeError, OSError, KeyError):
            pass


def _save_nodes():
    """Persist node registry (only config fields, not runtime state)."""
    with _nodes_lock:
        persist = {}
        for nid, n in _nodes.items():
            persist[nid] = {
                "host": n["host"],
                "port": n["port"],
                "label": n.get("label", ""),
                "token": n.get("token", ""),
                "added": n.get("added", ""),
            }
    try:
        _NODES_FILE.write_text(json.dumps(persist, indent=2) + "\n")
    except OSError:
        pass


def _add_node(host, port=8585, label="", token=""):
    """Add a node to the registry. Returns (node_id, created)."""
    nid = _generate_id(host, port)
    with _nodes_lock:
        if nid in _nodes:
            return nid, False
        _nodes[nid] = {
            "id": nid,
            "host": host,
            "port": port,
            "label": label,
            "token": token,
            "added": datetime.now().isoformat(timespec="seconds"),
            "online": False,
            "last_seen": None,
            "boot": None,
            "status": None,
        }
    _save_nodes()
    return nid, True


def _remove_node(nid):
    """Remove a node from the registry."""
    with _nodes_lock:
        if nid not in _nodes:
            return False
        del _nodes[nid]
    _save_nodes()
    return True


def _get_node(nid):
    with _nodes_lock:
        return _nodes.get(nid)


def _get_all_nodes():
    with _nodes_lock:
        return {nid: dict(n) for nid, n in _nodes.items()}


# ═══════════════════════════════════════════════════════════════════════════
# Node Communication
# ═══════════════════════════════════════════════════════════════════════════
def _node_url(node, path):
    return f"http://{node['host']}:{node['port']}/api/{path}"


def _node_headers(node):
    h = {}
    if node.get("token"):
        h["Authorization"] = f"Bearer {node['token']}"
    return h


def _fetch_node(node, path, method="GET", json_body=None, timeout=None):
    """Make an HTTP request to a SysMonitor node."""
    t = timeout or HUB_CONFIG["request_timeout"]
    url = _node_url(node, path)
    headers = _node_headers(node)
    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=t)
        elif method == "POST":
            r = requests.post(url, headers=headers, json=json_body, timeout=t)
        elif method == "PUT":
            r = requests.put(url, headers=headers, json=json_body, timeout=t)
        elif method == "DELETE":
            r = requests.delete(url, headers=headers, timeout=t)
        else:
            return None
        if r.status_code < 400:
            return r.json()
        return None
    except (requests.RequestException, ValueError):
        return None


def _poll_node(nid):
    """Poll a single node for status + boot info. Updates state in-place."""
    with _nodes_lock:
        node = _nodes.get(nid)
        if not node:
            return

    # Quick ping first
    ping = _fetch_node(node, "ping", timeout=2)
    if not ping or not ping.get("ok"):
        with _nodes_lock:
            if nid in _nodes:
                _nodes[nid]["online"] = False
        return

    # Fetch status (fast-changing metrics)
    status = _fetch_node(node, "status")

    # Fetch boot info less frequently (only if we don't have it)
    boot = node.get("boot")
    if not boot:
        boot = _fetch_node(node, "boot")

    # Fetch LLM service detection (candidate ports + any served models)
    llm = _fetch_node(node, "llm")

    # Fetch security status (hiddenscope — suspicious connections/listeners)
    security = _fetch_node(node, "security")

    with _nodes_lock:
        if nid in _nodes:
            _nodes[nid]["online"] = True
            _nodes[nid]["last_seen"] = time.time()
            if status:
                _nodes[nid]["status"] = status
            if boot:
                _nodes[nid]["boot"] = boot
            if llm is not None:
                _nodes[nid]["llm"] = llm
            if security is not None:
                _nodes[nid]["security"] = security


# ═══════════════════════════════════════════════════════════════════════════
# Background Poller
# ═══════════════════════════════════════════════════════════════════════════
_poller_running = False


def _poller_loop():
    """Background thread that polls all registered nodes."""
    global _poller_running
    _poller_running = True
    while _poller_running:
        try:
            node_ids = list(_get_all_nodes().keys())
            if node_ids:
                with ThreadPoolExecutor(max_workers=min(len(node_ids), 8)) as pool:
                    futures = {pool.submit(_poll_node, nid): nid for nid in node_ids}
                    for f in as_completed(futures, timeout=10):
                        try:
                            f.result()
                        except Exception:
                            pass
        except Exception:
            # A slow node can blow the as_completed timeout above (raising
            # TimeoutError from the iterator itself, not from f.result()).
            # Catch broadly here so one bad cycle never kills this daemon
            # thread — there's no supervisor to restart it otherwise.
            traceback.print_exc()
        time.sleep(HUB_CONFIG["poll_interval"])


def _start_poller():
    t = threading.Thread(target=_poller_loop, daemon=True, name="hub-poller")
    t.start()


# ═══════════════════════════════════════════════════════════════════════════
# Network Discovery
# ═══════════════════════════════════════════════════════════════════════════
def _get_local_ip():
    """Best-effort local IP detection."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _discover_subnet(subnet=None, port=None, timeout=1.5):
    """Scan a /24 subnet for SysMonitor instances responding to /api/ping."""
    port = port or HUB_CONFIG["discovery_port"]
    if not subnet:
        local_ip = _get_local_ip()
        # Default to the local /24
        subnet = re.sub(r"\.\d+$", ".0/24", local_ip)

    try:
        network = IPv4Network(subnet, strict=False)
    except ValueError:
        return []

    hosts = [str(ip) for ip in network.hosts()]
    found = []

    def _probe(ip):
        try:
            r = requests.get(
                f"http://{ip}:{port}/api/ping",
                timeout=timeout,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("ok"):
                    # Try to get boot info for labeling
                    boot = None
                    try:
                        br = requests.get(
                            f"http://{ip}:{port}/api/boot",
                            timeout=timeout,
                        )
                        if br.status_code == 200:
                            boot = br.json()
                    except Exception:
                        pass
                    return {
                        "host": ip,
                        "port": port,
                        "hostname": boot.get("hostname", "") if boot else "",
                        "model": boot.get("model", "") if boot else "",
                        "id": _generate_id(ip, port),
                        "already_registered": _generate_id(ip, port)
                        in _get_all_nodes(),
                    }
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=32) as pool:
        futures = {pool.submit(_probe, ip): ip for ip in hosts}
        for f in as_completed(futures, timeout=45):
            try:
                result = f.result()
                if result:
                    found.append(result)
            except Exception:
                pass

    return sorted(found, key=lambda x: x["host"])


# ═══════════════════════════════════════════════════════════════════════════
# Serialization Helper
# ═══════════════════════════════════════════════════════════════════════════
def _serialize_node(n):
    """Prepare a node dict for JSON response (safe, no internal refs)."""
    boot = n.get("boot") or {}
    status = n.get("status") or {}
    return {
        "id": n["id"],
        "host": n["host"],
        "port": n["port"],
        "label": n.get("label") or boot.get("hostname") or n["host"],
        "token_set": bool(n.get("token")),
        "added": n.get("added", ""),
        "online": n.get("online", False),
        "last_seen": n.get("last_seen"),
        # Boot info
        "hostname": boot.get("hostname", ""),
        "model": boot.get("model", ""),
        "is_raspberry_pi": boot.get("is_raspberry_pi", False),
        "soc": boot.get("soc", ""),
        "architecture": boot.get("architecture", ""),
        "os": boot.get("os", ""),
        "kernel": boot.get("kernel", ""),
        "cpu_vendor": boot.get("cpu_vendor", ""),
        "cpu_model": boot.get("cpu_model", ""),
        # Live status
        "cpu_usage": status.get("cpu", {}).get("usage"),
        "cpu_cores": status.get("cpu", {}).get("core_count"),
        "temperature": status.get("temperature"),
        "memory_percent": status.get("memory", {}).get("percent"),
        "memory_total_mb": status.get("memory", {}).get("total_mb"),
        "memory_used_mb": status.get("memory", {}).get("used_mb"),
        "uptime": status.get("uptime", {}).get("formatted"),
        "load_avg": status.get("cpu", {}).get("load_avg"),
        # LLM services detected on this node (port, label, serving, models)
        "llm_services": n.get("llm") or [],
        "llm_serving_count": sum(1 for s in (n.get("llm") or []) if s.get("serving")),
        # Security status (hiddenscope) on this node
        "security_available": (n.get("security") or {}).get("available", False),
        "security_actionable_count": (n.get("security") or {}).get("actionable_count", 0),
        "security_flagged_listeners": (n.get("security") or {}).get("flagged_listeners", []),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Auth Middleware
# ═══════════════════════════════════════════════════════════════════════════
def require_auth(f):
    """Optional bearer-token authentication."""

    @wraps(f)
    def decorated(*args, **kwargs):
        token = HUB_CONFIG["auth_token"]
        if token:
            auth = request.headers.get("Authorization", "")
            if auth != f"Bearer {token}":
                abort(401, description="Unauthorized")
        return f(*args, **kwargs)

    return decorated


@app.before_request
def _csrf_guard():
    """Reject cross-origin state-changing requests (CSRF via a plain form POST)."""
    if request.method not in ("POST", "PUT", "DELETE", "PATCH"):
        return
    expected = f"{request.scheme}://{request.host}"
    source = request.headers.get("Origin") or request.headers.get("Referer")
    if source and not source.startswith(expected):
        abort(403, description="Cross-origin request blocked")


# ═══════════════════════════════════════════════════════════════════════════
# API Routes
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    local_ip = _get_local_ip()
    return render_template("hub.html", config=HUB_CONFIG, local_ip=local_ip)


# ── Fleet Overview ──
@app.route("/api/fleet")
@require_auth
def api_fleet():
    """All nodes with latest cached status."""
    nodes = _get_all_nodes()
    fleet = [_serialize_node(n) for n in nodes.values()]
    fleet.sort(key=lambda x: (not x["online"], x["label"].lower()))
    online = sum(1 for n in fleet if n["online"])
    return jsonify(
        {
            "nodes": fleet,
            "total": len(fleet),
            "online": online,
        }
    )


# ── Node CRUD ──
@app.route("/api/nodes", methods=["POST"])
@require_auth
def api_add_node():
    data = request.get_json(silent=True) or {}
    host = data.get("host", "").strip()
    port = data.get("port", 8585)
    label = data.get("label", "").strip()
    token = data.get("token", "").strip()
    if not host:
        return jsonify({"success": False, "error": "Host required"}), 400
    if not re.match(r"^[\d.a-zA-Z_:-]+$", host):
        return jsonify({"success": False, "error": "Invalid host"}), 400
    nid, created = _add_node(host, int(port), label, token)
    if not created:
        return (
            jsonify({"success": False, "error": "Node already registered", "id": nid}),
            409,
        )
    # Trigger immediate poll
    threading.Thread(target=_poll_node, args=(nid,), daemon=True).start()
    return jsonify({"success": True, "id": nid}), 201


@app.route("/api/nodes/<nid>", methods=["DELETE"])
@require_auth
def api_remove_node(nid):
    if _remove_node(nid):
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Not found"}), 404


@app.route("/api/nodes/<nid>", methods=["PUT"])
@require_auth
def api_update_node(nid):
    data = request.get_json(silent=True) or {}
    with _nodes_lock:
        node = _nodes.get(nid)
        if not node:
            return jsonify({"success": False, "error": "Not found"}), 404
        if "label" in data:
            node["label"] = data["label"].strip()
        if "token" in data:
            node["token"] = data["token"].strip()
    _save_nodes()
    return jsonify({"success": True})


# ── Discovery ──
@app.route("/api/discover", methods=["POST"])
@require_auth
def api_discover():
    data = request.get_json(silent=True) or {}
    subnet = (data.get("subnet") or "").strip() or None
    port = data.get("port") or None
    found = _discover_subnet(subnet, port)
    return jsonify({"found": found, "count": len(found)})


# ── Proxy: fetch data from a specific node ──
@app.route("/api/nodes/<nid>/status")
@require_auth
def api_node_status(nid):
    node = _get_node(nid)
    if not node:
        return jsonify({"error": "Not found"}), 404
    data = _fetch_node(node, "status")
    return jsonify(data) if data else (jsonify({"error": "unreachable"}), 502)


@app.route("/api/nodes/<nid>/boot")
@require_auth
def api_node_boot(nid):
    node = _get_node(nid)
    if not node:
        return jsonify({"error": "Not found"}), 404
    data = _fetch_node(node, "boot")
    return jsonify(data) if data else (jsonify({"error": "unreachable"}), 502)


@app.route("/api/nodes/<nid>/llm")
@require_auth
def api_node_llm(nid):
    """Proxy a node's LLM-serving detection (ports + models, if any)."""
    node = _get_node(nid)
    if not node:
        return jsonify({"error": "Not found"}), 404
    data = _fetch_node(node, "llm")
    return jsonify(data) if data is not None else (jsonify({"error": "unreachable"}), 502)


@app.route("/api/nodes/<nid>/security")
@require_auth
def api_node_security(nid):
    """Proxy a node's hiddenscope security status (findings, flagged listeners)."""
    node = _get_node(nid)
    if not node:
        return jsonify({"error": "Not found"}), 404
    data = _fetch_node(node, "security")
    return jsonify(data) if data is not None else (jsonify({"error": "unreachable"}), 502)


@app.route("/api/nodes/<nid>/security/allowlist", methods=["POST"])
@require_auth
def api_node_security_allowlist_add(nid):
    """Proxy adding an entry to a node's security allowlist."""
    node = _get_node(nid)
    if not node:
        return jsonify({"error": "Not found"}), 404
    data = _fetch_node(node, "security/allowlist", method="POST", json_body=request.get_json(silent=True) or {})
    return jsonify(data) if data is not None else (jsonify({"error": "unreachable"}), 502)


@app.route("/api/nodes/<nid>/services")
@require_auth
def api_node_services(nid):
    node = _get_node(nid)
    if not node:
        return jsonify({"error": "Not found"}), 404
    data = _fetch_node(node, "services")
    return jsonify(data) if data else (jsonify({"error": "unreachable"}), 502)


@app.route("/api/nodes/<nid>/services/<svc>/<action>", methods=["POST"])
@require_auth
def api_node_service_action(nid, svc, action):
    node = _get_node(nid)
    if not node:
        return jsonify({"error": "Not found"}), 404
    data = _fetch_node(node, f"services/{svc}/{action}", method="POST")
    return jsonify(data) if data else (jsonify({"error": "unreachable"}), 502)


@app.route("/api/nodes/<nid>/storage")
@require_auth
def api_node_storage(nid):
    node = _get_node(nid)
    if not node:
        return jsonify({"error": "Not found"}), 404
    data = _fetch_node(node, "storage")
    return jsonify(data) if data else (jsonify({"error": "unreachable"}), 502)


@app.route("/api/nodes/<nid>/processes")
@require_auth
def api_node_processes(nid):
    node = _get_node(nid)
    if not node:
        return jsonify({"error": "Not found"}), 404
    data = _fetch_node(node, "processes?limit=12")
    return jsonify(data) if data else (jsonify({"error": "unreachable"}), 502)


@app.route("/api/nodes/<nid>/network")
@require_auth
def api_node_network(nid):
    node = _get_node(nid)
    if not node:
        return jsonify({"error": "Not found"}), 404
    data = _fetch_node(node, "network")
    return jsonify(data) if data else (jsonify({"error": "unreachable"}), 502)


@app.route("/api/nodes/<nid>/logs")
@require_auth
def api_node_logs(nid):
    node = _get_node(nid)
    if not node:
        return jsonify({"error": "Not found"}), 404
    data = _fetch_node(node, "logs?limit=80")
    return jsonify(data) if data else (jsonify({"error": "unreachable"}), 502)


@app.route("/api/nodes/<nid>/power/<action>", methods=["POST"])
@require_auth
def api_node_power(nid, action):
    node = _get_node(nid)
    if not node:
        return jsonify({"error": "Not found"}), 404
    if action not in ("reboot", "shutdown"):
        return jsonify({"error": "Invalid action"}), 400
    data = _fetch_node(node, f"power/{action}", method="POST")
    return jsonify(data) if data else (jsonify({"error": "unreachable"}), 502)


# ── Hub Health ──
@app.route("/api/ping")
def api_ping():
    return jsonify({"ok": True, "hub": True, "ts": time.time()})


# ═══════════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════════
_load_nodes()

if __name__ == "__main__":
    _start_poller()

    node_count = len(_get_all_nodes())
    local_ip = _get_local_ip()

    print(f"""
\033[36m╔══════════════════════════════════════════════════════════════╗
║   Sys\033[33mMonitor\033[36m Hub · Fleet Management Console                  ║
║   CoreConduit Consulting Services                              ║
╠══════════════════════════════════════════════════════════════╣\033[0m
  Aggregate dashboard for multiple SysMonitor nodes.

  Listen:     http://{HUB_CONFIG['host']}:{HUB_CONFIG['port']}
  Local IP:   {local_ip}
  Nodes:      {node_count} registered
  Polling:    every {HUB_CONFIG['poll_interval']}s
  Auth:       {'ENABLED' if HUB_CONFIG['auth_token'] else 'DISABLED'}
\033[36m╚══════════════════════════════════════════════════════════════╝\033[0m
""")

    app.run(
        host=HUB_CONFIG["host"],
        port=HUB_CONFIG["port"],
        debug=HUB_CONFIG["debug"],
    )
