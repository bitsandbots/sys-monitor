#!/usr/bin/env python3
"""
SysMonitor — Unified Linux System Monitor & Service Control Console
A lightweight Flask-based dashboard for monitoring and managing Ubuntu/Debian
PCs and servers *and* Raspberry Pi boards from the same codebase. Hardware is
auto-detected at boot — Pi-specific metrics (SoC, GPU memory, undervoltage/
throttle status) appear automatically when running on a Pi, and are simply
omitted on generic Linux hardware. Reads live data from /proc, /sys, and
systemctl. Also detects common local-LLM ports (Ollama, llama.cpp, vLLM,
LM Studio, text-generation-webui, and more) and reports which model(s), if
any, each one is currently serving. Integrates the hiddenscope endpoint/
connection scanner (vendored as hiddenscope_scanner.py) to flag suspicious
external connections and listening ports directly on the dashboard.

CoreConduit Consulting Services — https://coreconduit.com
License: MIT
"""

import ipaddress
import json
import os
import re
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, render_template, request, abort

app = Flask(__name__)

VERSION = "2.4.3"

# ═══════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════
CONFIG = {
    "host": os.getenv("SYSMONITOR_HOST", "0.0.0.0"),
    "port": int(os.getenv("SYSMONITOR_PORT", "8585")),
    "debug": os.getenv("SYSMONITOR_DEBUG", "false").lower() == "true",
    "auth_token": os.getenv("SYSMONITOR_TOKEN", ""),
    "config_token": os.getenv("SYSMONITOR_CONFIG_TOKEN", ""),
    "services": [
        s.strip()
        for s in os.getenv(
            "SYSMONITOR_SERVICES",
            "ssh,nginx,docker,ollama,mosquitto,cron,avahi-daemon",
        ).split(",")
        if s.strip()
    ],
    "refresh_interval": int(os.getenv("SYSMONITOR_REFRESH", "2")),
}

# ═══════════════════════════════════════════════════════════════════════════
# Service List Persistence
# ═══════════════════════════════════════════════════════════════════════════
_SERVICES_FILE = Path(
    os.getenv(
        "SYSMONITOR_SERVICES_FILE",
        str(Path(__file__).parent / "services.json"),
    )
)


def _load_services():
    """Load the persisted service list, falling back to CONFIG defaults."""
    if _SERVICES_FILE.exists():
        try:
            data = json.loads(_SERVICES_FILE.read_text())
            if isinstance(data, list) and all(isinstance(s, str) for s in data):
                CONFIG["services"] = [s.strip() for s in data if s.strip()]
                return
        except (json.JSONDecodeError, OSError):
            pass


def _save_services():
    """Persist the current service list to disk."""
    try:
        _SERVICES_FILE.write_text(json.dumps(CONFIG["services"], indent=2) + "\n")
    except OSError as e:
        log_event(f"Failed to save services config: {e}", "error")


# Load persisted services on import (works under WSGI and __main__)
_load_services()

# ═══════════════════════════════════════════════════════════════════════════
# Boot-time System Detection (runs once at startup)
# Works on both generic Ubuntu/Debian PCs & servers and Raspberry Pi boards —
# Pi-specific fields (soc, gpu_mb, revision, is_raspberry_pi) are populated
# only when Pi hardware is actually detected; they're safely empty/None
# otherwise.
# ═══════════════════════════════════════════════════════════════════════════
_BOOT_INFO = {}

_PI_SOC_MAP = {
    "0": "BCM2835",
    "1": "BCM2836",
    "2": "BCM2837",
    "3": "BCM2711",
    "4": "BCM2712",
}


def detect_system():
    """Detect hardware at startup and cache the result."""
    global _BOOT_INFO
    model = _read_file("/proc/device-tree/model", "").rstrip("\x00")
    revision = ""
    serial = ""
    hardware = ""

    for line in _read_file("/proc/cpuinfo").splitlines():
        if line.startswith("Revision"):
            revision = line.split(":")[-1].strip()
        elif line.startswith("Serial"):
            serial = line.split(":")[-1].strip()
        elif line.startswith("Hardware"):
            hardware = line.split(":")[-1].strip()
        elif line.startswith("Model") and not model:
            model = line.split(":")[-1].strip()

    is_pi = bool(model and ("raspberry" in model.lower() or "bcm" in hardware.lower()))

    # SoC detection from revision code (Pi only)
    soc = ""
    if is_pi and len(revision) >= 6:
        try:
            proc_id = str((int(revision, 16) >> 12) & 0xF)
            soc = _PI_SOC_MAP.get(proc_id, f"BCM_unknown({proc_id})")
        except ValueError:
            pass

    # GPU memory split (Pi-specific, via vcgencmd)
    gpu_mem = _run("vcgencmd get_mem gpu 2>/dev/null | grep -oP '\\d+'") if is_pi else ""

    # System identity
    kernel = _run("uname -r")
    arch = _run("uname -m")
    hostname = _run("hostname")
    os_name = _run("lsb_release -ds 2>/dev/null")
    if not os_name:
        for line in _read_file("/etc/os-release").splitlines():
            if line.startswith("PRETTY_NAME="):
                os_name = line.split("=", 1)[-1].strip('"')
                break

    # CPU info
    cpu_model = ""
    cpu_vendor = ""
    for line in _read_file("/proc/cpuinfo").splitlines():
        if "model name" in line.lower():
            cpu_model = line.split(":")[-1].strip()
        if "vendor_id" in line.lower():
            cpu_vendor = line.split(":")[-1].strip()
    if not cpu_model:
        cpu_model = hardware or "Unknown CPU"
    cpu_max_freq = _read_file(
        "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq", ""
    )
    if cpu_max_freq:
        cpu_max_freq = f"{int(cpu_max_freq) // 1000} MHz"

    # Generic PC/server hardware identity via DMI — used when there's no
    # Raspberry Pi device-tree model string to fall back on.
    if not model:
        dmi_vendor = _read_file("/sys/devices/virtual/dmi/id/sys_vendor", "")
        dmi_product = _read_file("/sys/devices/virtual/dmi/id/product_name", "")
        model = " ".join(p for p in (dmi_vendor, dmi_product) if p).strip()

    python_ver = _run("python3 --version 2>&1 | awk '{print $2}'")

    _BOOT_INFO = {
        "platform": "raspberry_pi" if is_pi else "linux",
        "is_raspberry_pi": is_pi,
        "model": model or "Generic Linux",
        "revision": revision,
        "soc": soc,
        "gpu_mb": int(gpu_mem) if gpu_mem else None,
        "hostname": hostname,
        "kernel": kernel,
        "architecture": arch,
        "os": os_name or "Unknown",
        "cpu_model": cpu_model,
        "cpu_vendor": cpu_vendor,
        "cpu_max_freq": cpu_max_freq,
        "hardware": hardware,
        "serial": serial[-8:] if serial else "",
        "python": python_ver,
        "boot_time": datetime.now().isoformat(timespec="seconds"),
    }
    return _BOOT_INFO


# ═══════════════════════════════════════════════════════════════════════════
# Auth Middleware
# ═══════════════════════════════════════════════════════════════════════════
def require_auth(f):
    """Optional bearer-token authentication."""

    @wraps(f)
    def decorated(*args, **kwargs):
        token = CONFIG["auth_token"]
        if token:
            auth = request.headers.get("Authorization", "")
            if auth != f"Bearer {token}":
                abort(401, description="Unauthorized")
        return f(*args, **kwargs)

    return decorated


def require_config_auth(f):
    """Optional second bearer-token check for routes that mutate the
    monitored-services allowlist itself (not routes that merely control an
    already-whitelisted service). Stacks on top of require_auth rather than
    replacing it -- setting SYSMONITOR_CONFIG_TOKEN alone adds a second gate
    without weakening the first. Unset (default) = no behavior change from
    the single-token model.

    Uses a distinct X-Config-Token header rather than Authorization: a
    caller needs to present both the regular token (Authorization) and this
    one in the same request when both are configured, which isn't possible
    if they share one header -- HTTP only carries one Authorization value.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        token = CONFIG["config_token"]
        if token:
            supplied = request.headers.get("X-Config-Token", "")
            if supplied != token:
                abort(401, description="Unauthorized (config token required)")
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
# Low-level Helpers
# ═══════════════════════════════════════════════════════════════════════════
def _read_file(path: str, default: str = "") -> str:
    """Safely read a system file."""
    try:
        return Path(path).read_text().strip()
    except (FileNotFoundError, PermissionError, OSError):
        return default


def _run(cmd: str, timeout: int = 5) -> str:
    """Run a shell command and return stdout."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, Exception):
        return ""


# ═══════════════════════════════════════════════════════════════════════════
# CPU — Differential Sampling
# ═══════════════════════════════════════════════════════════════════════════
_cpu_prev = {"total": {}, "per_core": {}}


def _parse_proc_stat():
    """Parse /proc/stat into per-cpu dicts of {user, nice, system, idle, ...}."""
    result = {}
    for line in _read_file("/proc/stat").splitlines():
        if not line.startswith("cpu"):
            continue
        parts = line.split()
        name = parts[0]  # 'cpu' or 'cpu0', 'cpu1', ...
        vals = [int(v) for v in parts[1:]]
        # user, nice, system, idle, iowait, irq, softirq, steal
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        total = sum(vals)
        result[name] = {"idle": idle, "total": total}
    return result


def get_cpu_usage() -> dict:
    """CPU usage via differential /proc/stat sampling."""
    global _cpu_prev
    current = _parse_proc_stat()

    def calc_pct(name):
        prev = _cpu_prev.get(name)
        cur = current.get(name)
        if not prev or not cur:
            return 0.0
        d_total = cur["total"] - prev["total"]
        d_idle = cur["idle"] - prev["idle"]
        if d_total <= 0:
            return 0.0
        return round((1.0 - d_idle / d_total) * 100, 1)

    usage = calc_pct("cpu")
    cores = []
    i = 0
    while f"cpu{i}" in current:
        cores.append(calc_pct(f"cpu{i}"))
        i += 1

    _cpu_prev = current

    # Load averages
    load_parts = _read_file("/proc/loadavg").split()
    load_avg = [float(x) for x in load_parts[:3]] if len(load_parts) >= 3 else [0, 0, 0]

    # Current frequency
    cur_freq = _read_file("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "")
    freq_mhz = int(cur_freq) // 1000 if cur_freq else None

    return {
        "usage": usage,
        "cores": cores,
        "core_count": len(cores) or 1,
        "load_avg": load_avg,
        "freq_mhz": freq_mhz,
    }


def get_cpu_temperature() -> float:
    """CPU temperature in °C."""
    temp_str = _read_file("/sys/class/thermal/thermal_zone0/temp", "0")
    try:
        return round(int(temp_str) / 1000.0, 1)
    except ValueError:
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════
# Temperature Alerts
# ═══════════════════════════════════════════════════════════════════════════
TEMP_WARNING = 70  # °C - Start warning
TEMP_CRITICAL = 80  # °C - Red alert
TEMP_THROTTLE = 85  # °C - Pi throttles automatically


def get_temperature_status() -> dict:
    """
    Temperature with alert levels.

    Returns:
        temp_c: float - Current CPU temperature in °C
        level: 'normal' | 'warning' | 'critical' | 'throttling'
        message: str | None - Human-readable alert message
        color: str - CSS color class for UI
        throttled_status: dict | None - vcgencmd get_throttled output (Pi only)
    """
    temp = get_cpu_temperature()

    # On a Raspberry Pi, vcgencmd exposes hard throttle/undervoltage state.
    # On generic Linux this command doesn't exist, _run() returns "", and
    # throttled_status stays None — the UI simply omits it.
    throttled_raw = _run("vcgencmd get_throttled 2>/dev/null")
    throttled_status = None
    if throttled_raw and "throttled=0x" in throttled_raw:
        try:
            value = int(throttled_raw.split("=")[1].strip(), 16)
            throttled_status = {
                "undervoltage_occurred": bool(value & (1 << 0)),
                "frequency_capped_occurred": bool(value & (1 << 1)),
                "throttled_occurred": bool(value & (1 << 2)),
                "undervoltage_now": bool(value & (1 << 16)),
                "frequency_capped_now": bool(value & (1 << 17)),
                "throttled_now": bool(value & (1 << 18)),
            }
        except (ValueError, IndexError):
            pass

    if temp >= TEMP_THROTTLE:
        return {
            "temp_c": temp,
            "level": "throttling",
            "message": f"CPU at {temp}°C — system may become unstable",
            "color": "var(--red)",
            "throttled_status": throttled_status,
        }
    elif temp >= TEMP_CRITICAL:
        return {
            "temp_c": temp,
            "level": "critical",
            "message": f"CPU at {temp}°C — immediate action needed",
            "color": "var(--orange)",
            "throttled_status": throttled_status,
        }
    elif temp >= TEMP_WARNING:
        return {
            "temp_c": temp,
            "level": "warning",
            "message": f"CPU at {temp}°C — consider improving cooling",
            "color": "var(--yellow)",
            "throttled_status": throttled_status,
        }
    else:
        return {
            "temp_c": temp,
            "level": "normal",
            "message": None,
            "color": "var(--green)",
            "throttled_status": throttled_status,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Power Status (Raspberry Pi voltage/throttle monitoring)
# ═══════════════════════════════════════════════════════════════════════════
def get_power_status() -> dict:
    """
    Read Pi voltage/frequency throttle status via vcgencmd, if available.
    There's no universal equivalent for generic desktop/server Linux, so on
    non-Pi hardware this simply reports unavailable and the UI hides it.

    Returns:
        available: bool - Is power monitoring available on this hardware?
        undervoltage_occurred: bool - Has undervoltage happened?
        undervoltage_now: bool - Currently experiencing undervoltage?
        frequency_capped_occurred: bool - Has frequency been capped?
        frequency_capped_now: bool - Currently capped?
        throttled_now: bool - Currently throttled?
    """
    throttled = _run("vcgencmd get_throttled 2>/dev/null")

    if throttled and "throttled=0x" in throttled:
        try:
            value = int(throttled.split("=")[1].strip(), 16)
            return {
                "available": True,
                "undervoltage_occurred": bool(value & (1 << 0)),
                "frequency_capped_occurred": bool(value & (1 << 1)),
                "throttled_occurred": bool(value & (1 << 2)),
                "undervoltage_now": bool(value & (1 << 16)),
                "frequency_capped_now": bool(value & (1 << 17)),
                "throttled_now": bool(value & (1 << 18)),
                "throttled_raw": throttled.strip(),
            }
        except (ValueError, IndexError):
            pass

    return {
        "available": False,
        "undervoltage_occurred": False,
        "frequency_capped_occurred": False,
        "throttled_now": False,
    }


# ═══════════════════════════════════════════════════════════════════════════
# System Stability & Critical Services
# ═══════════════════════════════════════════════════════════════════════════
def get_critical_services_status() -> list:
    """
    Check if critical system services are running.

    Monitors: systemd-journald, dbus, cron, systemd-networkd (or networking)
    Returns list of failed critical services.
    """
    critical = ["systemd-journald", "dbus", "cron"]
    # Add the networking service that actually exists on this system
    if _run("systemctl is-active systemd-networkd 2>/dev/null") in ("active", "inactive"):
        critical.append("systemd-networkd")
    elif _run("systemctl is-active networking 2>/dev/null") in ("active", "inactive"):
        critical.append("networking")

    failed = []
    for svc in critical:
        active = _run(f"systemctl is-active {svc} 2>/dev/null")
        if active != "active":
            failed.append({"name": svc, "state": active or "unknown", "critical": True})
    return failed


def get_system_stability() -> dict:
    """
    Detect system-wide issues:
    - OOM killer activity
    - Kernel panics / critical errors
    - Service restart loops
    """
    issues = []

    # Check for recent OOM events
    oom_check = _run(
        "journalctl -p err -n 50 --no-pager 2>/dev/null | grep -i 'out of memory' | tail -1"
    )
    if oom_check:
        issues.append(
            {
                "type": "oom",
                "severity": "critical",
                "message": "Out of memory condition detected",
            }
        )

    # Check for kernel critical errors
    panic_check = _run("journalctl -p crit -n 20 --no-pager 2>/dev/null | tail -1")
    if panic_check and "kernel" in panic_check.lower():
        issues.append(
            {"type": "kernel", "severity": "critical", "message": panic_check[:100]}
        )

    # Check for service restart loops (>5 restarts in recent logs)
    restart_count = _run(
        "journalctl -p warning -n 100 --no-pager 2>/dev/null | grep -c 'restart job'"
    )
    try:
        restart_count = int(restart_count or 0)
    except ValueError:
        restart_count = 0

    if restart_count > 5:
        issues.append(
            {
                "type": "restart_loop",
                "severity": "warning",
                "message": f"Service restart loop detected ({restart_count} restarts)",
            }
        )

    return {"stable": len(issues) == 0, "issues": issues}


# ═══════════════════════════════════════════════════════════════════════════
# Memory
# ═══════════════════════════════════════════════════════════════════════════
def get_memory() -> dict:
    """Memory stats from /proc/meminfo."""
    info = {}
    for line in _read_file("/proc/meminfo").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            info[parts[0].rstrip(":")] = int(parts[1])

    total = info.get("MemTotal", 0)
    free = info.get("MemFree", 0)
    available = info.get("MemAvailable", 0)
    buffers = info.get("Buffers", 0)
    cached = info.get("Cached", 0)
    used = total - free - buffers - cached

    swap_total = info.get("SwapTotal", 0)
    swap_free = info.get("SwapFree", 0)

    return {
        "total_mb": round(total / 1024, 1),
        "used_mb": round(max(used, 0) / 1024, 1),
        "free_mb": round(free / 1024, 1),
        "available_mb": round(available / 1024, 1),
        "cached_mb": round(cached / 1024, 1),
        "buffers_mb": round(buffers / 1024, 1),
        "swap_total_mb": round(swap_total / 1024, 1),
        "swap_used_mb": round((swap_total - swap_free) / 1024, 1),
        "gpu_mb": _BOOT_INFO.get("gpu_mb"),
        "percent": round(max(used, 0) / total * 100, 1) if total > 0 else 0.0,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Storage
# ═══════════════════════════════════════════════════════════════════════════
def get_storage() -> list:
    """Mounted filesystem usage via df."""
    output = _run(
        "df -BM --output=source,target,size,used,avail,pcent,fstype "
        "-x devtmpfs -x squashfs -x overlay -x tmpfs 2>/dev/null"
    )
    devices = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 7 and not parts[1].startswith("/snap"):
            devices.append(
                {
                    "device": parts[0],
                    "mount": parts[1],
                    "total_mb": int(parts[2].rstrip("M")),
                    "used_mb": int(parts[3].rstrip("M")),
                    "avail_mb": int(parts[4].rstrip("M")),
                    "percent": int(parts[5].rstrip("%")),
                    "fstype": parts[6],
                }
            )
    return devices


# ═══════════════════════════════════════════════════════════════════════════
# Network — Rate Tracking
# ═══════════════════════════════════════════════════════════════════════════
_net_lock = threading.Lock()
_net_prev = {}
_net_prev_time = 0.0


def get_network() -> dict:
    """Network interfaces with throughput rates (bytes/sec)."""
    global _net_prev, _net_prev_time
    now = time.time()

    interfaces = []
    rates = {}

    net_path = Path("/sys/class/net")
    if not net_path.exists():
        return {"interfaces": [], "rates": {}}

    with _net_lock:
        elapsed = now - _net_prev_time if _net_prev_time > 0 else 1.0
        _net_prev_time = now

        for iface_dir in sorted(net_path.iterdir()):
            name = iface_dir.name
            if name == "lo":
                continue

            state = _read_file(f"/sys/class/net/{name}/operstate", "unknown")
            mac = _read_file(f"/sys/class/net/{name}/address", "—")
            ip_out = _run(
                f"ip -4 addr show {name} 2>/dev/null | grep -oP 'inet \\K[\\d.]+'"
            )
            rx = int(_read_file(f"/sys/class/net/{name}/statistics/rx_bytes", "0"))
            tx = int(_read_file(f"/sys/class/net/{name}/statistics/tx_bytes", "0"))

            prev = _net_prev.get(name, {"rx": rx, "tx": tx})
            rx_rate = max(0, round((rx - prev["rx"]) / elapsed)) if elapsed > 0 else 0
            tx_rate = max(0, round((tx - prev["tx"]) / elapsed)) if elapsed > 0 else 0
            _net_prev[name] = {"rx": rx, "tx": tx}

            interfaces.append(
                {
                    "name": name,
                    "state": state,
                    "mac": mac,
                    "ip": ip_out or "—",
                    "rx_bytes": rx,
                    "tx_bytes": tx,
                    "rx_mb": round(rx / (1024 * 1024), 2),
                    "tx_mb": round(tx / (1024 * 1024), 2),
                }
            )
            rates[name] = {"rx_rate": rx_rate, "tx_rate": tx_rate}

    return {"interfaces": interfaces, "rates": rates}


# ═══════════════════════════════════════════════════════════════════════════
# Processes
# ═══════════════════════════════════════════════════════════════════════════
def get_top_processes(limit: int = 12) -> list:
    """Top processes by CPU usage."""
    output = _run(f"ps aux --sort=-%cpu | head -n {limit + 1}")
    processes = []
    for line in output.splitlines()[1:]:
        parts = line.split(None, 10)
        if len(parts) >= 11:
            processes.append(
                {
                    "user": parts[0],
                    "pid": int(parts[1]),
                    "cpu": float(parts[2]),
                    "mem": float(parts[3]),
                    "command": parts[10][:140],
                }
            )
    return processes


def kill_process(pid: int, sig: int = 15) -> dict:
    """Send a signal to a process. Default SIGTERM (15), or SIGKILL (9)."""
    if pid <= 1:
        return {"success": False, "error": "Refusing to signal PID <= 1"}
    allowed_signals = {9, 15}
    if sig not in allowed_signals:
        return {"success": False, "error": f"Signal {sig} not allowed"}
    try:
        os.kill(pid, sig)
        return {"success": True, "pid": pid, "signal": sig}
    except ProcessLookupError:
        return {"success": False, "error": f"PID {pid} not found"}
    except PermissionError:
        # Fall back to sudo kill
        result = subprocess.run(
            ["sudo", "kill", f"-{sig}", str(pid)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return {
            "success": result.returncode == 0,
            "pid": pid,
            "signal": sig,
            "stderr": result.stderr.strip(),
        }


# ═══════════════════════════════════════════════════════════════════════════
# Uptime
# ═══════════════════════════════════════════════════════════════════════════
def get_uptime() -> dict:
    """System uptime."""
    raw = _read_file("/proc/uptime")
    if raw:
        seconds = int(float(raw.split()[0]))
        d = seconds // 86400
        h = (seconds % 86400) // 3600
        m = (seconds % 3600) // 60
        return {
            "seconds": seconds,
            "formatted": f"{d}d {h}h {m}m",
            "days": d,
            "hours": h,
            "minutes": m,
        }
    return {"seconds": 0, "formatted": "unknown", "days": 0, "hours": 0, "minutes": 0}


# ═══════════════════════════════════════════════════════════════════════════
# Service Management
# ═══════════════════════════════════════════════════════════════════════════
def get_services() -> list:
    """Get status of configured services."""
    services = []
    for svc in CONFIG["services"]:
        active_raw = _run(f"systemctl is-active {svc} 2>/dev/null")
        enabled_raw = _run(f"systemctl is-enabled {svc} 2>/dev/null")
        desc = _run(f"systemctl show {svc} --property=Description --value 2>/dev/null")
        services.append(
            {
                "name": svc,
                "active": active_raw == "active",
                "active_state": active_raw or "unknown",
                "enabled": enabled_raw == "enabled",
                "enabled_state": enabled_raw or "unknown",
                "description": desc or svc,
            }
        )
    return services


def control_service(name: str, action: str) -> dict:
    """Control a systemd service."""
    if name not in CONFIG["services"]:
        return {"success": False, "error": f"Service '{name}' not in allowed list"}

    valid_actions = {"start", "stop", "restart", "enable", "disable"}
    if action not in valid_actions:
        return {"success": False, "error": f"Invalid action: {action}"}

    try:
        result = subprocess.run(
            ["sudo", "systemctl", action, name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return {
            "success": result.returncode == 0,
            "service": name,
            "action": action,
            "stderr": result.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Timeout: systemctl {action} {name}"}


# ═══════════════════════════════════════════════════════════════════════════
# Power Controls
# ═══════════════════════════════════════════════════════════════════════════
def system_power(action: str) -> dict:
    """Reboot or shutdown."""
    if action == "reboot":
        subprocess.Popen(
            ["sudo", "reboot"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return {"success": True, "action": "reboot"}
    elif action == "shutdown":
        subprocess.Popen(
            ["sudo", "shutdown", "-h", "now"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return {"success": True, "action": "shutdown"}
    return {"success": False, "error": "Invalid power action"}


# ═══════════════════════════════════════════════════════════════════════════
# Open Ports (0-49151 — well-known + registered range; excludes the IANA
# ephemeral/dynamic port range 49152-65535 so short-lived client sockets
# don't clutter the list)
# ═══════════════════════════════════════════════════════════════════════════
# Common service name to default port mappings
_SERVICE_PORTS = {
    # Well-known network services
    "ssh": 22,
    "sshd": 22,
    "http": 80,
    "nginx": 80,
    "apache2": 80,
    "apache": 80,
    "httpd": 80,
    "https": 443,
    "ssl": 443,
    "mysql": 3306,
    "mysqld": 3306,
    "mariadb": 3306,
    "postgresql": 5432,
    "postgres": 5432,
    "redis": 6379,
    "redis-server": 6379,
    "mongodb": 27017,
    "mongod": 27017,
    "docker": 2375,
    "ftp": 21,
    "vsftpd": 21,
    "proftpd": 21,
    "dns": 53,
    "named": 53,
    "bind9": 53,
    "smtp": 25,
    "postfix": 25,
    "sendmail": 25,
    "imap": 143,
    "dovecot": 143,
    "pop3": 110,
    "ntp": 123,
    "ntpd": 123,
    "chrony": 123,
    "vnc": 5900,
    "vncserver": 5900,
    "mosquitto": 1883,
    "grafana-server": 3000,
    "grafana": 3000,
    "prometheus": 9090,
    "node_exporter": 9100,
    "nodered": 1880,
    "node-red": 1880,
    "chromadb": 8000,
    # Local LLM / AI model-serving services (see LLM_PORTS below for the
    # subset that's actively probed for a served model)
    "ollama": 11434,
    "llama-server": 8080,
    "llama.cpp": 8080,
    "llamafile": 8080,
    "lmstudio": 1234,
    "lm-studio": 1234,
    "text-generation-webui": 5000,
    "textgen-webui": 5000,
    "oobabooga": 5000,
    "koboldcpp": 5001,
    "kobold": 5001,
    "vllm": 8000,
    "localai": 8080,
    "tgi": 8080,
    "text-generation-inference": 8080,
    "gpt4all": 4891,
    "litellm": 4000,
    "openwebui": 8080,
    "open-webui": 8080,
    "jan": 1337,
    "rag-chatbot": 7860,
    # SysMonitor itself
    "sys-monitor": 8585,
    "sysmonitor": 8585,
    "sys-monitor-hub": 8686,
    "sysmonitor-hub": 8686,
    # Other homelab / custom apps — extend as needed
    "rpi-fleet": 5088,
    "coreai": 5050,
    "nexus": 8000,
    "docsync-web": 8484,
    "wiki-notebook": 5001,
    "flow-analyzer": 8090,
    "clippy": 5080,
}

# Ports above this are the IANA ephemeral/dynamic range — never relevant to
# service discovery, so we exclude them from the open-ports scan.
_MAX_SCANNED_PORT = 49151


def get_open_ports() -> list:
    """Get all listening TCP/UDP ports in the well-known + registered range."""
    ports = []
    # ss -tuln = TCP/UDP, listening, numeric ports
    # TCP uses LISTEN state, UDP uses UNCONN
    # Format: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port
    output = _run("ss -tuln 2>/dev/null | grep -E 'LISTEN|UNCONN'")
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        local = parts[4]  # Local Address:Port (index 4, not 3)
        if ":" not in local:
            continue
        # Handle IPv6 [addr]:port and IPv4 addr:port
        if local.startswith("["):
            addr_port = local.rsplit(":", 1)
            addr = addr_port[0].strip("[]") if len(addr_port) == 2 else "*"
            port_str = addr_port[1] if len(addr_port) == 2 else ""
        else:
            addr_port = local.rsplit(":", 1)
            addr = addr_port[0] or "*" if len(addr_port) == 2 else "*"
            port_str = addr_port[1] if len(addr_port) == 2 else ""
        try:
            port = int(port_str)
            if port > _MAX_SCANNED_PORT:
                continue
            netid = parts[0].lower()
            ports.append(
                {
                    "port": port,
                    "protocol": "tcp" if "tcp" in netid else "udp",
                    "address": addr if addr else "*",
                }
            )
        except ValueError:
            continue
    # Sort by port number and remove duplicates
    ports.sort(key=lambda x: (x["port"], x["protocol"]))
    # Deduplicate by (port, protocol)
    seen = set()
    unique_ports = []
    for p in ports:
        key = (p["port"], p["protocol"])
        if key not in seen:
            seen.add(key)
            unique_ports.append(p)
    return unique_ports


def get_services_with_ports() -> list:
    """Get services with port information, including unknown ports."""
    # Get configured services and their status
    services = get_services()
    ports = get_open_ports()

    # Build a map of service name -> expected port
    service_port_map = {}
    for svc in services:
        name = svc["name"].lower()
        # Check if we know the default port for this service
        for key, port in _SERVICE_PORTS.items():
            if key in name or name in key:
                service_port_map[port] = svc["name"]
                break

    # Build map of monitored services by name
    monitored = {s["name"]: s for s in services}

    # Find which ports are associated with monitored services
    ports_with_services = []
    used_ports = set()

    for port_info in ports:
        port = port_info["port"]
        # Try to find a matching service
        matching_service = None
        for svc in services:
            name_lower = svc["name"].lower()
            # Check if this service typically uses this port
            expected_port = _SERVICE_PORTS.get(name_lower)
            if expected_port == port:
                matching_service = svc["name"]
                break
            # Also check common variations
            for key, p in _SERVICE_PORTS.items():
                if p == port and (key in name_lower or name_lower in key):
                    matching_service = svc["name"]
                    break
            if matching_service:
                break

        if matching_service:
            used_ports.add(port)
            ports_with_services.append(
                {
                    **port_info,
                    "service": matching_service,
                    "known": True,
                }
            )
        else:
            ports_with_services.append(
                {
                    **port_info,
                    "service": None,
                    "known": False,
                }
            )

    # Add services that might not be listening (stopped services)
    result = []
    for svc in services:
        svc_ports = [p for p in ports_with_services if p.get("service") == svc["name"]]
        if svc_ports:
            # Use the first matching port for this service
            result.append(
                {
                    **svc,
                    "port": svc_ports[0]["port"],
                    "protocol": svc_ports[0]["protocol"],
                    "known": True,
                }
            )
        else:
            # Service not listening (stopped or no port)
            result.append(
                {
                    **svc,
                    "port": None,
                    "protocol": None,
                    "known": True,
                }
            )

    # Add unknown ports (not associated with any monitored service)
    for port_info in ports_with_services:
        if not port_info.get("service") and port_info["port"] not in used_ports:
            result.append(
                {
                    "name": None,
                    "port": port_info["port"],
                    "protocol": port_info["protocol"],
                    "address": port_info["address"],
                    "active": False,
                    "enabled": False,
                    "description": f"Port {port_info['port']}/{port_info['protocol']}",
                    "known": False,
                }
            )

    # Sort: known services first, then by port (None ports go last)
    result.sort(key=lambda x: (not x.get("known", False), x.get("port") or 99999))
    return result


# ═══════════════════════════════════════════════════════════════════════════
# LLM Model-Serving Detection
#
# Beyond just noticing that a port is open, this checks whether it's
# actually an LLM inference server and, if so, which model(s) it currently
# has loaded/available — so the dashboard can show "Ollama :11434 —
# serving llama3:8b" rather than just "port 11434 open".
# ═══════════════════════════════════════════════════════════════════════════
# Well-known local-LLM ports to actively probe when found listening. This is
# a superset hint list — probing is response-driven (see _probe_llm_port),
# so a port doesn't need to be in this table to be recognized so long as a
# monitored service name looks LLM-related (see _LLM_NAME_HINTS below).
LLM_PORTS = {
    11434: "Ollama",
    8080: "llama.cpp / LocalAI / TGI / OpenWebUI",
    1234: "LM Studio",
    5000: "text-generation-webui",
    5001: "KoboldCpp",
    8000: "vLLM",
    4891: "GPT4All",
    4000: "LiteLLM",
    1337: "Jan.ai",
    7860: "Gradio UI (text-generation-webui / RAG chatbot)",
}

_LLM_NAME_HINTS = (
    "ollama",
    "llama",
    "gpt",
    "llm",
    "vllm",
    "kobold",
    "localai",
    "lmstudio",
    "lm-studio",
    "textgen",
    "text-generation",
    "tgi",
    "litellm",
    "jan",
    "chatbot",
    "rag",
    "openwebui",
    "open-webui",
)


def _http_get_json(url: str, timeout: float = 1.2):
    """GET a URL and parse the JSON body. Returns None on any failure —
    connection refused, timeout, non-200 status, or non-JSON body."""
    try:
        req = urllib.request.Request(
            url, headers={"Accept": "application/json", "User-Agent": "SysMonitor/2.3"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            return json.loads(resp.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None


def _probe_llm_port(port: int) -> dict:
    """
    Probe a listening port to see whether it's serving an LLM API and,
    if so, which model(s) are currently loaded/available.

    Tries the Ollama native API first (/api/tags), then the OpenAI-
    compatible /v1/models endpoint used by llama.cpp, vLLM, LocalAI,
    LM Studio, text-generation-webui, TGI, LiteLLM, GPT4All, and others.
    """
    base = f"http://127.0.0.1:{port}"

    data = _http_get_json(f"{base}/api/tags")
    if isinstance(data, dict) and isinstance(data.get("models"), list):
        models = [
            m.get("name") or m.get("model")
            for m in data["models"]
            if isinstance(m, dict) and (m.get("name") or m.get("model"))
        ]
        if models:
            return {"serving": True, "api": "ollama", "models": models}

    data = _http_get_json(f"{base}/v1/models")
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        models = [
            m.get("id")
            for m in data["data"]
            if isinstance(m, dict) and m.get("id")
        ]
        if models:
            return {"serving": True, "api": "openai-compatible", "models": models}

    return {"serving": False, "api": None, "models": []}


def get_llm_services() -> list:
    """
    Detect common LLM-serving ports among currently listening ports and,
    for each one found, check whether it's actively serving a model.

    Returns a list of:
        port: int, label: str, serving: bool, api: str | None,
        models: list[str]
    """
    open_ports = {p["port"] for p in get_open_ports()}
    candidates = {port: label for port, label in LLM_PORTS.items() if port in open_ports}

    # Also probe the port of any monitored service whose name looks
    # LLM-related, even if its port isn't in the well-known LLM_PORTS list
    # above (e.g. a custom LLM server run on a non-standard port).
    for svc in CONFIG["services"]:
        name_l = svc.lower()
        if any(hint in name_l for hint in _LLM_NAME_HINTS):
            port = _SERVICE_PORTS.get(name_l)
            if port and port in open_ports and port not in candidates:
                candidates[port] = svc

    results = []
    for port, label in sorted(candidates.items()):
        probe = _probe_llm_port(port)
        results.append({"port": port, "label": label, **probe})

    return results


# ═══════════════════════════════════════════════════════════════════════════
# Security Monitoring — hiddenscope integration
#
# hiddenscope (github.com/coreconduit/hiddenscope) is a stdlib-only Linux
# endpoint/connection scanner: it scores active external connections and
# listening ports against known C2/backdoor indicators (Metasploit, NetBus,
# Back Orifice, Tor, ADB, etc.), and can optionally static-scan a directory
# for embedded secrets/reverse-shell patterns. It's vendored unmodified as
# `hiddenscope_scanner.py` alongside this file — no extra dependency beyond
# stdlib, matching SysMonitor's own "reads /proc, /sys, and shells out to
# standard tools" philosophy. If that file is missing, every security
# feature here degrades to "unavailable" rather than erroring.
# ═══════════════════════════════════════════════════════════════════════════
try:
    import hiddenscope_scanner as _hs

    HIDDENSCOPE_AVAILABLE = True
except ImportError:  # pragma: no cover — optional companion file
    _hs = None
    HIDDENSCOPE_AVAILABLE = False

# Minimum severity (info|low|medium|high|critical) that counts as
# "actionable" for the dashboard alert card. Live connection scoring only
# ever produces "high" (suspicious port/exe) or "info" (plain external
# connection), so "high" is the meaningful cutoff; static scans can also
# surface "medium"/"critical" findings (e.g. embedded credentials).
HIDDENSCOPE_MIN_SEVERITY = os.getenv("HIDDENSCOPE_MIN_SEVERITY", "high")

# Fixed, server-configured directory for the optional on-demand static scan.
# Intentionally NOT taken from the API request — accepting an arbitrary
# filesystem path from the web UI would turn "scan for secrets" into a
# path-traversal / DoS vector. Empty (default) disables the static-scan
# endpoint entirely.
HIDDENSCOPE_SCAN_PATH = os.getenv("HIDDENSCOPE_SCAN_PATH", "").strip()

_HS_ALLOWLIST_FILE = Path(
    os.getenv(
        "HIDDENSCOPE_ALLOWLIST_FILE",
        str(Path(__file__).parent / "hiddenscope_allowlist.json"),
    )
)


def _load_hs_allowlist():
    """Load the persisted suppression allowlist (ports/procs/networks)."""
    al = _hs.AllowList()
    if _HS_ALLOWLIST_FILE.exists():
        try:
            data = json.loads(_HS_ALLOWLIST_FILE.read_text())
            al.procs = {str(p).lower() for p in data.get("procs", [])}
            al.ports = {int(p) for p in data.get("ports", [])}
            al.url_domains = {str(d).lower() for d in data.get("url_domains", [])}
            for net_str in data.get("networks", []):
                try:
                    al.networks.append(ipaddress.ip_network(net_str, strict=False))
                except ValueError:
                    pass
        except (json.JSONDecodeError, OSError, ValueError):
            pass
    return al


def _save_hs_allowlist(al) -> None:
    """Persist the suppression allowlist to disk."""
    try:
        data = {
            "procs": sorted(al.procs),
            "ports": sorted(al.ports),
            "networks": [str(n) for n in al.networks],
            "url_domains": sorted(al.url_domains),
        }
        _HS_ALLOWLIST_FILE.write_text(json.dumps(data, indent=2) + "\n")
    except OSError as e:
        log_event(f"Failed to save security allowlist: {e}", "error")


def get_security_status() -> dict:
    """
    Live security monitoring via the vendored hiddenscope scanner: scores
    every active external (non-private) connection and every listening
    socket against known C2/backdoor indicators.

    Returns:
        available: bool - False if hiddenscope_scanner.py / `ss` is missing
        findings: list[dict] - every scored finding (info severity included)
        actionable_count: int - findings at/above HIDDENSCOPE_MIN_SEVERITY
        flagged_listeners: list[dict] - listening ports matching known-bad
            port numbers (informational — a locally-run dev tool can
            legitimately use one of these ports)
        summary: dict - connection/listener counts, findings by severity
    """
    if not HIDDENSCOPE_AVAILABLE:
        return {
            "available": False,
            "findings": [],
            "actionable_count": 0,
            "flagged_listeners": [],
            "summary": {},
        }

    al = _load_hs_allowlist()
    conns = _hs._connections()
    listeners = _hs._listeners()

    findings = [f for f in (_hs.score_connection(c, al) for c in conns) if f]

    # Cross-reference listening ports against known-bad port numbers.
    # A hit here is informational, not proof of compromise — e.g. LM Studio
    # defaults to port 1234, which hiddenscope also flags as "Common C2".
    # We annotate (not suppress) when the port matches a SysMonitor-known
    # local service so the dashboard can show "expected" vs. "unexpected".
    known_local_ports = set(_SERVICE_PORTS.values())
    flagged_listeners = []
    for l in listeners:
        port = l.get("port")
        if port in _hs.SUSPICIOUS_PORTS and port not in al.ports:
            flagged_listeners.append(
                {
                    "port": port,
                    "proc": l.get("proc"),
                    "pid": l.get("pid"),
                    "iface": l.get("iface"),
                    "label": _hs.SUSPICIOUS_PORTS[port],
                    "known_local_service": port in known_local_ports,
                }
            )

    threshold = _hs._sev(HIDDENSCOPE_MIN_SEVERITY)
    actionable = [f for f in findings if _hs._sev(f.severity) >= threshold]

    return {
        "available": True,
        "findings": [f.to_dict() for f in findings],
        "actionable_count": len(actionable),
        "flagged_listeners": flagged_listeners,
        "summary": {
            "total_connections": len(conns),
            "external_connections": sum(
                1 for c in conns if c.get("rip") and not _hs.is_private(c["rip"])
            ),
            "total_listeners": len(listeners),
            "findings_by_severity": {
                s: sum(1 for f in findings if f.severity == s) for s in _hs.SEV_LEVELS
            },
        },
    }


def run_security_scan(path: Path) -> list:
    """Run hiddenscope's static scanner (embedded secrets, reverse-shell
    patterns, suspicious source) over a fixed directory. Returns a list of
    finding dicts."""
    al = _load_hs_allowlist()
    findings = list(_hs.scan_tree(path, al=al, quiet=True))
    return [f.to_dict() for f in findings]


# ═══════════════════════════════════════════════════════════════════════════
# System Errors (journalctl)
# ═══════════════════════════════════════════════════════════════════════════
def get_system_errors(limit: int = 50) -> list:
    """Get recent error-level journal entries."""
    errors = []
    # -p err = priority error and below, --no-pager
    output = _run(
        f"journalctl -p err -n {min(limit, 200)} --no-pager -o json 2>/dev/null || "
        f"journalctl -p err -n {min(limit, 200)} --no-pager 2>/dev/null"
    )
    if not output:
        return errors
    for line in output.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
            ts_raw = data.get("__REALTIME_TIMESTAMP", "")
            # Convert microseconds timestamp to readable
            if ts_raw and ts_raw.isdigit():
                ts_usec = int(ts_raw)
                ts = datetime.fromtimestamp(ts_usec / 1_000_000).strftime("%H:%M:%S")
            else:
                ts = ""
            errors.append(
                {
                    "ts": ts,
                    "unit": data.get(
                        "_SYSTEMD_UNIT", data.get("SYSLOG_IDENTIFIER", "system")
                    ),
                    "msg": data.get("MESSAGE", ""),
                    "priority": data.get("PRIORITY", "3"),
                }
            )
        except json.JSONDecodeError:
            # Plain text fallback
            if line.strip():
                errors.append(
                    {
                        "ts": "",
                        "unit": "system",
                        "msg": line.strip(),
                        "priority": "3",
                    }
                )
    return errors


# ═══════════════════════════════════════════════════════════════════════════
# Event Log (in-memory ring buffer)
# ═══════════════════════════════════════════════════════════════════════════
_log_lock = threading.Lock()
_event_log = []
LOG_MAX = 200


def log_event(msg: str, level: str = "info"):
    """Append an event to the in-memory log."""
    with _log_lock:
        _event_log.append(
            {
                "ts": datetime.now().strftime("%H:%M:%S"),
                "msg": msg,
                "level": level,
            }
        )
        if len(_event_log) > LOG_MAX:
            del _event_log[: len(_event_log) - LOG_MAX]


def get_log(limit: int = 100) -> list:
    with _log_lock:
        return list(_event_log[-limit:])


# ═══════════════════════════════════════════════════════════════════════════
# API Routes
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return render_template("index.html", config=CONFIG, boot=_BOOT_INFO, version=VERSION)


@app.route("/api/ping")
def api_ping():
    """Health check for connection-lost detection."""
    return jsonify({"ok": True, "ts": time.time()})


@app.route("/api/boot")
@require_auth
def api_boot():
    """Static boot-time hardware detection info."""
    return jsonify(_BOOT_INFO)


@app.route("/api/status")
@require_auth
def api_status():
    """Primary polling endpoint — fast-changing metrics."""
    net = get_network()
    temp_status = get_temperature_status()
    power_status = get_power_status()
    return jsonify(
        {
            "cpu": get_cpu_usage(),
            "temperature": get_cpu_temperature(),
            "temperature_status": temp_status,
            "power_status": power_status,
            "memory": get_memory(),
            "uptime": get_uptime(),
            "network_rates": net["rates"],
            "timestamp": time.time(),
        }
    )


@app.route("/api/storage")
@require_auth
def api_storage():
    return jsonify(get_storage())


@app.route("/api/network")
@require_auth
def api_network():
    return jsonify(get_network())


@app.route("/api/processes")
@require_auth
def api_processes():
    limit = request.args.get("limit", 12, type=int)
    return jsonify(get_top_processes(limit=min(limit, 50)))


@app.route("/api/processes/<int:pid>", methods=["DELETE"])
@require_auth
def api_kill_process(pid):
    sig = request.args.get("signal", 15, type=int)
    result = kill_process(pid, sig)
    if result["success"]:
        log_event(f"Killed PID {pid} (signal {sig})", "warning")
    return jsonify(result), 200 if result["success"] else 400


@app.route("/api/services")
@require_auth
def api_services():
    return jsonify(get_services())


@app.route("/api/services-with-ports")
@require_auth
def api_services_with_ports():
    """Return services merged with port information."""
    return jsonify(get_services_with_ports())


@app.route("/api/services/<name>/<action>", methods=["POST"])
@require_auth
def api_service_control(name, action):
    result = control_service(name, action)
    level = "success" if result["success"] else "error"
    log_event(
        f"Service {action}: {name} — {'OK' if result['success'] else result.get('error','failed')}",
        level,
    )
    return jsonify(result), 200 if result["success"] else 400


# ── Service List CRUD ──
@app.route("/api/services/config", methods=["GET"])
@require_auth
def api_services_config():
    """Return the raw list of configured service names."""
    return jsonify(CONFIG["services"])


@app.route("/api/services/config", methods=["POST"])
@require_auth
@require_config_auth
def api_services_add():
    """Add a service to the monitored list."""
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"success": False, "error": "Service name required"}), 400
    if not re.match(r"^[a-zA-Z0-9@._:-]+$", name):
        return jsonify({"success": False, "error": "Invalid service name"}), 400
    if name in CONFIG["services"]:
        return jsonify({"success": False, "error": f"'{name}' already monitored"}), 409
    CONFIG["services"].append(name)
    _save_services()
    log_event(f"Service added to monitor list: {name}", "success")
    return (
        jsonify({"success": True, "service": name, "services": CONFIG["services"]}),
        201,
    )


@app.route("/api/services/config/<svc>", methods=["DELETE"])
@require_auth
@require_config_auth
def api_services_remove(svc):
    """Remove a service from the monitored list."""
    if svc not in CONFIG["services"]:
        return jsonify({"success": False, "error": f"'{svc}' not in list"}), 404
    CONFIG["services"].remove(svc)
    _save_services()
    log_event(f"Service removed from monitor list: {svc}", "warning")
    return jsonify({"success": True, "service": svc, "services": CONFIG["services"]})


@app.route("/api/services/config/<svc>", methods=["PUT"])
@require_auth
@require_config_auth
def api_services_rename(svc):
    """Rename/replace a service entry in the monitored list."""
    data = request.get_json(silent=True) or {}
    new_name = data.get("name", "").strip()
    if not new_name:
        return jsonify({"success": False, "error": "New name required"}), 400
    if not re.match(r"^[a-zA-Z0-9@._:-]+$", new_name):
        return jsonify({"success": False, "error": "Invalid service name"}), 400
    if svc not in CONFIG["services"]:
        return jsonify({"success": False, "error": f"'{svc}' not in list"}), 404
    if new_name in CONFIG["services"]:
        return jsonify({"success": False, "error": f"'{new_name}' already exists"}), 409
    idx = CONFIG["services"].index(svc)
    CONFIG["services"][idx] = new_name
    _save_services()
    log_event(f"Service renamed: {svc} -> {new_name}", "success")
    return jsonify(
        {"success": True, "old": svc, "new": new_name, "services": CONFIG["services"]}
    )


@app.route("/api/power/<action>", methods=["POST"])
@require_auth
def api_power(action):
    if action not in ("reboot", "shutdown"):
        return jsonify({"success": False, "error": "Invalid action"}), 400
    log_event(f"Power: {action} initiated", "warning")
    result = system_power(action)
    return jsonify(result)


@app.route("/api/logs")
@require_auth
def api_logs():
    limit = request.args.get("limit", 100, type=int)
    include_system = request.args.get("system", "false").lower() == "true"
    events = get_log(limit)
    if include_system:
        system_errors = get_system_errors(limit)
        # Merge and sort by timestamp
        combined = events + [
            {"ts": e["ts"], "msg": f"[{e['unit']}] {e['msg']}", "level": "error"}
            for e in system_errors
            if e.get("msg")
        ]
        # Sort by timestamp (events have HH:MM:SS format)
        combined.sort(key=lambda x: x.get("ts", ""))
        return jsonify(combined[-limit:])
    return jsonify(events)


@app.route("/api/ports")
@require_auth
def api_ports():
    """Return all listening TCP/UDP ports in the well-known + registered range."""
    return jsonify(get_open_ports())


@app.route("/api/llm")
@require_auth
def api_llm():
    """
    Detect common local-LLM ports (Ollama, llama.cpp, vLLM, LM Studio,
    text-generation-webui, and more) among currently listening ports, and
    report whether each one is actively serving a model — and which.
    """
    return jsonify(get_llm_services())


@app.route("/api/security")
@require_auth
def api_security():
    """
    Live security status via the vendored hiddenscope scanner: suspicious
    external connections, flagged listening ports, and severity summary.
    Reports {"available": false} if hiddenscope_scanner.py isn't present.
    """
    return jsonify(get_security_status())


@app.route("/api/security/allowlist", methods=["GET"])
@require_auth
def api_security_allowlist_get():
    """Return the current security allowlist (suppressed ports/procs/networks)."""
    if not HIDDENSCOPE_AVAILABLE:
        return jsonify({"procs": [], "ports": [], "networks": [], "url_domains": []})
    al = _load_hs_allowlist()
    return jsonify(
        {
            "procs": sorted(al.procs),
            "ports": sorted(al.ports),
            "networks": [str(n) for n in al.networks],
            "url_domains": sorted(al.url_domains),
        }
    )


@app.route("/api/security/allowlist", methods=["POST"])
@require_auth
def api_security_allowlist_add():
    """
    Add an entry to the security allowlist to suppress future findings for
    a known-safe port, process name, or IP/CIDR — e.g. a locally-run dev
    tool that happens to use a port hiddenscope flags as suspicious.
    """
    if not HIDDENSCOPE_AVAILABLE:
        return jsonify({"success": False, "error": "hiddenscope not available"}), 400
    data = request.get_json(silent=True) or {}
    al = _load_hs_allowlist()
    added = []

    if data.get("port") not in (None, ""):
        try:
            port = int(data["port"])
            al.ports.add(port)
            added.append(f"port {port}")
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "invalid port"}), 400

    if data.get("proc"):
        proc = str(data["proc"]).strip().lower()
        al.procs.add(proc)
        added.append(f"proc {proc}")

    if data.get("network"):
        try:
            net = ipaddress.ip_network(str(data["network"]).strip(), strict=False)
            al.networks.append(net)
            added.append(f"network {net}")
        except ValueError:
            return jsonify({"success": False, "error": "invalid IP/CIDR"}), 400

    if not added:
        return (
            jsonify({"success": False, "error": "provide port, proc, or network"}),
            400,
        )

    _save_hs_allowlist(al)
    log_event(f"Security allowlist: added {', '.join(added)}", "info")
    return jsonify({"success": True, "added": added}), 201


@app.route("/api/security/allowlist", methods=["DELETE"])
@require_auth
def api_security_allowlist_remove():
    """Remove an entry (port, proc, or network) from the security allowlist."""
    if not HIDDENSCOPE_AVAILABLE:
        return jsonify({"success": False, "error": "hiddenscope not available"}), 400
    data = request.get_json(silent=True) or {}
    al = _load_hs_allowlist()
    removed = []

    if data.get("port") not in (None, ""):
        try:
            port = int(data["port"])
            if port in al.ports:
                al.ports.discard(port)
                removed.append(f"port {port}")
        except (ValueError, TypeError):
            pass

    if data.get("proc"):
        proc = str(data["proc"]).strip().lower()
        if proc in al.procs:
            al.procs.discard(proc)
            removed.append(f"proc {proc}")

    if data.get("network"):
        net_str = str(data["network"]).strip()
        before = len(al.networks)
        al.networks = [n for n in al.networks if str(n) != net_str]
        if len(al.networks) < before:
            removed.append(f"network {net_str}")

    if not removed:
        return jsonify({"success": False, "error": "entry not found"}), 404

    _save_hs_allowlist(al)
    log_event(f"Security allowlist: removed {', '.join(removed)}", "warning")
    return jsonify({"success": True, "removed": removed})


@app.route("/api/security/scan", methods=["POST"])
@require_auth
def api_security_scan():
    """
    Run an on-demand static scan (embedded secrets, reverse-shell patterns)
    over a fixed, server-configured directory (HIDDENSCOPE_SCAN_PATH). The
    path is never taken from the request — only a server operator can
    choose what gets scanned, since accepting an arbitrary filesystem path
    from the web UI would be a path-traversal / resource-exhaustion risk.
    """
    if not HIDDENSCOPE_AVAILABLE:
        return jsonify({"success": False, "error": "hiddenscope not available"}), 400
    if not HIDDENSCOPE_SCAN_PATH:
        return (
            jsonify(
                {
                    "success": False,
                    "error": "HIDDENSCOPE_SCAN_PATH is not configured on this node",
                }
            ),
            400,
        )
    path = Path(HIDDENSCOPE_SCAN_PATH)
    if not path.exists():
        return jsonify({"success": False, "error": f"scan path not found: {path}"}), 400
    try:
        findings = run_security_scan(path)
    except Exception as e:  # defensive: never let a scan crash the node agent
        log_event(f"Security scan failed: {e}", "error")
        return jsonify({"success": False, "error": str(e)}), 500
    level = "warning" if findings else "success"
    log_event(f"Security scan of {path}: {len(findings)} finding(s)", level)
    return jsonify({"success": True, "path": str(path), "findings": findings})


@app.route("/api/system-health")
@require_auth
def api_system_health():
    """Return system health status: critical services and stability checks."""
    critical_services = get_critical_services_status()
    stability = get_system_stability()
    return jsonify(
        {
            "stable": stability["stable"],
            "issues": stability["issues"],
            "critical_services_failed": critical_services,
            "all_critical_ok": len(critical_services) == 0,
        }
    )


@app.route("/api/system-errors")
@require_auth
def api_system_errors():
    """Return recent error-level journal entries."""
    limit = request.args.get("limit", 50, type=int)
    return jsonify(get_system_errors(limit))


# ═══════════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    info = detect_system()

    # Seed the CPU differential sampler
    _parse_proc_stat()
    time.sleep(0.1)

    marker = "RASPBERRY PI" if info["is_raspberry_pi"] else "LINUX"

    log_event("SysMonitor starting...")
    log_event(f"Platform: {marker} — {info['model']}")
    if info["soc"]:
        log_event(f"SoC: {info['soc']} | Arch: {info['architecture']}")
    log_event(f"Hostname: {info['hostname']} | Kernel: {info['kernel']}")
    log_event(f"CPU: {info['cpu_model']} | Arch: {info['architecture']}")
    log_event(f"OS: {info['os']}")
    log_event(f"Services configured: {len(CONFIG['services'])}")
    log_event(
        f"Security monitoring (hiddenscope): "
        f"{'ENABLED — min severity ' + HIDDENSCOPE_MIN_SEVERITY if HIDDENSCOPE_AVAILABLE else 'UNAVAILABLE (hiddenscope_scanner.py not found)'}"
    )
    log_event(f"Listening on http://{CONFIG['host']}:{CONFIG['port']}")
    log_event("SysMonitor ready.", "success")

    print(f"""
\033[36m╔══════════════════════════════════════════════════╗
║   Sys\033[33mMonitor\033[36m · v{VERSION}  [{marker}]{" " * max(0, 16 - len(marker))}║
║   CoreConduit Consulting Services                 ║
╠══════════════════════════════════════════════════╣\033[0m
  Device:   {info['model']}
  CPU:      {info['cpu_model']}
  SoC:      {info.get('soc') or '—'}
  Kernel:   {info['kernel']}
  OS:       {info['os']}
  Auth:     {'ENABLED' if CONFIG['auth_token'] else 'DISABLED'}
  Config token: {'ENABLED' if CONFIG['config_token'] else 'DISABLED'}
  Security: {'hiddenscope active' if HIDDENSCOPE_AVAILABLE else 'hiddenscope unavailable'}
  Services: {len(CONFIG['services'])} configured
  Listen:   http://{CONFIG['host']}:{CONFIG['port']}
\033[36m╚══════════════════════════════════════════════════╝\033[0m
""")

    app.run(host=CONFIG["host"], port=CONFIG["port"], debug=CONFIG["debug"])
