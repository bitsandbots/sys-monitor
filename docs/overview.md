# SysMonitor — Overview

## Purpose

SysMonitor is a lightweight, self-hosted system monitoring and management console for Ubuntu/Debian PCs & servers **and** Raspberry Pi boards — one codebase, auto-detecting which platform it's on. It provides a real-time web dashboard for viewing hardware metrics, controlling systemd services, inspecting running processes, issuing power commands, and spotting locally-served LLM models — all without requiring cloud connectivity.

## Goals

- **Zero cloud dependency** — runs entirely on-device; no telemetry, no external APIs.
- **Low overhead** — reads directly from `/proc` and `/sys`; no heavy agent or daemon.
- **One codebase, any Debian-family host** — hardware (and Pi-specific sensors) are auto-detected at startup; the same install works on a headless Ubuntu server or a Raspberry Pi without any flags or config changes.
- **Operational control** — start/stop/restart services and send signals to processes from the browser.
- **AI-aware** — detects common local-LLM ports (Ollama, llama.cpp, vLLM, LM Studio, and more) and reports which model each one is actually serving, not just that the port is open.
- **Security-aware** — integrates hiddenscope, a vendored stdlib-only Linux security scanner, to score live connections/listeners for known-suspicious ports and processes, and to run on-demand static scans for hardcoded secrets and reverse-shell patterns.
- **Multi-node fleet management** — the optional Hub component aggregates any number of SysMonitor nodes — mixed Ubuntu and Pi fleets included — into a single pane of glass, including which nodes are serving LLM models and which have active security alerts.
- **Secure by default** — optional bearer-token authentication; systemd hardening via `ProtectSystem`, `PrivateTmp`, `ProtectHome`.
- **Hardware health monitoring** — real-time alerts for temperature, power (undervoltage on Pi), and system failures.
- **Firewall-aware** — install script automatically opens required ports via ufw or firewalld.
- **Offline fonts** — self-hosted WOFF2 fonts; no CDN or internet dependency for the dashboard.

## v2.4.0 — New Features

### Security Monitoring (hiddenscope)

| Feature | Description |
|---------|--------------|
| **Vendored scanner** | [hiddenscope](https://coreconduit.com) (MIT, same author) is copied unmodified into the project as `hiddenscope_scanner.py` — a stdlib-only Linux security scanner, not a pip dependency |
| **Live connection/listener scoring** | Every poll scores active outbound connections and listening ports against known-suspicious ports (Telnet, common C2 ports, Metasploit defaults, IRC, Tor control ports, NetBus, Back Orifice, and more) and flags suspicious process/connection combos |
| **Dashboard visibility** | A red "Security Alert" card appears on the Overview tab when actionable findings exist; a full **Security** tab lists findings by severity, flagged listeners, and an allowlist manager |
| **On-demand static scan** | `POST /api/security/scan` runs hiddenscope's secret/reverse-shell detector against a server-configured directory (`HIDDENSCOPE_SCAN_PATH`) — never a client-supplied path |
| **Fleet-wide** | The Hub polls every node's `/api/security` and shows a "🛡 N security alerts" badge across the fleet grid, plus a dashboard-wide "Security Alerts" tile |
| **Graceful degradation** | If `hiddenscope_scanner.py` isn't installed, security monitoring simply reports "unavailable" rather than breaking anything else |

## v2.3.0 — Previous Features

### Unified Ubuntu + Raspberry Pi Support

SysMonitor and the earlier RPiMonitor fork are now the same codebase. `detect_system()` checks for Raspberry Pi hardware (device-tree model, `BCM` hardware string) at startup; when found, it decodes the SoC from the revision code and reads GPU memory split and undervoltage/throttle status via `vcgencmd`. On generic PCs and servers, it instead reads DMI vendor/product identification. Every other feature is identical across both.

### LLM Model-Serving Detection

| Feature | Description |
|---------|-------------|
| **Port recognition** | Recognizes Ollama, llama.cpp/llamafile, vLLM, LM Studio, text-generation-webui, KoboldCpp, LocalAI, TGI, LiteLLM, GPT4All, Jan.ai, and gradio chat UIs |
| **Live model check** | Queries each candidate port's API to confirm it's actually serving a model (not just that the port is open), and which one(s) |
| **Dashboard visibility** | A "🧠 LLM Models" card appears on the Overview tab whenever a model is being served; full detail lives on the Services tab |
| **Fleet-wide** | The Hub polls every node's `/api/llm` and shows a "serving" badge across the fleet grid |

## v2.2.0 — Previous Features

### Hardware Alerts

SysMonitor now includes real-time hardware health monitoring with automated alerts:

| Feature | Description |
|---------|-------------|
| **Temperature Alerts** | Automatic warnings at 70°C (warning), 80°C (critical), and 85°C (throttling) |
| **Service Failure Detection** | Monitors critical services (systemd-journald, dbus, cron) and reports failures |
| **System Stability Checks** | Detects OOM events, kernel errors, and service restart loops |

Alerts appear as cards on the Overview tab and clear automatically when conditions normalize.

## Components

| Component | Entry Point | Default Port | Role |
|-----------|------------|-------------|------|
| **Node Agent** | `sys_monitor.py` | `8585` | Per-device monitor & control API |
| **Fleet Hub** | `hub/sys_monitor_hub.py` | `8686` | Multi-node aggregation dashboard |

A node agent runs on every device you want to monitor. The hub is optional and typically runs on one machine that can reach all nodes over the network.

## License

MIT — open source, no restrictions on personal or commercial use.
