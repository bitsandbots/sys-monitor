# SysMonitor Wiki

> Lightweight, self-hosted system monitor and service console for Ubuntu/Debian PCs, servers, *and* Raspberry Pi boards — one codebase, auto-detected hardware.

**Version:** v2.4.0 · **License:** MIT · **Author:** [CoreConduit Consulting Services](https://coreconduit.com)

---

## What is SysMonitor?

SysMonitor is a zero-dependency (Flask only), single-file Flask dashboard that turns any Linux system into a remotely observable node. It reads live data directly from `/proc` and `/sys` — no agents, no psutil, no cloud. It runs unmodified on generic Ubuntu/Debian hosts and Raspberry Pi boards alike, auto-detecting which one it's on and exposing Pi-specific sensors (SoC, GPU memory, undervoltage/throttle) only where they apply.

It also detects common local-LLM ports (Ollama, llama.cpp, vLLM, LM Studio, and more) and shows which model each one is actively serving, right on the dashboard.

It vendors [hiddenscope](https://coreconduit.com), a stdlib-only Linux security scanner (same author), to score live connections and listeners for known-suspicious ports/processes and to run on-demand static scans for hardcoded secrets and reverse-shell patterns — surfaced via a Security Alert card and a dedicated Security tab.

The **Hub** (`sys_monitor_hub.py`) adds a fleet layer: discover nodes on your network, view aggregate metrics, control services, and see which nodes are serving LLM models or have active security alerts — all from one dashboard, across mixed Ubuntu/Pi fleets.

```
Browser
  │
  ├─► Node Agent :8585  ─► /proc, /sys, systemctl
  │
  └─► Hub :8686  ─►  Node A :8585
                  ─►  Node B :8585
                  ─►  Node N :8585
```

---

## Pages

| Page | Description |
|---|---|
| [[Installation]] | One-command and manual install, systemd setup, uninstall |
| [[Configuration]] | All environment variables for node agent and hub |
| [[API Reference]] | Full REST API docs for node agent and hub |
| [[Architecture]] | Data flows, design decisions, key components |
| [[Hub Setup]] | Multi-node fleet management walkthrough |
| [[Release Guide]] | How to version, package, and tag a release |
| [[Troubleshooting]] | Common issues and fixes |

---

## Quick Start

```bash
git clone https://github.com/bitsandbots/sys-monitor
cd sys-monitor
sudo ./install.sh
```

Open `http://<node-ip>:8585`

---

## Repository

**GitHub:** https://github.com/bitsandbots/sys-monitor
