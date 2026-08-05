# Installation

## Requirements

- Python 3.11+
- Flask 3.0+ (`pip install flask`)
- systemd (for service install)
- Linux with `/proc` and `/sys` (Debian, Ubuntu Linux, or Raspberry Pi OS — same install either way)
- (Raspberry Pi only, optional) `vcgencmd`, present by default on Raspberry Pi OS, for GPU memory and undervoltage/throttle reporting

---

## One-Command Install (Recommended)

Works identically on Ubuntu/Debian or Raspberry Pi OS — hardware is auto-detected at runtime, so there's nothing to choose here. Clone the repo and run `install.sh` as root:

```bash
git clone https://github.com/bitsandbots/sys-monitor
cd sys-monitor
sudo ./install.sh
```

### Install options

| Command | What it does |
|---|---|
| `sudo ./install.sh` | Node agent only |
| `sudo ./install.sh --hub` | Node agent + Hub |
| `sudo ./install.sh --hub-only` | Hub only (no node agent) |
| `sudo ./install.sh --uninstall` | Remove everything |

The installer will:
1. Check Python 3.11+, pip3, and systemctl are present
2. Copy files to `/opt/sys-monitor`, including `hiddenscope_scanner.py` if present in the source checkout
3. Install Python dependencies via pip
4. Install and enable the systemd service
5. Wait up to 10 seconds for the health endpoint to respond

Security monitoring needs no separate install step — it's part of the same `install.sh` run. As long as `hiddenscope_scanner.py` ends up alongside `sys_monitor.py`, live connection/listener monitoring works immediately; see [[Configuration]] for the `HIDDENSCOPE_*` environment variables that tune it.

---

## Install from Release Tarball

Download a release from [GitHub Releases](https://github.com/bitsandbots/sys-monitor/releases):

```bash
curl -LO https://github.com/bitsandbots/sys-monitor/releases/download/v2.0.0/sys-monitor-2.0.0.tar.gz
# Verify checksum
curl -LO https://github.com/bitsandbots/sys-monitor/releases/download/v2.0.0/sys-monitor-2.0.0.sha256
sha256sum -c sys-monitor-2.0.0.sha256

tar -xzf sys-monitor-2.0.0.tar.gz
cd sys-monitor-2.0.0
sudo ./install.sh
```

---

## Manual Install

```bash
# Install dependency
pip3 install flask --break-system-packages

# Run directly
python3 sys_monitor.py
```

Access at `http://<node-ip>:8585`.

---

## Install as systemd Service (Manual)

```bash
sudo cp sys-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sys-monitor
```

Check status:

```bash
sudo systemctl status sys-monitor
journalctl -u sys-monitor -f
```

---

## Sudoers (Non-Root)

If running as a non-root user, grant scoped sudoers access:

```
# /etc/sudoers.d/sys-monitor
sysmonitor ALL=(ALL) NOPASSWD: /usr/bin/systemctl start ssh nginx docker ollama
sysmonitor ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop ssh nginx docker ollama
sysmonitor ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart ssh nginx docker ollama
sysmonitor ALL=(ALL) NOPASSWD: /usr/bin/systemctl enable ssh nginx docker ollama
sysmonitor ALL=(ALL) NOPASSWD: /usr/bin/systemctl disable ssh nginx docker ollama
sysmonitor ALL=(ALL) NOPASSWD: /sbin/reboot
sysmonitor ALL=(ALL) NOPASSWD: /sbin/shutdown
```

List each service explicitly — do **not** use wildcards.

---

## Uninstall

```bash
sudo ./install.sh --uninstall
```

This stops and disables both services, removes unit files, and deletes `/opt/sys-monitor`.
