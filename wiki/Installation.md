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

## Non-Root Node Agent

The node agent runs as `root` by default. To run it unprivileged with scoped sudo:

```bash
sudo contrib/install-nonroot.sh                 # after install.sh
contrib/install-nonroot.sh --print-sudoers      # preview, no root needed
sudo systemctl restart sys-monitor
```

It creates the `sys-monitor` user, a systemd drop-in, `/var/lib/sys-monitor` for the files
the agent writes, and `/etc/sudoers.d/sys-monitor` with one exact line per action and
service (re-run it after changing the monitored services). Don't hand-write the rules: a
bare `systemctl` entry is root, and on systemd hosts a bare `reboot`/`shutdown` entry lets
sudo run any `systemctl` command because they are the same file.

Trade-off: unprivileged, other users' sockets show no process names on the Security tab
unless you enable the drop-in's commented `AmbientCapabilities=` line.

The Fleet Hub always runs as the unprivileged `sys-monitor-hub` user; its registry is
`/var/lib/sys-monitor-hub/hub_nodes.json` (0600) and `install.sh` migrates an old one.

---

## Uninstall

```bash
sudo ./install.sh --uninstall
```

This stops and disables both services, removes unit files, and deletes `/opt/sys-monitor`.
