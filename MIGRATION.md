# Migration Guide: sys-monitor / rpi-monitor → unified SysMonitor v2.3.0

`sys-monitor` and `rpi-monitor` were previously two separate forks of the same project — one tuned for generic Ubuntu/Debian hosts, one tuned for Raspberry Pi. As of v2.3.0 they are a single codebase that auto-detects which platform it's running on. If you were running either fork, you can migrate to this unified build.

**`install.sh` now removes the old `rpi-monitor` fork automatically.** Every install run (`sudo ./install.sh`, with or without `--hub`) stops and disables any `rpi-monitor` / `rpi-monitor-hub` services, removes their systemd unit files, and deletes `/opt/rpi-monitor` — no manual stop/uninstall step required first. If `/opt/rpi-monitor/services.json` exists and the new install doesn't already have one at `/opt/sys-monitor/services.json`, it's carried over automatically so your monitored-service list isn't lost. This does not run under `--check` or `--uninstall`. The manual steps below are still accurate and useful if you're migrating by hand (e.g. without `install.sh`, or on a host where you want to review what's being removed first).

## What Changed

| Category | `sys-monitor` (old) | `rpi-monitor` (old) | Unified (new) |
|----------|---------------------|----------------------|---------------|
| File name | `sys_monitor.py` | `rpi_monitor.py` | `sys_monitor.py` |
| Service name | `sys-monitor` | `rpi-monitor` | `sys-monitor` |
| Hub service | `sys-monitor-hub` | `rpi-monitor-hub` | `sys-monitor-hub` |
| Install directory | `/opt/sys-monitor` | `/opt/rpi-monitor` | `/opt/sys-monitor` |
| Env var prefix | `SYSMONITOR_*` / `SYSHUB_*` | `PIMONITOR_*` / `PIHUB_*` | `SYSMONITOR_*` / `SYSHUB_*` (unchanged from `sys-monitor`) |
| Hardware detection | Generic Linux (CPU vendor/model) only | Pi model/SoC/GPU only | Both — auto-detected, no config needed |
| LLM model detection | Not present | Not present | New — see `docs/api.md` (`GET /api/llm`) |
| Fork cleanup on install | — | — | `install.sh` auto-removes a leftover `rpi-monitor` install (stop/disable/remove service, delete `/opt/rpi-monitor`, carry over `services.json`) |

If you were running the **`rpi-monitor` fork**, note the environment variable prefix change: `PIMONITOR_*` → `SYSMONITOR_*`, and `PIHUB_*` → `SYSHUB_*`. Update your systemd unit / `.env` file accordingly (see the table above).

## What Stayed the Same

- **Ports:** Node agent (8585), Hub (8686)
- **API endpoints:** All existing `/api/*` paths are unchanged and backward compatible — the only additions are `GET /api/llm` and `GET /api/nodes/<nid>/llm`
- **Web UI:** Same interface and functionality, plus the new LLM Models card/section
- **Configuration format:** Same structure (`services.json`, `hub_nodes.json`)
- **`sys-monitor` fork users:** no environment variable changes needed at all — just replace the files

---

## Migration Steps

### Option 1: Fresh Install (Recommended)

```bash
git clone https://github.com/bitsandbots/sys-monitor
cd sys-monitor
sudo ./install.sh           # node agent only
sudo ./install.sh --hub     # node agent + hub
```

`install.sh` handles the rest: it stops/disables any `rpi-monitor` / `rpi-monitor-hub` services, removes their unit files, carries over `/opt/rpi-monitor/services.json` if present (and you don't already have a `/opt/sys-monitor/services.json`), and deletes `/opt/rpi-monitor`. This installs to `/opt/sys-monitor` regardless of which fork you're migrating from — no manual backup or stop step needed.

### Option 2: Manual Migration (no `install.sh`, or reviewing before you run it)

If you're not using `install.sh` — or want to see exactly what would be removed before it happens — do it by hand:

```bash
# 1. Backup existing configuration (optional)
sudo cp /opt/sys-monitor/services.json ~/services.json.bak 2>/dev/null || true
sudo cp /opt/rpi-monitor/services.json ~/services.json.bak 2>/dev/null || true

# 2. Stop the old service(s)
sudo systemctl stop sys-monitor sys-monitor-hub rpi-monitor rpi-monitor-hub 2>/dev/null || true

# 3. Install the unified build
git clone https://github.com/bitsandbots/sys-monitor
cd sys-monitor
sudo ./install.sh

# 4. Restore your service list (if not already carried over by install.sh)
sudo cp ~/services.json.bak /opt/sys-monitor/services.json
sudo systemctl restart sys-monitor
```

### If migrating from `rpi-monitor`: update environment variables

If you had a custom systemd override or `.env` file using `PIMONITOR_*` / `PIHUB_*`, rename them to `SYSMONITOR_*` / `SYSHUB_*`:

```bash
sudo systemctl edit sys-monitor
# Replace:
#   Environment=PIMONITOR_SERVICES=...
# With:
#   Environment=SYSMONITOR_SERVICES=...
sudo systemctl daemon-reload
sudo systemctl restart sys-monitor
```

---

## Post-Migration Checklist

- [ ] Node agent accessible at `http://<ip>:8585`
- [ ] Hub accessible at `http://<ip>:8686` (if installed)
- [ ] Service running: `systemctl status sys-monitor`
- [ ] Logs showing correct version: `journalctl -u sys-monitor -f` (should say `v2.3.0`)
- [ ] Services list persisted: Check Services tab in UI
- [ ] Hardware correctly identified: Check System tab — Raspberry Pi devices should show `Platform: Raspberry Pi` with SoC/GPU fields; generic PCs should show `Platform: Linux` with DMI-derived Model
- [ ] If you run a local LLM server (Ollama, llama.cpp, etc.), it appears on the Overview tab's LLM Models card once it's serving a model

---

## Uninstalling Old Installations

`sudo ./install.sh` already does this automatically (see the note at the top of this guide). Only run these manually if you're not using `install.sh`, or want to remove the old fork without also installing the new one:

```bash
# Remove old rpi-monitor / sys-monitor directories and service files if they still exist
sudo systemctl stop rpi-monitor rpi-monitor-hub 2>/dev/null || true
sudo systemctl disable rpi-monitor rpi-monitor-hub 2>/dev/null || true
sudo rm -f /etc/systemd/system/rpi-monitor*.service
sudo rm -rf /opt/rpi-monitor
sudo systemctl daemon-reload
```

---

## Troubleshooting

### "Permission denied" on /opt/sys-monitor

Update your sudoers rules if running as non-root:

```bash
# /etc/sudoers.d/sys-monitor
sys-monitor ALL=(ALL) NOPASSWD: /usr/bin/systemctl start ssh nginx docker
sys-monitor ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop ssh nginx docker
sys-monitor ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart ssh nginx docker
sys-monitor ALL=(ALL) NOPASSWD: /usr/bin/systemctl enable ssh nginx docker
sys-monitor ALL=(ALL) NOPASSWD: /usr/bin/systemctl disable ssh nginx docker
sys-monitor ALL=(ALL) NOPASSWD: /sbin/reboot
sys-monitor ALL=(ALL) NOPASSWD: /sbin/shutdown
```

### Old service still running after upgrade

This shouldn't happen if you installed via `sudo ./install.sh` — it removes `rpi-monitor`/`rpi-monitor-hub` automatically before installing. If you migrated manually and skipped that step, or the old service uses a different name than `rpi-monitor`:

```bash
systemctl list-units | grep -E 'sys-monitor|rpi-monitor'
sudo systemctl stop rpi-monitor rpi-monitor-hub
sudo systemctl disable rpi-monitor rpi-monitor-hub
sudo rm -f /etc/systemd/system/rpi-monitor*.service
sudo systemctl daemon-reload
```

### Ollama (or another LLM server) not showing as "serving" on the dashboard

- Confirm it's actually listening: `curl http://127.0.0.1:11434/api/tags` (or `/v1/models` for OpenAI-compatible servers) should return a JSON model list.
- Confirm the port is in the recognized well-known + registered range (0-49151) — see `docs/api.md`.
- If it's on a non-standard port, add it as a monitored service with an LLM-hinting name (containing `ollama`, `llama`, `vllm`, `gpt`, `llm`, etc.) via the Services tab.

---

## Support

For issues, check:
- Wiki: https://github.com/bitsandbots/sys-monitor/wiki
- Documentation: `docs/` folder in the repository
