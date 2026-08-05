# SysMonitor — Troubleshooting & Diagnostics

Supplement to the [wiki Troubleshooting](../wiki/Troubleshooting.md) with diagnostic procedures and common log patterns.

## Diagnostic Commands

### Quick health check

```bash
# Is the service running?
systemctl is-active sys-monitor

# Is the API responding?
curl -s http://localhost:8585/api/ping

# What does the system health endpoint say?
curl -s http://localhost:8585/api/system-health | python3 -m json.tool

# Live metrics snapshot
curl -s http://localhost:8585/api/status | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'CPU: {d[\"cpu\"][\"usage\"]}%  '
      f'Temp: {d[\"temperature\"]}C  '
      f'Mem: {d[\"memory\"][\"percent\"]}%  '
      f'Up: {d[\"uptime\"][\"formatted\"]}')"
```

### Check for system-level errors

```bash
# Recent errors in journal
journalctl -p err --since "1 hour ago" --no-pager

# Critical errors in past 7 days
journalctl -p crit --since "7 days ago" --no-pager

# SysMonitor's own logs
journalctl -u sys-monitor -n 50 --no-pager

# In-memory event log via API
curl -s http://localhost:8585/api/logs?limit=50 | python3 -m json.tool
```

## Common Log Patterns

### Harmless (expected noise)

| Pattern | Meaning | Action |
|---------|---------|--------|
| `motd-news.service: Failed to start` | Message-of-the-day fetch timed out (no network) | None — cosmetic only |
| `systemd-networkd-wait-online: Timeout occurred` | Network not ready within timeout window | None unless services depend on it |
| `sudo: conversation failed` / `auth could not identify password` | Non-TTY sudo attempt (cron job, script) | Check cron jobs use `NOPASSWD` sudoers or run as root |

### Requires attention

| Pattern | Meaning | Action |
|---------|---------|--------|
| `Out of memory` in journalctl | OOM killer was invoked | Check memory pressure; review sys-monitor's Overview tab |
| `kernel: oops` / `kernel: BUG` | Kernel fault | Investigate hardware; check `dmesg` |
| Repeated `Service restart job` in logs | systemd restart loop | Check the affected service; may need intervention |
| `sys-monitor.service: Failed with result` | SysMonitor itself crashed | Check `journalctl -u sys-monitor -n 100` |

## Verifying the Networking Detection Fix

As of v2.2.0, the `get_critical_services_status()` function selects between `systemd-networkd` and `networking` by checking which service unit actually exists on the system. Previously it checked `/etc/os-release` for a string that never appears there, causing false "networking inactive" alerts on Ubuntu 24.04.

Verify:

```bash
# After restart, this should show all_critical_ok: true on Ubuntu 24.04
curl -s http://localhost:8585/api/system-health | python3 -m json.tool
```

## Security tab shows "unavailable"

`hiddenscope_scanner.py` isn't present alongside `sys_monitor.py`, so `HIDDENSCOPE_AVAILABLE` is `False` and `/api/security` reports monitoring as unavailable instead of crashing. Copy `hiddenscope_scanner.py` into the same directory as `sys_monitor.py` (re-running `install.sh` also copies it, if present in the source checkout) and restart the service:

```bash
curl -s http://localhost:8585/api/security | python3 -m json.tool
```

## Static scan (`POST /api/security/scan`) returns 400

`HIDDENSCOPE_SCAN_PATH` isn't set on the server, or the configured path doesn't exist. Set it to a valid directory and restart:

```bash
sudo systemctl edit sys-monitor
# Environment=HIDDENSCOPE_SCAN_PATH=/opt/sys-monitor
sudo systemctl daemon-reload
sudo systemctl restart sys-monitor
```

This is intentional — the scan path can only be set server-side, never from the API or dashboard, to prevent an arbitrary-filesystem-scan vector.

## Restarting After Config Changes

```bash
# After editing sys-monitor.service or sys_monitor.py:
sudo systemctl daemon-reload
sudo systemctl restart sys-monitor

# Verify it came back:
curl -s http://localhost:8585/api/ping
```
