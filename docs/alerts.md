# Hardware Alerts & System Health

Real-time hardware monitoring with automated alerts for temperature, power issues, and system failures. These work identically on Ubuntu/Debian and Raspberry Pi — the one difference is `power_status.available`, which is only ever `true` on a Raspberry Pi (via `vcgencmd`); generic PCs/servers have no universal equivalent, so it always reports `false` there and the power alert card simply never appears. See `docs/api.md` for LLM model-serving detection (`/api/llm`), which is a separate feature from these hardware health alerts. See below for the **Security Alert** card, which is driven by the hiddenscope security integration (`/api/security`) rather than hardware health.

---

## Temperature Alerts

### Thresholds

| Level | Temperature | Action |
|-------|-------------|--------|
| **Normal** | < 70°C | No alert |
| **Warning** | 70°C - 79°C | Yellow alert card shown |
| **Critical** | 80°C - 84°C | Orange alert card shown |
| **Throttling** | ≥ 85°C | Red alert card shown + CPU frequency capped |

### Alert Message Examples

```
⚠️ Warning: CPU at 72°C — consider improving cooling
⚠️ Critical: CPU at 82°C — immediate action needed
⚠️ Throttling: CPU at 87°C — throttling active (CPU frequency capped)
```

---

## System Health Monitoring

### Critical Services Monitored

| Service | Purpose | Restart if down? |
|---------|---------|------------------|
| `systemd-journald` | System logging | No (auto-restart by systemd) |
| `dbus` | System message bus | No |
| `cron` | Scheduled tasks | No |
| `systemd-networkd` or `networking` | Network management | No |

### System Stability Checks

| Check | Detection Method | Severity |
|-------|------------------|----------|
| **OOM Events** | `journalctl -p err | grep "out of memory"` | Critical |
| **Kernel Errors** | `journalctl -p crit | tail -1` | Critical |
| **Service Restart Loops** | >5 restarts in 100 recent logs | Warning |

### Alert Examples

```
⚠️ System Health Alert:
  - Critical services down: dbus
  - Out of memory condition detected
  - Service restart loop detected (7 restarts)
```

---

## API Endpoints

### `GET /api/status`

Now includes `temperature_status` and `power_status` in the response:

```json
{
  "cpu": { "usage": 15.2, "cores": [12.3, 18.1, 14.0, 16.5], ... },
  "temperature": 52.3,
  "temperature_status": {
    "temp_c": 52.3,
    "level": "normal",
    "message": null,
    "color": "var(--green)"
  },
  "power_status": {
    "available": true,
    "undervoltage_occurred": false,
    "frequency_capped_occurred": false,
    "undervoltage_now": false,
    "frequency_capped_now": false,
    "throttled_now": false
  },
  "memory": { ... },
  "uptime": { ... }
}
```

### `GET /api/system-health`

Returns system health status and critical services status:

```json
{
  "stable": true,
  "issues": [],
  "critical_services_failed": [],
  "all_critical_ok": true
}
```

When there are issues:

```json
{
  "stable": false,
  "issues": [
    { "type": "oom", "severity": "critical", "message": "Out of memory condition detected" }
  ],
  "critical_services_failed": [
    { "name": "dbus", "state": "inactive", "critical": true }
  ],
  "all_critical_ok": false
}
```

---

## Security Alerts (new in v2.4.0)

hiddenscope, a vendored security scanner (`hiddenscope_scanner.py`), scores every active connection and listening port on each poll against a list of known-suspicious ports (Telnet, common C2 ports, Metasploit defaults, IRC, Tor control ports, NetBus, Back Orifice, and more) and suspicious process/connection combinations. Findings carry a severity of `info`, `low`, `medium`, `high`, or `critical` — live connection/listener scoring only ever produces `high` (suspicious port/process) or `info` (a plain external connection); `medium`/`critical` findings come only from the on-demand static scan (see `docs/api.md`).

### Trigger

The **Security Alert** card appears on the Overview tab whenever there's at least one "actionable" finding — a finding whose severity is `>=` `HIDDENSCOPE_MIN_SEVERITY` (default `high`). Lower the threshold to `medium` or `low` for a noisier card, or raise it to `critical` to only alert on the most severe findings. `info`-level findings never trigger the card, but remain visible via the API and behind a "show informational" toggle on the Security tab.

### Where it appears

- **Overview tab** — red **Security Alert** card, shown only when actionable findings exist; clears automatically once findings drop below the threshold
- **Security tab** (8th dashboard tab) — full breakdown: summary stats (total/external connections, total listeners, findings by severity), the findings list, flagged listeners (ports matching the suspicious-port list that aren't allowlisted, annotated `known_local_service: true` when they also match a locally-known service like LM Studio on 1234), an allowlist manager, and a button to trigger the on-demand static scan
- **Fleet Hub** — a "🛡 N security alerts" badge on any node card with actionable findings, plus a fleet-wide "Security Alerts" tile on the Hub dashboard header

If `hiddenscope_scanner.py` isn't present on a node, the Security tab reports monitoring as unavailable instead of showing any alert.

---

## Frontend Alert Cards

Four alert cards appear on the Overview tab when conditions warrant:

| Card ID | Color | Trigger |
|---------|-------|---------|
| `#power-alert-card` | Yellow/Orange/Red | Voltage or throttling issues |
| `#temp-alert-card` | Yellow/Orange/Red | Temperature warnings |
| `#health-alert-card` | Red | Service failures or system issues |
| Security Alert card | Red | Actionable hiddenscope finding (severity ≥ `HIDDENSCOPE_MIN_SEVERITY`, default `high`) |

All cards clear automatically when conditions normalize.

---

## Configuration

Temperature thresholds are configurable in `sys_monitor.py`:

```python
TEMP_WARNING = 70   # °C - Start warning
TEMP_CRITICAL = 80  # °C - Red alert
TEMP_THROTTLE = 85  # °C - CPU throttles automatically
```

To modify, edit the values in the source file and restart the service.

---

## Testing Alerts

### Simulate Temperature Alert

```bash
# Create a fake high temperature for testing (not recommended on production)
echo "90000" | sudo tee /sys/class/thermal/thermal_zone0/temp
```


---

## Logging

All alert conditions are logged to the in-memory event log:

```
[14:22:01] Temperature alert: CPU at 72°C — consider improving cooling
[14:23:15] System health: Service failed: dbus
```

View with: `/api/logs?limit=100`
