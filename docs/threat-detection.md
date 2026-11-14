# Threat Detection

Log-driven detection of remote-login abuse and bot-like traffic. Detect-only:
nothing here blocks traffic (see the blocker section once enabled).

Implemented in `threat_detect.py` (stdlib only, pure detectors) and wired into
`sys_monitor.py` as the `threat-detector` background thread.

## Sources

| Source | How | Needs |
|--------|-----|-------|
| sshd | `journalctl -t sshd -t sshd-session` with a cursor file | service user in group `systemd-journal` |
| Web access logs | tail of combined-format logs (`SYSMONITOR_ACCESS_LOGS`, default `/var/log/nginx/access.log`) | read access (group `adm`) |
| SysMonitor itself | failed dashboard/API auth attempts | nothing |

Storage is the history database (`SYSMONITOR_HISTORY_DB`, or
`StateDirectory=sys-monitor`). Without it, detection is disabled.

## Detectors

| Detector | Triggers on | Severity | Blockable |
|----------|-------------|----------|-----------|
| `brute_force` | ≥6 failed logins from one IP in 120s | warning | public IPs only |
| `password_spray` | ≥4 distinct accounts from one IP in 300s | warning | public IPs only |
| `distributed_attack` | one account failed from ≥5 IPs in 600s | warning | no |
| `success_after_failures` | login succeeds after ≥3 failures from that IP | critical | no |
| `root_login` | any remote root login | critical | no |
| `new_login_pattern` | unseen source IP, first login for an account, or an hour never seen (≥10 logins of history) | warning (info while learning) | no |
| `request_burst` | ≥100 requests from one IP in 10s | warning | public IPs only |
| `web_scan` | ≥3 distinct probe paths (`.env`, `wp-login`, `.git/`…) or ≥8 401/403/404 in 60s | warning | public IPs only |
| `bot_timing` | ≥12 requests at near-constant intervals (public IPs only) | info | no |

"Blockable" means the finding is eligible for the IP blocker: only globally
routable addresses outside the allowlist. Loopback, LAN, link-local and
documentation ranges are never blockable.

The same (detector, IP) pair re-alerts at most every 10 minutes.

## Learning mode

For the first `SYSMONITOR_THREAT_LEARNING_DAYS` (default 7) days the
baseline-based detector (`new_login_pattern`) records `info` only. On the first
run the baseline is also seeded from 30 days of sshd history. Attack detectors
(brute force, spraying, scanning) are active from the start.

## Alerts

`warning` and `critical` findings are pushed through the configured webhook /
ntfy destinations immediately (not via the debounced alert state machine),
capped at `SYSMONITOR_THREAT_NOTIFY_PER_HOUR` (default 20); the rest are
counted as `suppressed` in `/api/threats`. `info` findings are stored only.

## Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `SYSMONITOR_THREAT` | `true` | Master switch |
| `SYSMONITOR_THREAT_INTERVAL` | `10` | Poll seconds |
| `SYSMONITOR_THREAT_LEARNING_DAYS` | `7` | Baseline learning window |
| `SYSMONITOR_THREAT_RETENTION_DAYS` | `30` | Finding retention |
| `SYSMONITOR_THREAT_NOTIFY_PER_HOUR` | `20` | Notification cap |
| `SYSMONITOR_ACCESS_LOGS` | `/var/log/nginx/access.log` | Comma-separated logs to tail |
| `SYSMONITOR_THREAT_ALLOWLIST` | empty | Extra IPs/CIDRs never flagged blockable |
| `SYSMONITOR_ALERT_NTFY_TOKEN` | empty | Bearer token for an authenticated ntfy server |

## API

`GET /api/threats?range=1h|6h|24h|7d|30d&ip=&severity=info|warning|critical&limit=`

Returns `{enabled, status{learning, learning_ends, last_poll, events_seen,
suppressed, problems[]}, findings[], top_offenders[]}`. `status.problems`
reports unreadable sources (e.g. missing journal access).
