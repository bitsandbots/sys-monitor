# SysMonitor v2.4.0 — Gap Analysis & Improvement Scoping

**Scope:** sys_monitor.py (node agent), hub/sys_monitor_hub.py (Fleet Hub), templates/index.html, hub/templates/hub.html, hiddenscope_scanner.py (vendored), install/update/release scripts, systemd units, and the docs/wiki tree.

**Method:** six focused code-reading passes (feature completeness, security, testing, deployment/ops, code quality, documentation accuracy), each grounded in specific file/line citations rather than the README's self-description. Findings below are what was actually verified in the code as of this build.

**Headline:** the project is functionally rich and well-documented for a single-developer, LAN-trusted tool, but it has three categories of real risk before it should run unattended anywhere less trusted than a home network: **the Hub has no authentication enforcement at all**, **CSRF is trivially exploitable when a token isn't set (the shipped default)**, and **there is no automated test suite or CI gate**, so every fix so far has depended on manual verification.

---

## 1. Security posture

| # | Finding | Severity | Where |
|---|---|---|---|
| 1 | **Hub enforces no authentication on any route.** `HUB_CONFIG["auth_token"]` is read from `SYSHUB_TOKEN` and printed in the startup banner, but no `require_auth`-equivalent decorator exists anywhere in `hub/sys_monitor_hub.py`. Anyone who can reach port 8686 can add/remove nodes or trigger `POST /api/nodes/<nid>/power/reboot` on any registered node with zero credentials, token set or not. | **Critical** | `hub/sys_monitor_hub.py` (no auth check on any route) |
| 2 | **CSRF is exploitable by design when no token is set — the out-of-box default.** `.env.example` ships `SYSMONITOR_TOKEN=` (empty); `require_auth` skips all checks when the token is falsy. There's no CSRF token, no Origin/Referer check, no CORS lockdown. A plain auto-submitting `<form method="POST" action="http://node:8585/api/power/reboot">` on any webpage a LAN user visits triggers a reboot with no interaction needed. | **Critical** | `sys_monitor.py:203-215`, `.env.example:15` |
| 3 | **Service allowlist is self-extensible, defeating its own purpose.** `POST /api/services/config` lets any caller (unauthenticated by default) add an arbitrary systemd unit name to the monitored list, then immediately control it via `/api/services/<name>/<action>`. The "whitelist" provides no real containment once it can be mutated by the same caller. | High | `sys_monitor.py:1480-1498`, `:720` |
| 4 | **Process-kill can hit any PID via a `sudo kill` fallback.** `kill_process()` only blocks PID ≤ 1 and non-{9,15} signals; on `PermissionError` it shells to `sudo kill`, which always succeeds since the service already runs as root — including against `sshd` or other system daemons. | High | `sys_monitor.py:648-673` |
| 5 | Bearer token comparison uses `!=` rather than `hmac.compare_digest` — theoretically timing-attackable over a fast LAN. | Medium | `sys_monitor.py:211` |
| 6 | No rate limiting anywhere (`flask-limiter` absent from both `requirements.txt`s) — power/kill/service-control endpoints can be hit unlimited times, enabling brute-force of a weak token or a DoS reboot-loop. | Medium | both `requirements.txt` |
| 7 | No TLS/HTTPS story — both apps call `app.run()` with no `ssl_context`; tokens travel in cleartext with no documented reverse-proxy pattern. | Medium | `sys_monitor.py:1801`, `hub/sys_monitor_hub.py:611` |
| 8 | Hub persists per-node bearer tokens in plaintext in `hub_nodes.json`, and `install.sh` never `chmod`s any data file. | Medium | `hub/sys_monitor_hub.py:94-109` |
| 9 | Both systemd units run `User=root`; the node unit sets `NoNewPrivileges=false` (required only because `system_power()` needlessly shells to `sudo reboot` while already root); the **Hub unit has no hardening directives at all**. | Medium | `sys-monitor.service:28`, `hub/sys-monitor-hub.service` |
| 10 | `install.sh` opens firewall ports (ufw/firewalld) unconditionally during install, before the operator is ever prompted to set a token. | Low | `install.sh:54-72` |

**What's already solid:** `HIDDENSCOPE_SCAN_PATH` is correctly server-env-only and never accepted from a request (closes a real path-traversal vector); `control_service()` validates `action` against a fixed set, so arbitrary `systemctl` subcommands aren't reachable.

## 2. Deployment & operational readiness

| # | Finding | Impact | Where |
|---|---|---|---|
| 1 | **Hub poller can silently die under load.** `_poller_loop()` wraps only `f.result()` in try/except, not the `as_completed(..., timeout=10)` iterator itself. Since each node poll makes up to 4 sequential calls at a 4s default timeout, one slow node can blow the 10s window, raising an uncaught `TimeoutError` that kills the poller thread — with no watchdog to restart it. Dashboard data goes stale until a full Hub restart. | High | `hub/sys_monitor_hub.py:240-254` |
| 2 | Poller concurrency is hard-capped at `min(len(node_ids), 8)` regardless of fleet size — a 50+ node fleet takes multiple sequential batches per cycle, so data staleness (and the crash risk above) gets worse exactly as the fleet scales, which is the Hub's core use case. | High | `hub/sys_monitor_hub.py:247` |
| 3 | No resource limits (`MemoryMax`, `CPUQuota`, `TasksMax`) on either systemd unit — on a 1-4GB Pi, a leak or a heavy static scan has nothing capping it from OOMing the whole board. | Medium | both `.service` files |
| 4 | Event log is in-memory only (`LOG_MAX = 200`), never written to stdout/journal — a crash loses all operational history; there's nothing for post-mortem debugging beyond the one-time startup banner. | Medium | `sys_monitor.py:1357-1368` |
| 5 | Flask dev server (Werkzeug) runs directly in production, no gunicorn/waitress, no `threaded=True` — requests serialize under load, worst on the Hub's own per-node AJAX fan-out. | Medium | both `app.run()` calls |
| 6 | Decommissioned nodes are never cleaned up — no TTL/staleness pruning exists; only a manual DELETE removes a node, so a churning fleet accumulates dead entries forever. | Low-Medium | `hub/sys_monitor_hub.py` (no TTL logic) |
| 7 | No startup config validation — an empty-string token silently disables auth with no persistent warning; an invalid `HIDDENSCOPE_MIN_SEVERITY` silently falls back to the most permissive threshold ("info") rather than erroring. | Low-Medium | `sys_monitor.py:209`, `hiddenscope_scanner.py:120-121` |
| 8 | `update.sh` has no rollback: if `pip3 install` fails mid-update, the old process keeps running from now-stale-on-disk code, then crash-loops on next restart. No snapshot of `$INSTALL_DIR` is taken before overwrite. | Medium | `update.sh:190-191`, `install.sh:171-192` |
| 9 | Only liveness signal is unauthenticated `/api/ping` — fine for a basic uptime check, but no deeper `/healthz` (e.g. "is the poller thread alive," which would have caught #1 automatically). | Low | `sys_monitor.py:1384-1387` |

**Verified fixed, not a gap:** an earlier pass of this analysis flagged `services.json` as unconditionally overwritten on every `update.sh` run. Re-checked against the current tree — `install.sh:228` guards the default-seed copy with `[[ -f "$INSTALL_DIR/services.json" ]] ||`, and the legacy-migration copy at `install.sh:197-200` has the same guard. `update.sh` never touches the file directly; it only invokes `install.sh`. No overwrite path exists in the current code.

## 3. Feature gaps vs. mature monitoring platforms

Benchmarked informally against tools in this space (Netdata, Prometheus+Grafana, Zabbix, Uptime Kuma, Glances).

- **No historical/time-series persistence** — metrics live only in per-browser JS arrays (60 samples at 2s ≈ 2 minutes), lost on reload. Nothing writes to sqlite/InfluxDB/Prometheus/RRD. Can't answer "what happened last night." **Large effort.**
- **No outbound alerting** — every "alert" only toggles a dashboard card's CSS. No webhook/email/Slack/PagerDuty notifier exists; if nobody has the tab open, a downed node or 90°C CPU goes unnoticed. **Medium effort.**
- **No container/Docker monitoring** — `docker` appears only as a service-name string and a port-map entry; nothing touches the Docker socket. **Medium-large effort.**
- **No GPU monitoring beyond Pi VideoCore memory** — no `nvidia-smi`/`rocm-smi` integration, notable given this tool explicitly targets local-LLM hosts, which are often GPU-equipped desktops. **Medium effort.**
- **No disk I/O or network error-rate metrics** — storage only reports capacity (`df`); network only tracks byte counters, never `rx_errors`/`tx_errors`/drops from sysfs (a one-read-away addition). **Small-medium effort.**
- **No config backup/export/import** — three flat JSON files with no export/import path; losing disk means manually re-adding every node/service/allowlist entry.
- **No API rate limiting** (ties to security finding #6 above).
- **Discovery is a manual, single-subnet scan** — no mDNS/Avahi/SSDP support despite `avahi-daemon` being a default monitored service; nodes on other subnets are invisible unless added by IP.
- **No multi-user/RBAC** — one shared token, no viewer-vs-admin distinction.
- Mobile responsiveness is *already* handled (viewport meta + media queries) — not a gap.

## 4. Testing maturity

**No automated test suite exists anywhere in the repo** — confirmed via exhaustive glob for test files, and no CI config of any kind (no `.github/workflows`, no `tox.ini`, no `Makefile`). `release.sh`'s only gate before packaging is a clean git tree; it runs no compile check, lint, or test command. Verification throughout this project's history has been manual and ad hoc (`py_compile`, curl smoke tests) rather than persisted as a re-runnable suite.

Concrete gaps, roughly ordered by risk if left uncovered:

1. `/proc` parsing (CPU/memory/uptime) — a kernel format change would silently break metrics with nothing to catch it. (~1 day)
2. LLM-detection probing logic — needs mocked HTTP responses per backend signature. (~1 day)
3. hiddenscope integration glue (`get_security_status`, allowlist load/save, `HIDDENSCOPE_AVAILABLE=False` degrade path). (~0.5-1 day)
4. The vendored `hiddenscope_scanner.py` itself — allowlist matching and severity scoring are untested. (~1-2 days)
5. Hub polling/proxy/aggregation logic — directly relevant given the poller-crash bug found above; a test would have caught it. (~1 day)
6. A regression guard for the port-range constant (`_MAX_SCANNED_PORT`) — this exact bug class (cap at 9999 excluding Ollama's 11434) already shipped once before this project's v2.3.0 fix. (~0.5 day)
7. No CI running `py_compile`/lint on every change — currently entirely manual. (~0.5 day)
8. No fixtures for Pi vs. generic-PC `/proc` trees to exercise both hardware-detection branches. (~0.5-1 day)

**Rough total to reach baseline coverage** (core parsing/detection unit tests + a CI gate): ~6-9 developer-days. Frontend/JS testing and full Hub integration tests are separable follow-on work.

Two planning docs already exist in the repo and should be the starting point rather than scoping this from scratch: `docs/TESTING_STRATEGY_TEMPLATE-v2.md` and `docs/blueprint-testing-prompts-v2.md`.

## 5. Code quality & maintainability

- **No linter/formatter/type-checker config anywhere** (no `.flake8`, `pyproject.toml`, `.eslintrc`, `mypy.ini`) — nothing enforces style or catches regressions automatically.
- `templates/index.html` has grown to ~850 lines of embedded JS plus ~420 lines of CSS inside a Jinja template with no bundler/linting/IDE support — the "no build step" approach is past the point where it's still comfortable to maintain.
- `index.html` and `hub.html` are two independently maintained copies of the same design system — the majority of CSS custom properties are duplicated verbatim and have already begun drifting rather than sharing a common stylesheet.
- `hiddenscope_scanner.py` is a frozen, unmodified 2,353-line vendor copy with no update mechanism (no submodule, no version pin file, no diff-against-upstream script) — any upstream fix requires manual re-vendoring, and nothing flags staleness.
- Error-response shape is inconsistent across the API (`{"error": ...}` vs. `{"success": False, "error": ...}` vs. bespoke shapes) — no shared error-envelope helper.
- Only 5 of 26 routes/helpers have explicit `try/except`; most fall through to Flask's default 500 on an unexpected exception rather than a controlled JSON error.
- Type hints are partial (52/62 functions have return annotations, few have parameter annotations) and unenforced — no mypy config to make them mean anything.
- Scattered magic numbers (assorted inline timeouts, `_MAX_SCANNED_PORT`, port-map dicts) live in source rather than the existing `CONFIG` object, which is already env-driven for other settings.

## 6. Documentation accuracy

The recent docs/wiki update for the hiddenscope integration is largely accurate — route inventory, config defaults, troubleshooting guidance, and version numbers all checked out correctly against the code. One real defect found, duplicated in two places:

- **`POST`/`DELETE /api/security/allowlist` request and response shapes are documented incorrectly** in both `docs/api.md` and `wiki/API-Reference.md`. The docs show a `{"type": "port"|"proc"|"network", "value": ...}` body and an `{"allowlist": {...}}` response; the actual code reads `data.get("port")`/`data.get("proc")`/`data.get("network")` directly and returns `{"success": true, "added": [...]}` / `{"success": true, "removed": [...]}`. A user following the documented curl example would get a 400 error. **Trivial fix, ~15 minutes, but worth doing before anyone relies on it.**

---

## Prioritized improvement backlog

**P0 — fix before this runs anywhere beyond a fully trusted home LAN:**
1. Add authentication enforcement to the Hub (mirror `sys_monitor.py`'s `require_auth` pattern across all Hub routes).
2. Add CSRF protection (SameSite cookies / custom header requirement / Origin check) so state-changing routes aren't exploitable via a plain form POST when no token is configured — or make an empty token a documented "read-only demo mode" instead of full control.
3. Fix the Hub poller's uncaught `TimeoutError` (wrap the `as_completed` iterator, add a watchdog that restarts the poller thread if it dies).

**P1 — high-value, moderate effort:**
4. Correct the `/api/security/allowlist` docs (trivial).
5. Constrain the self-extensible service allowlist (e.g. require a separate, more-privileged action to add new services vs. control existing ones).
6. Stand up a minimal test suite + CI gate for `/proc` parsing, LLM detection, and hiddenscope glue (items 1-3, 6-7 from Section 4) — this is the highest-leverage single investment, since it would have caught both the poller bug and the docs mismatch automatically.
7. Add basic outbound alerting (webhook at minimum) so alerts aren't limited to "someone has the tab open."
8. Scale the Hub's poller concurrency with fleet size, or convert to an async/streaming model instead of a fixed 8-worker cap.

**P2 — solid next-phase work:**
9. Historical metrics persistence (even a lightweight sqlite ring buffer would unlock trend views).
10. Rate limiting on power/kill/service-control endpoints.
11. Resource limits + full systemd hardening on both units; drop the unnecessary `sudo reboot`/`sudo shutdown` shell-out now that the service already runs as root, which would let `NoNewPrivileges=true` be restored.
12. Node TTL/pruning in the Hub.
13. Disk I/O and network error-rate metrics (low effort, sysfs data is already one read away).

**P3 — larger roadmap items, scope when there's demand:**
14. Container/Docker monitoring.
15. GPU monitoring (nvidia-smi/rocm-smi) for LLM-host nodes.
16. Multi-user/RBAC auth.
17. mDNS/Avahi-based discovery.
18. Shared CSS/JS between `index.html` and `hub.html`, and a longer-term look at whether the single-file-no-build-step approach still fits at current size.

---

*This analysis is based on static code reading, not a penetration test or load test — treat severity ratings as directional. Six parallel review passes were run against the codebase at /tmp/work/unified/sys-monitor/; each finding above cites the specific file/function it was verified against. That checkout can drift from the `sys-monitor` repo itself — one finding in an earlier version of this doc (a `services.json` overwrite bug) turned out to already be fixed here. Re-diff findings against current HEAD before treating this backlog as final; a 2026-08-05 pass re-verified every P0/P1 item and the Section 6 docs mismatch directly against this repo and confirmed them accurate, with that one correction applied.*
