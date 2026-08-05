# Troubleshooting

## Service won't start

**Check logs first:**

```bash
journalctl -u sys-monitor -n 50 --no-pager
```

Common causes:

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: flask` | Flask not installed | `pip3 install flask --break-system-packages` |
| `Permission denied` on `/proc/...` | Running in restricted sandbox | Check `ProtectSystem=` in the unit file |
| `Address already in use` | Port 8585 taken | Change `SYSMONITOR_PORT` or stop the conflicting process |
| `python3: not found` | Python not installed | `sudo apt install python3` |

---

## Dashboard shows stale data / no data

- Check the browser console for failed XHR requests to `/api/status`
- Confirm the service is running: `systemctl status sys-monitor`
- Verify the node's IP and port: `curl http://localhost:8585/api/ping`
- If behind a firewall: `sudo ufw allow 8585/tcp`

---

## CPU usage shows 0% or 100%

The node agent uses **differential sampling** — it computes CPU% from the delta between two `/proc/stat` reads. On the very first poll after startup there is no previous reading, so CPU shows 0%. This corrects itself on the second poll (within `SYSMONITOR_REFRESH` seconds).

---

## Temperature reads as `null`

`/sys/class/thermal/thermal_zone0/temp` doesn't exist on all hardware. This is normal on some Linux machines and VMs. The dashboard handles `null` gracefully.

---

## Service control returns 401

`SYSMONITOR_TOKEN` is set but the request didn't include the `Authorization: Bearer` header. The web UI does not send auth headers — use a reverse proxy with basic auth for UI-level authentication.

---

## `systemctl` commands fail (Permission denied)

The service is running as a non-root user without sudoers rules. Add scoped rules — see [[Installation#Sudoers (Non-Root)]].

---

## Hub shows all nodes as offline

1. Check hub logs: `journalctl -u sys-monitor-hub -n 50`
2. Verify nodes are reachable from the hub machine: `curl http://<node-ip>:8585/api/ping`
3. Check `SYSHUB_TIMEOUT` — increase if nodes are on a slow network
4. If nodes require auth tokens, verify they're set in `hub_nodes.json` or via `PUT /api/nodes/<nid>`

---

## Hub discovery finds nothing

- Confirm nodes are running: `systemctl status sys-monitor` on each node
- Verify the subnet matches your network (e.g. `192.168.1.0/24` vs `10.0.0.0/24`)
- Check `SYSHUB_DISCOVERY_PORT` matches `SYSMONITOR_PORT` on nodes (both default to `8585`)
- Firewall: ensure port 8585 is open between the hub and the node subnet

---

## `release.sh` fails: "Working tree is dirty"

Commit or stash all changes before cutting a release:

```bash
git stash
./release.sh 2.1.0
git stash pop
```

Or use `--dry-run` to preview without the clean-tree requirement.

---

## `/proc/device-tree/model` not found

Normal on Linux systems. Hardware detection uses standard `/proc` and `/sys` interfaces. All monitoring features work normally.

---

## High memory usage on the hub

Each registered node keeps a cached status dict in memory — the hub is very lightweight. If you're seeing actual high memory, check for runaway Flask debug reloaders (`SYSHUB_DEBUG=false`).

---

## Viewing live logs

```bash
# Node agent
journalctl -u sys-monitor -f

# Hub
journalctl -u sys-monitor-hub -f

# In-memory event log via API
curl http://localhost:8585/api/logs | python3 -m json.tool
```

---

## My LLM server isn't showing as "serving" on the dashboard

- Check `curl http://127.0.0.1:8585/api/llm` directly — it lists every candidate port SysMonitor found and whether each is serving.
- Confirm the server actually responds to `/api/tags` (Ollama) or `/v1/models` (OpenAI-compatible servers like llama.cpp, vLLM, LM Studio, text-generation-webui) with a non-empty model list — `curl http://127.0.0.1:<port>/v1/models`.
- If it's running on a non-standard port not in the `LLM_PORTS` table (`sys_monitor.py`), add it as a monitored service with a name containing an LLM hint (`ollama`, `llama`, `vllm`, `gpt`, `llm`, etc.) so it gets probed anyway.
- A port below 49151 that never responds to either API is reported as open but not serving — this is expected for non-LLM services that happen to share a common LLM port number.

## Security tab shows "unavailable"

`hiddenscope_scanner.py` isn't present alongside `sys_monitor.py` on that node, so `HIDDENSCOPE_AVAILABLE` is `False` and `/api/security` reports monitoring as unavailable instead of erroring. Copy `hiddenscope_scanner.py` into the install directory (re-running `install.sh` also copies it, if present in the source checkout) and restart the service.

## Static scan returns 400

`POST /api/security/scan` returns `400` when `HIDDENSCOPE_SCAN_PATH` is unset or the configured directory doesn't exist. Set it on the server (never accepted from the API or dashboard, by design — see [[Architecture]]) and restart:

```bash
sudo systemctl edit sys-monitor
# Environment=HIDDENSCOPE_SCAN_PATH=/opt/sys-monitor
sudo systemctl daemon-reload
sudo systemctl restart sys-monitor
```

## Raspberry Pi shows `Platform: Linux` instead of `Platform: Raspberry Pi`

`detect_system()` checks `/proc/device-tree/model` and `/proc/cpuinfo`'s `Hardware` line. This can come back empty inside some containers or chroots even on real Pi hardware — run SysMonitor directly on the host (not inside Docker without `--privileged` or bind-mounting `/proc`) to get accurate detection.
