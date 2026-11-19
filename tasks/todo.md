# HiddenScope extension — plan

Source: `~/Downloads/HiddenScope Extension Plan.md` (reviewed 2026-10-13), reconciled with
`~/hiddenscope-improvements.md` and the actual code. Implemented and released in v2.5.0 (P1-P4, PR #29) and v2.5.1 (P6 fixes, PR #32); P5 skipped. **Status: CLOSED.**

## Review verdict on the source doc

- **Its premise is wrong for this repo.** It assumes hiddenscope is a secret scanner wired to a
  Claude Code `PreToolUse` hook. Here it is a stdlib connection/listener monitor
  (`score_connection`, `watch`, `baseline_*`) plus a static scanner (`scan_file`, `scan_deps`)
  that already flags reverse shells, `/dev/tcp`, netcat, base64 `eval/exec`. Phase 0 is therefore
  already answered (see below).
- **Layers that don't belong in sys-monitor:** Claude Code hooks (agent-sabotage guard),
  Falco/Tetragon (kernel eBPF fleet-ops), Wazuh, NEXUS approval gateway, cc-mailrelay. None exist
  here; each is a separate project/repo. Semgrep and Canarytokens violate "stdlib-first, justify
  every dependency" for a Pi-class node agent.
- **Auto-kill tier is rejected here.** No block capability exists today; the only kill path is the
  manual, whitelisted-by-pid `DELETE /api/processes/<pid>`. Keep response = log + alert; a human
  kills. (The source doc's own OWASP guidance says the same for anything not canary-grade.)
- **Good ideas kept:** declared-baseline mindset, obfuscated-network-target static rules,
  behavioural/volume signals, canary tokens, tiered response, red-team before trusting.
- Tetragon YAML in the doc is illustrative/untested; don't copy it.

## Phase 0 — inventory (done)

Existing coverage: 14-port `SUSPICIOUS_PORTS`; `/tmp|/dev/shm` exe heuristic; `scan_file` regex set
incl. reverse-shell + base64 exec; `scan_deps`; `baseline_capture/diff` (unused by product);
`AlertTracker` + NDJSON `--log` in `cmd_watch` (CLI only, `pragma: no cover`); Hub webhook on
security transitions. Gaps: private destinations skipped (`score_connection` line ~1031), poll-only,
no first-seen signal, no deleted-exe check, no integer-encoded-IP static rule.

## Phases (each = own branch + PR; stdlib only; tests use HARNESS_ fixtures + single-seam mocks)

- [x] **P1 Wire existing code (no new detection logic)**
  - [x] Expose `baseline_capture/diff` via `/api/security/baseline` (POST capture, GET diff);
        `require_auth` on POST; fold `new_listener`/`new_external` into `get_security_status()`
  - [x] Background watcher thread in node agent reusing `AlertTracker` + append-only NDJSON log
        (path via env var, default off-path-safe); replaces stateless per-poll derivation
  - Verification: new tests; run node, capture baseline, open a listener, confirm finding
- [x] **P2 Static: obfuscated network targets** (extend `scan_file` patterns, regex not Semgrep)
  - [x] integer-encoded IP, `inet_ntoa(pack(...))`, `bytes([...]).decode`, joined-octet IPs,
        base64-decoded host feeding `connect/requests/urlopen`
  - [x] Positive + false-positive-reduction tests (test paths, docs downgrade)
  - Note: edits the "verbatim" vendored file — update its header note and CLAUDE.md in same PR
- [x] **P3 Runtime signals**
  - [x] Deleted-binary (`exe` → `(deleted)`) via `psutil` when available, degrade otherwise
  - [x] Fleet-aware internal scoring in Hub: node↔node connection on an undeclared port
        (uses `hub_nodes.json`; do NOT add platform `if`s in the node agent)
  - [x] First-seen external destination per process (builds on P1 state)
- [x] **P4 Alerting depth**
  - [x] Hub webhook payload carries finding detail (process, dest, rule), not just a boolean
        (confirm against improvements doc §4.2 before starting)
- [-] **P5 (skipped by user) Canary (opt-in, decide first):** local honeytoken file + stdlib poll/inotify-less
      access check; atime is unreliable under `relatime`, so may need `auditd` → likely out of scope
- [x] **P6 Red-team (run 2026-10-16, PR #32):** sandboxed script reproducing integer-IP / base64-host exfil; confirm P2+P3
      catch it. Never run against live power/kill routes.

## Out of repo (track separately, do not start here)

- Falco on Pi fleet / Tetragon on workstation (systemd, detection-only first)
- Claude Code `PreToolUse` blocking hook for agent writes/Bash egress
- cc-mailrelay / NEXUS approval-gateway ingestion

## Open questions

1. P1–P4 only (in-repo), or should Falco/Tetragon/hook work be scoped as sibling projects now?
2. Is P5 (canary) wanted given the `relatime` limitation?
3. Version target: one minor bump (2.5.0) after P1–P4, or per-phase patch releases?
4. Fleet-aware scoring (P3): Hub-only is assumed — OK?

---

# Release v2.6.0 — plan (2026-11-18) — SHIPPED

Scope: PRs #34–#54 on main (bf380e4), untagged since v2.5.1. Minor bump: many `feat:` PRs
(threat detection, IP blocker, quarantine, alerting, history, mDNS, /healthz, non-root units).

## Blocker found
- `release.sh` RELEASE_FILES omits `ip_block.py`, `threat_detect.py`; `install.sh` only copies
  `sys_monitor.py` + `hiddenscope_scanner.py`. `sys_monitor.py:40-47` swallows the ImportError, so
  a released install silently runs with `THREAT_AVAILABLE=False`. Also unshipped: `contrib/` is in
  the tarball but never installed by `install.sh` (blocker/non-root are opt-in scripts - OK).

## Steps (branch `fix/ship-threat-modules`, then `chore/bump-2.6.0`; PRs only, no push to main)
- [x] release.sh: add `ip_block.py`, `threat_detect.py` to RELEASE_FILES
- [x] install.sh: copy both beside `sys_monitor.py` (same optional pattern as hiddenscope)
- [x] test: tests/test_update_script.py-style check that every top-level module imported by
      sys_monitor.py is in RELEASE_FILES and copied by install.sh
- [x] PR -> merge; then `./release.sh 2.6.0 --clean` on a bump branch, PR -> merge
- [x] tag v2.6.0, `gh release create` with tarball + sha256
- [x] Verify: untar release into temp dir, confirm both modules present; `pytest`
- [x] Fleet rollout: blueberry (node+hub) and pecan (node) on v2.6.0, verified 2026-11-18
- [ ] Remaining nodes: rhubarb (on v2.4.5, reachable), cherry (ro root fs, needs fsck/SMART), keylime + potpie (sshd resets at kex)
- [ ] Gitea mirror lagging: confirm v2.6.0 tag appears on cake.local:3000/coreconduit/sys-monitor
- [ ] Wiki: create first page in GitHub UI, then ./push-wiki.sh
- [ ] Threat detector learning mode ends ~2026-11-25; review findings after

## Release-note callouts (behavior changes)
- Unknown `Host` header -> 400 (DNS-rebinding guard); set `SYSMONITOR_ALLOWED_HOSTS` / `SYSHUB_ALLOWED_HOSTS`
- Hub without token: node power routes loopback-only
- Hub registry moves to /var/lib/sys-monitor-hub/ (0600), runs as `sys-monitor-hub` user
- Token auth: 10 fails/min/IP -> 429 (node), 5/60s (hub)
