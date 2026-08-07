# Testing Strategy — SysMonitor

> Filled in from `docs/TESTING_STRATEGY_TEMPLATE-v2.md` for this project specifically. That
> template (and its companion `docs/blueprint-testing-prompts-v2.md`) is generic — written for
> projects with a formal blueprint/acceptance-spec system, AI-generated components, and/or
> multi-agent coordination. SysMonitor is none of those: a single-repo, stdlib-first Flask tool
> with two apps. Sections below that don't apply are marked N/A with one line of reasoning,
> per the template's own instruction to do that rather than force-fill placeholder values.
>
> Last reviewed: 2026-08-07 by Claude (sys-monitor session)

## Gap-analysis backlog tracking

`docs/sysmonitorgapanalysis.md` §4 lists 8 concrete testing gaps. Status as of this doc:

| # | Item | Status |
|---|---|---|
| 1 | `/proc` parsing (CPU/memory/uptime) | **Done** — `tests/test_proc_parsing.py` |
| 2 | LLM-detection probing (mocked HTTP) | **Done** — `tests/test_llm_detection.py` |
| 3 | hiddenscope integration glue | Deferred — follow-up PR |
| 4 | `hiddenscope_scanner.py` internals | Deferred — follow-up PR (lowest priority per the doc itself) |
| 5 | Hub polling/proxy/aggregation logic | Deferred — follow-up PR |
| 6 | Port-range regression guard (`_MAX_SCANNED_PORT`) | **Done** — `tests/test_llm_detection.py` |
| 7 | CI running `py_compile`/tests on every change | **Done** — `.github/workflows/ci.yml` |
| 8 | Pi vs. generic-PC `/proc` fixtures | **Done** — `tests/fixtures/proc/` |

Items 3, 4, 5 cover the Hub (`hub/sys_monitor_hub.py`) and the vendored `hiddenscope_scanner.py` —
deliberately out of scope for this pass to keep it one coherent, reviewable PR touching only the
node agent. Same pattern as every other change already shipped to this repo.

## 1. Definition of Done

A change to this project is considered properly tested when:
- [ ] New `/proc`-parsing or hardware/service-detection logic has a unit test in `tests/`.
- [ ] Any bugfix ships with a regression test that fails without the fix — e.g.
      `test_max_scanned_port_includes_ollama` reproduces the exact bug class that already shipped
      once (port cap excluding Ollama's 11434).
- [ ] Anything that shells out or reads `/proc`/`/sys` is tested via the `_read_file`/`_run` mock
      seams (see "Why this is testable" below), never against the real filesystem/process table.
- [ ] `python3 -m py_compile sys_monitor.py hub/sys_monitor_hub.py hiddenscope_scanner.py` and
      `python3 -m pytest tests/` both pass — enforced by CI on every push/PR to `main`.
- [ ] No test invokes `kill_process()`, `control_service()`, or `system_power()` unmocked, and
      none makes a real outbound HTTP request. (See the incident this rule comes from: a prior
      verification script rebooted the real `blueberry` host twice by hitting `/api/power/reboot`
      on an unmocked app object.)

This project has no formal blueprint/acceptance-spec system — its spec is `README.md` and
`docs/api.md`. The template's Section 2 (Blueprint & Acceptance Spec) is N/A for that reason.

## 2. Blueprint & Acceptance Spec

N/A — no formal blueprint system. `README.md` (feature list) and `docs/api.md` (request/response
shapes) serve this role informally.

## 3. Workflow / Multi-Step Completion Coverage

This project doesn't have long multi-step user workflows in the sense the template means (job
submission → processing → notify, etc.). The closest analog is the Hub's poll → cache → serve
cycle (`_poller_loop()` → `_poll_node()` → in-memory `_nodes` cache → `/api/fleet`), which is
explicitly deferred (gap-analysis item 5) to the follow-up Hub test PR.

## 4. Regression Suite

- Framework: `pytest` (9.0.3), plus `pytest-flask` and `pytest-mock` — see `requirements-dev.txt`.
- Location: `tests/`.
- Rule: no bugfix merges without a regression test reproducing the original bug. Concrete example
  already in the suite: `test_max_scanned_port_includes_ollama`.
- No property-based/snapshot testing yet — the input space for the current test surface (fixed
  `/proc` formats, fixed JSON API shapes) doesn't need it. Worth revisiting if `hiddenscope`
  allowlist matching (item 4) gets covered, since that has a larger input space.

## 5. Integration Contracts

| Talks to | Mechanism | Contract defined at | Consumer tests | Provider tests | Status |
|---|---|---|---|---|---|
| Fleet Hub ↔ node agent | HTTP (`requests`, JSON) | `docs/api.md` | — | — | Deferred (item 5) |
| Node agent ↔ local LLM servers | HTTP (`urllib`), Ollama/OpenAI-compatible shapes | `sys_monitor.py::_probe_llm_port` | `tests/test_llm_detection.py` | — (external servers, not ours to test) | **Covered** |

## 6. Evals (AI-generated / AI-assisted components)

N/A — this codebase has no AI-generated or AI-assisted runtime components. (The *development*
process has used AI assistance, per this repo's commit history, but that's a development-process
fact, not a component of the shipped software the template's eval framework is meant for.)

## 7. Suite Trust: Mutation Testing & Flaky Test Management

Not adopted yet. At the current coverage level (2 of 8 gap-analysis test areas), mutation testing
would mostly measure gaps we already know about from the tracking table above — not worth the
tooling overhead until coverage is broader. Revisit once items 3/4/5 land.

No flaky tests currently — everything in `tests/` is pure parsing logic or fully mocked I/O, no
timing dependencies, no real network/filesystem/process access.

## 8. Performance & Load Benchmarks

N/A for this pass — nothing in the current test surface is performance-sensitive enough to
benchmark. The Hub's poller concurrency (`SYSHUB_POLL_MAX_WORKERS`) would be the first real
candidate if this section gets adopted later, once Hub tests (item 5) exist.

## 9. Security & Dependency Scanning

Not wired into CI yet. A cheap, high-value future addition: `pip-audit` as a CI step (would have
flagged nothing new here, but low-cost to add later). Out of scope for this pass — flagging it
rather than silently skipping.

## 10. Non-Determinism & Fault Injection

N/A — deleted per the template's own instruction. This project doesn't coordinate multiple
agents/services in a way that requires fault-injection testing; the Hub is a simple poll/cache/
proxy, not a coordination system.

## 11. Test Harness

- Single entrypoint: `python3 -m pytest tests/`
- Not containerized — matches this project's no-Docker, stdlib-first posture (`CLAUDE.md`).
- Host prerequisites: Python 3.11+ (matches `README.md`'s stated floor), `pip install -r
  requirements-dev.txt`.
- Runs identically on any Linux host, including the real Raspberry Pi this suite was developed and
  verified on — the `_read_file`/`_run` mock seams (see below) mean it never depends on which
  hardware it's running on.
- Output: standard pytest pass/fail per test, verbose (`-v`) in CI for readability.

### Why this is testable with zero production-code changes

Every `/proc`/`/sys` read in `sys_monitor.py` goes through one function, `_read_file(path,
default="")`. Every shell-out goes through one function, `_run(cmd)`. LLM probing goes through one
function, `_http_get_json(url)`, using stdlib `urllib.request` (not `requests`), so no extra
HTTP-mocking dependency is needed — `tests/conftest.py`'s `proc_files` and `run_stub` fixtures
mock `_read_file`/`_run` directly; `test_llm_detection.py` mocks `urllib.request.urlopen`
directly. `CONFIG["auth_token"]`/`CONFIG["config_token"]` are read fresh per request (not cached
at decoration time). `detect_system()` only runs under `if __name__ == "__main__":` — importing
`sys_monitor` for tests never touches the real system.

## 12. CI Wiring

- `.github/workflows/ci.yml`
- Triggers: push and pull_request to `main`.
- Gates: `py_compile` (all three Python files) + `pytest tests/`. Both must pass.
- Runs on: `ubuntu-latest` only. Pi-specific behavior (hardware detection, GPU memory split) is
  tested via the fixture trees in `tests/fixtures/proc/raspberry-pi-5/`, not real Pi hardware in
  CI — GitHub Actions has no ARM/Pi runners available to this project.

## 13. Closing the Loop: Incidents → Acceptance Criteria

Two concrete incidents map directly to items in this suite:
- The Hub poller `TimeoutError` crash (fixed in PR #3) — motivates the deferred Hub polling tests
  (item 5).
- The port-range cap excluding Ollama's 11434 (fixed before this session) — directly covered by
  `test_max_scanned_port_includes_ollama`, the first regression test in this suite.

Process going forward: any future production incident should produce a regression test in
`tests/`, added to this table, not just a code fix.

## 14. Blueprint Versioning / Spec-First Discipline

N/A — no formal blueprint (see Section 2).

## 15. Review Cadence

Revisit this doc's tracking table whenever `docs/sysmonitorgapanalysis.md`'s testing backlog is
picked up again — i.e., whenever items 3, 4, or 5 get their own PR.
