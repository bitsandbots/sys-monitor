"""Shared fixtures for the node-agent test suite.

sys_monitor.py touches the real system through exactly two seams:
_read_file() (all /proc and /sys reads) and _run() (all subprocess
shell-outs). Every fixture here mocks at those seams rather than the
real filesystem/process table, so this suite is safe to run on any
host -- including a real Raspberry Pi, which is where it was written.
"""
import copy
from pathlib import Path

import pytest

import sys_monitor

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "proc"


@pytest.fixture(autouse=True)
def isolate_module_state():
    """Snapshot and restore sys_monitor's module-level mutable state
    (CONFIG, the CPU differential sampler, cached boot info) around every
    test, so tests can't leak into each other regardless of execution
    order."""
    config_snapshot = copy.deepcopy(sys_monitor.CONFIG)
    cpu_prev_snapshot = copy.deepcopy(sys_monitor._cpu_prev)
    boot_info_snapshot = copy.deepcopy(sys_monitor._BOOT_INFO)
    yield
    sys_monitor.CONFIG.clear()
    sys_monitor.CONFIG.update(config_snapshot)
    sys_monitor._cpu_prev.clear()
    sys_monitor._cpu_prev.update(cpu_prev_snapshot)
    sys_monitor._BOOT_INFO.clear()
    sys_monitor._BOOT_INFO.update(boot_info_snapshot)


@pytest.fixture
def node_client():
    """Flask test client for the node agent."""
    sys_monitor.app.config["TESTING"] = True
    return sys_monitor.app.test_client()


@pytest.fixture
def proc_files(monkeypatch):
    """Returns a function that maps sys_monitor's system-file paths to
    fixture file contents (paths relative to tests/fixtures/proc/).

    Any real path not explicitly mapped returns the caller's default
    ("" unless overridden) -- it never falls through to the real
    filesystem. That's deliberate: this suite may run on a real
    Raspberry Pi, and letting an unmapped path leak through would make
    the "generic-pc" scenario silently read real Pi data.
    """

    def _use(mapping: dict):
        resolved = {path: (FIXTURES_DIR / fname).read_text() for path, fname in mapping.items()}

        def fake_read_file(path, default=""):
            return resolved.get(path, default)

        monkeypatch.setattr(sys_monitor, "_read_file", fake_read_file)

    return _use


@pytest.fixture
def run_stub(monkeypatch):
    """Returns a function that maps a command substring to canned stdout
    for sys_monitor._run(), without ever executing a real subprocess.
    Commands not matching any mapped substring return "" (mirroring
    _run()'s own behavior when a command fails or isn't found)."""

    def _use(mapping: dict):
        def fake_run(cmd, timeout=5):
            for substr, output in mapping.items():
                if substr in cmd:
                    return output
            return ""

        monkeypatch.setattr(sys_monitor, "_run", fake_run)

    return _use
