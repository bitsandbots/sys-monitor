"""Shared fixtures for the Fleet Hub test suite.

sys_monitor_hub.py touches nodes through exactly one seam, _fetch_node()
-- every proxy route is a thin synchronous wrapper around it. This suite
mocks at that seam (and at _NODES_FILE for the registry file) rather than
making any real HTTP request or touching a real hub_nodes.json.
"""
import copy

import pytest

import sys_monitor_hub


@pytest.fixture(autouse=True)
def isolate_hub_state():
    """Reset the in-memory node registry and restore HUB_CONFIG around
    every test, so tests can't leak into each other regardless of
    execution order."""
    config_snapshot = copy.deepcopy(sys_monitor_hub.HUB_CONFIG)
    yield
    sys_monitor_hub._nodes.clear()
    sys_monitor_hub.HUB_CONFIG.clear()
    sys_monitor_hub.HUB_CONFIG.update(config_snapshot)


@pytest.fixture(autouse=True)
def isolated_nodes_file(tmp_path, monkeypatch):
    """Never let a test touch a real hub_nodes.json."""
    monkeypatch.setattr(sys_monitor_hub, "_NODES_FILE", tmp_path / "hub_nodes.json")


@pytest.fixture(autouse=True)
def mock_fetch_node(monkeypatch):
    """Default every node to "unreachable" unless a test explicitly
    overrides _fetch_node. This is a safety net, not just a convenience:
    it means even a fire-and-forget background thread (see
    api_add_node's immediate-poll trigger) can never reach a real host,
    whichever test ends up triggering it."""
    monkeypatch.setattr(sys_monitor_hub, "_fetch_node", lambda *a, **k: None)


@pytest.fixture
def hub_client():
    sys_monitor_hub.app.config["TESTING"] = True
    return sys_monitor_hub.app.test_client()
