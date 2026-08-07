"""_poll_node / _poller_loop / alert-transition tests.

_poller_loop() is an infinite loop, so the only way to exercise its
timeout/concurrency behavior is to actually run it in a background
thread for a couple of cycles and stop it -- see the two threading
tests at the bottom. Everything else here calls _poll_node()/
_check_alerts() directly as plain functions.
"""
import concurrent.futures
import threading
import time

import sys_monitor_hub


def _run_poller_briefly(monkeypatch, min_cycles=2, timeout=5):
    """Starts _poller_loop() in a background thread, waits until it has
    completed at least `min_cycles` iterations (tracked via a wrapped
    as_completed that counts calls), then stops it cleanly. Returns the
    call counter dict. Uses try/finally so a failed assertion in the
    caller can never leak a running poller thread into later tests."""
    sys_monitor_hub.HUB_CONFIG["poll_interval"] = 0

    call_count = {"n": 0}
    real_as_completed = sys_monitor_hub.as_completed

    def counting_as_completed(futures, timeout=None):
        call_count["n"] += 1
        return real_as_completed(futures, timeout=timeout)

    monkeypatch.setattr(sys_monitor_hub, "as_completed", counting_as_completed)

    sys_monitor_hub._poller_running = True
    t = threading.Thread(target=sys_monitor_hub._poller_loop, daemon=True)
    t.start()
    try:
        deadline = time.time() + timeout
        while call_count["n"] < min_cycles and time.time() < deadline:
            time.sleep(0.01)
    finally:
        sys_monitor_hub._poller_running = False
        t.join(timeout=2)

    return call_count, t


# ── _poll_node ──────────────────────────────────────────────────────────


def test_poll_node_ping_failure_marks_offline(monkeypatch):
    nid, _ = sys_monitor_hub._add_node("10.0.0.5", 8585)
    monkeypatch.setattr(sys_monitor_hub, "_fetch_node", lambda node, path, **k: None)

    sys_monitor_hub._poll_node(nid)

    node = sys_monitor_hub._get_node(nid)
    assert node["online"] is False
    assert node["status"] is None  # never touched


def test_poll_node_success_caches_status_and_marks_online(monkeypatch):
    nid, _ = sys_monitor_hub._add_node("10.0.0.5", 8585)

    responses = {
        "ping": {"ok": True},
        "status": {"cpu": {"usage": 12.3}},
        "boot": {"hostname": "kitchen-pi", "is_raspberry_pi": True},
        "llm": [],
        "security": {"available": True, "actionable_count": 0},
    }
    monkeypatch.setattr(sys_monitor_hub, "_fetch_node", lambda node, path, **k: responses.get(path))

    sys_monitor_hub._poll_node(nid)

    node = sys_monitor_hub._get_node(nid)
    assert node["online"] is True
    assert node["last_seen"] is not None
    assert node["status"] == {"cpu": {"usage": 12.3}}
    assert node["boot"]["hostname"] == "kitchen-pi"
    assert node["llm"] == []
    assert node["security"]["actionable_count"] == 0


# ── _check_alerts / _send_webhook ──────────────────────────────────────


def test_check_alerts_fires_once_on_online_to_offline_transition(monkeypatch):
    sys_monitor_hub.HUB_CONFIG["alert_webhook_url"] = "http://example.invalid/hook"
    nid, _ = sys_monitor_hub._add_node("10.0.0.5", 8585, label="kitchen-pi", token="secret-token")
    with sys_monitor_hub._nodes_lock:
        sys_monitor_hub._nodes[nid]["_alert_state"]["online"] = True  # was online

    posted = []
    monkeypatch.setattr(
        sys_monitor_hub.requests, "post", lambda url, json=None, timeout=None: posted.append(json)
    )

    sys_monitor_hub._check_alerts(nid, online=False)

    assert len(posted) == 1
    assert posted[0]["event"] == "node_offline"
    assert posted[0]["node_id"] == nid
    # The node's own auth token must never appear in a webhook payload
    assert "secret-token" not in str(posted[0])
    assert "token" not in posted[0]


def test_check_alerts_no_webhook_on_repeated_same_state(monkeypatch):
    sys_monitor_hub.HUB_CONFIG["alert_webhook_url"] = "http://example.invalid/hook"
    nid, _ = sys_monitor_hub._add_node("10.0.0.5", 8585)
    # _alert_state starts online=False (the default from _add_node)

    posted = []
    monkeypatch.setattr(
        sys_monitor_hub.requests, "post", lambda url, json=None, timeout=None: posted.append(json)
    )

    sys_monitor_hub._check_alerts(nid, online=False)  # still offline -> no transition

    assert posted == []


def test_send_webhook_noop_when_url_unset(monkeypatch):
    sys_monitor_hub.HUB_CONFIG["alert_webhook_url"] = ""
    called = []
    monkeypatch.setattr(sys_monitor_hub.requests, "post", lambda *a, **k: called.append(1))

    sys_monitor_hub._send_webhook("node_offline", {"id": "x", "host": "10.0.0.5", "port": 8585}, "msg")

    assert called == []


# ── _poller_loop: PR #3 regression + worker sizing ─────────────────────


def test_poller_loop_survives_as_completed_timeout(monkeypatch):
    """Regression test for the exact bug fixed in PR #3: as_completed(...,
    timeout=10) can raise TimeoutError from the iterator itself (not from
    f.result()), which used to kill the poller daemon thread outright
    since nothing caught it. The loop's outer `except Exception:` must
    swallow this and keep looping."""
    sys_monitor_hub._add_node("10.0.0.5", 8585)

    real_as_completed = sys_monitor_hub.as_completed
    call_count = {"n": 0}

    def flaky_as_completed(futures, timeout=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise concurrent.futures.TimeoutError("simulated slow node")
        return real_as_completed(futures, timeout=timeout)

    monkeypatch.setattr(sys_monitor_hub, "as_completed", flaky_as_completed)
    sys_monitor_hub.HUB_CONFIG["poll_interval"] = 0

    sys_monitor_hub._poller_running = True
    t = threading.Thread(target=sys_monitor_hub._poller_loop, daemon=True)
    t.start()
    try:
        deadline = time.time() + 5
        while call_count["n"] < 2 and time.time() < deadline:
            time.sleep(0.01)
    finally:
        sys_monitor_hub._poller_running = False
        t.join(timeout=2)

    assert call_count["n"] >= 2, "loop died after the first TimeoutError instead of surviving it"
    assert not t.is_alive()


def test_poller_loop_respects_poll_max_workers(monkeypatch):
    sys_monitor_hub._add_node("10.0.0.1", 8585)
    sys_monitor_hub._add_node("10.0.0.2", 8585)
    sys_monitor_hub._add_node("10.0.0.3", 8585)
    sys_monitor_hub.HUB_CONFIG["poll_max_workers"] = 2  # cap below the 3 registered nodes

    real_executor_cls = sys_monitor_hub.ThreadPoolExecutor
    captured = []

    class SpyExecutor(real_executor_cls):
        def __init__(self, *args, max_workers=None, **kwargs):
            captured.append(max_workers)
            super().__init__(*args, max_workers=max_workers, **kwargs)

    monkeypatch.setattr(sys_monitor_hub, "ThreadPoolExecutor", SpyExecutor)

    call_count, _ = _run_poller_briefly(monkeypatch, min_cycles=1)

    assert call_count["n"] >= 1
    assert captured[0] == 2  # min(3 nodes, cap of 2)
