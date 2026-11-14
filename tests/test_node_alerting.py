"""Tests for the node-local alert state machine and notifiers."""
import json

import pytest

import sys_monitor


REAL_SEND_ALERT = sys_monitor._send_alert


@pytest.fixture
def real_send_alert():
    return REAL_SEND_ALERT


@pytest.fixture(autouse=True)
def alert_state(monkeypatch):
    sys_monitor._alert_active.clear()
    sys_monitor._alert_streak.clear()
    sys_monitor._alert_history.clear()
    sent = []
    monkeypatch.setattr(sys_monitor, "_send_alert", lambda *a: sent.append(a))
    sys_monitor.CONFIG["alert_confirm_samples"] = 2
    yield sent
    sys_monitor._alert_active.clear()
    sys_monitor._alert_streak.clear()
    sys_monitor._alert_history.clear()


BAD = {"cpu_temp": ("critical", "CPU at 82C")}


def test_alert_needs_consecutive_samples(alert_state):
    assert sys_monitor._alert_tick(BAD) == []
    assert sys_monitor._alert_tick(BAD) == [("alert", "cpu_temp")]
    assert len(alert_state) == 1


def test_alert_fires_once_not_every_sample(alert_state):
    for _ in range(5):
        sys_monitor._alert_tick(BAD)
    assert len(alert_state) == 1


def test_transient_blip_never_fires(alert_state):
    sys_monitor._alert_tick(BAD)
    sys_monitor._alert_tick({})
    sys_monitor._alert_tick(BAD)
    assert alert_state == []


def test_recovery_notifies_once(alert_state):
    sys_monitor._alert_tick(BAD)
    sys_monitor._alert_tick(BAD)
    assert sys_monitor._alert_tick({}) == [("alert_recovered", "cpu_temp")]
    assert sys_monitor._alert_tick({}) == []
    assert alert_state[-1][0] == "alert_recovered"
    assert alert_state[-1][3].startswith("Recovered:")


def test_collect_conditions_thresholds(monkeypatch):
    monkeypatch.setattr(sys_monitor, "get_temperature_status", lambda: {"level": "normal"})
    monkeypatch.setattr(
        sys_monitor, "get_storage",
        lambda: [{"mount": "/", "percent": 95, "avail_mb": 100}, {"mount": "/d", "percent": 10, "avail_mb": 9}],
    )
    monkeypatch.setattr(
        sys_monitor, "get_gpu",
        lambda: {"available": True, "processes": [], "gpus": [
            {"index": 0, "name": "G", "temp_c": 90.0, "mem_percent": 50.0}]},
    )
    monkeypatch.setattr(sys_monitor, "get_critical_services_status", lambda: [{"name": "cron"}])
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", False)
    bad = sys_monitor._collect_alert_conditions()
    assert set(bad) == {"disk:/", "gpu_temp:0", "service:cron"}


def test_gpu_unavailable_is_not_an_alert(monkeypatch):
    monkeypatch.setattr(sys_monitor, "get_temperature_status", lambda: {"level": "normal"})
    monkeypatch.setattr(sys_monitor, "get_storage", lambda: [])
    monkeypatch.setattr(sys_monitor, "get_gpu", lambda: {"available": False, "gpus": [], "processes": []})
    monkeypatch.setattr(sys_monitor, "get_critical_services_status", lambda: [])
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", False)
    assert sys_monitor._collect_alert_conditions() == {}


def test_start_alerting_requires_destination():
    sys_monitor.CONFIG["alert_webhook_url"] = ""
    sys_monitor.CONFIG["alert_ntfy_url"] = ""
    assert sys_monitor.start_alerting() is False


def test_send_alert_posts_webhook_and_ntfy(monkeypatch, real_send_alert):
    calls = []

    class _Resp:
        def close(self):
            pass

    def fake_urlopen(req, timeout=0):
        calls.append(req)
        return _Resp()

    monkeypatch.setattr(sys_monitor.urllib.request, "urlopen", fake_urlopen)
    sys_monitor.CONFIG["alert_webhook_url"] = "http://HARNESS.invalid/hook"
    sys_monitor.CONFIG["alert_ntfy_url"] = "http://HARNESS.invalid/topic"
    real_send_alert("alert", "cpu_temp", "critical", "CPU at 82C")
    hook, ntfy = calls
    body = json.loads(hook.data)
    assert body["event"] == "alert" and body["rule"] == "cpu_temp"
    assert ntfy.data == b"CPU at 82C"
    assert ntfy.get_header("Priority") == "urgent"


def test_send_alert_swallows_delivery_failure(monkeypatch, real_send_alert):
    def boom(req, timeout=0):
        raise OSError("connection refused")

    monkeypatch.setattr(sys_monitor.urllib.request, "urlopen", boom)
    sys_monitor.CONFIG["alert_webhook_url"] = "http://HARNESS.invalid/hook"
    sys_monitor.CONFIG["alert_ntfy_url"] = ""
    real_send_alert("alert", "r", "warning", "m")  # must not raise


def test_alerts_route(node_client):
    sys_monitor._alert_active["cpu_temp"] = {"severity": "critical", "message": "hot"}
    data = node_client.get("/api/alerts").get_json()
    assert data["active"] == [{"rule": "cpu_temp", "severity": "critical", "message": "hot"}]
    assert "history" in data
