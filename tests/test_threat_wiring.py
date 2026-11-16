"""Tests for the sys_monitor <-> threat_detect integration."""

import time

import pytest

import sys_monitor
import threat_detect as td

PUB = "8.8.8.8"
REAL_SEND_ALERT = sys_monitor._send_alert


@pytest.fixture
def threat(monkeypatch, tmp_path):
    """Isolated threat engine + DB; delivery captured, sources stubbed."""
    db = str(tmp_path / "HARNESS_metrics.db")
    sys_monitor.CONFIG.update(
        history_db=db,
        threat_enabled=True,
        threat_notify_per_hour=3,
        threat_learning_days=7,
        threat_access_logs=[],
        threat_allowlist="",
    )
    sent = []
    monkeypatch.setattr(sys_monitor, "_send_alert", lambda *a, **k: sent.append(a))
    monkeypatch.setattr(sys_monitor._td, "read_journal_sshd", lambda *a, **k: [])
    sys_monitor._threat_feed.clear()
    sys_monitor._threat_notified.clear()
    sys_monitor._threat_state.update(suppressed=0, events_seen=0, problems=[])
    sys_monitor._threat_init()
    yield sent
    sys_monitor._threat_feed.clear()
    sys_monitor._threat_notified.clear()
    sys_monitor._threat_engine = None


def _fails(n, ip=PUB, start=None):
    start = start if start is not None else time.time()
    return [
        td.LogEvent(
            ts=start + i, source="sshd", kind="login_fail", ip=ip, user="HARNESS_x"
        )
        for i in range(n)
    ]


def test_poll_records_and_notifies(threat, monkeypatch):
    monkeypatch.setattr(sys_monitor, "_threat_collect_events", lambda: _fails(8))
    findings = sys_monitor._threat_poll_once()
    assert [f.detector for f in findings] == ["brute_force"]
    conn = td.open_db(sys_monitor.CONFIG["history_db"])
    assert len(td.query_findings(conn)) == 1
    conn.close()
    assert threat[0][0] == "threat" and threat[0][2] == "warning"


def test_info_findings_are_stored_but_not_notified(threat, monkeypatch):
    ev = td.LogEvent(
        ts=time.time(), source="sshd", kind="login_ok", ip=PUB, user="HARNESS_x"
    )
    monkeypatch.setattr(sys_monitor, "_threat_collect_events", lambda: [ev])
    findings = sys_monitor._threat_poll_once()
    assert findings and findings[0].severity == "info"
    assert threat == []
    conn = td.open_db(sys_monitor.CONFIG["history_db"])
    assert PUB in td.load_baseline(conn).ips  # baseline persisted
    conn.close()


def test_notification_budget_caps_floods(threat, monkeypatch):
    ips = [f"8.8.{i}.8" for i in range(10)]
    events = [e for ip in ips for e in _fails(8, ip=ip)]
    monkeypatch.setattr(sys_monitor, "_threat_collect_events", lambda: events)
    findings = sys_monitor._threat_poll_once()
    assert len(findings) > 3
    assert len(threat) == 3  # threat_notify_per_hour
    assert sys_monitor._threat_state["suppressed"] == len(findings) - 3


def test_api_auth_failures_feed_detector(threat, monkeypatch):
    for _ in range(8):
        sys_monitor._auth_record_failure(PUB)
    assert len(sys_monitor._threat_feed) == 8
    findings = sys_monitor._threat_poll_once()
    assert any(f.detector == "brute_force" and f.ip == PUB for f in findings)


def test_feed_ignores_garbage_ip(threat):
    sys_monitor._threat_push_login_fail("not-an-ip")
    assert len(sys_monitor._threat_feed) == 0


def test_threats_route(threat, node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "_threat_collect_events", lambda: _fails(8))
    sys_monitor._threat_poll_once()
    data = node_client.get("/api/threats?range=1h&severity=warning").get_json()
    assert data["enabled"] and data["findings"][0]["ip"] == PUB
    assert data["top_offenders"][0]["ip"] == PUB
    assert data["status"]["learning"] is True
    assert node_client.get("/api/threats?range=bogus").status_code == 400
    assert node_client.get("/api/threats?limit=abc").status_code == 400


def test_threats_route_disabled(node_client):
    sys_monitor.CONFIG["history_db"] = ""
    assert node_client.get("/api/threats").get_json()["enabled"] is False


def test_ntfy_token_sent_as_bearer(monkeypatch):
    calls = []

    class _Resp:
        def close(self):
            pass

    monkeypatch.setattr(
        sys_monitor.urllib.request,
        "urlopen",
        lambda req, timeout=0: calls.append(req) or _Resp(),
    )
    sys_monitor.CONFIG.update(
        alert_webhook_url="",
        alert_ntfy_url="http://HARNESS.invalid/t",
        alert_ntfy_token="tk_HARNESS",
    )
    REAL_SEND_ALERT("threat", "r", "warning", "m")
    assert calls[0].get_header("Authorization") == "Bearer tk_HARNESS"
    sys_monitor.CONFIG["alert_ntfy_token"] = ""
    REAL_SEND_ALERT("threat", "r", "warning", "m")
    assert calls[1].get_header("Authorization") is None
