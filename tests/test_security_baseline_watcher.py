"""Baseline endpoints + background watcher in sys_monitor.py.

Mocks only _hs._connections/_hs._listeners (the live-system seam); the
baseline file lives in tmp_path via the autouse isolate_security_state fixture.
"""
import json
import time

import sys_monitor

BAD = {"rip": "8.8.8.8", "rport": 4444, "proc": "HARNESS_nc", "pid": 1,
       "exe": "/usr/bin/nc", "raddr": "8.8.8.8:4444", "status": "ESTABLISHED"}


def _live(monkeypatch, conns, listeners=()):
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", True)
    monkeypatch.setattr(sys_monitor, "_HS_ALLOWLIST_FILE", sys_monitor._HS_BASELINE_FILE.parent / "al.json")
    monkeypatch.setattr(sys_monitor._hs, "_connections", lambda: list(conns))
    monkeypatch.setattr(sys_monitor._hs, "_listeners", lambda: list(listeners))


def test_baseline_get_before_capture(node_client, monkeypatch):
    _live(monkeypatch, [])
    assert node_client.get("/api/security/baseline").get_json() == {"captured": False}


def test_baseline_capture_then_diff_reports_new_listener(node_client, monkeypatch):
    listeners = [{"laddr": "0.0.0.0:8585", "port": 8585, "proc": "sm", "pid": 4, "iface": "0.0.0.0"}]
    _live(monkeypatch, [], listeners)
    r = node_client.post("/api/security/baseline")
    assert r.get_json()["success"] is True
    assert node_client.get("/api/security/baseline").get_json()["captured"] is True

    listeners.append({"laddr": "0.0.0.0:9999", "port": 9999, "proc": "x", "pid": 5, "iface": "0.0.0.0"})
    findings = sys_monitor.get_security_status()["findings"]
    assert [f["category"] for f in findings] == ["baseline.new_listener"]


def test_baseline_capture_requires_auth_when_token_set(node_client, monkeypatch):
    _live(monkeypatch, [])
    sys_monitor.CONFIG["auth_token"] = "HARNESS_tok"
    assert node_client.post("/api/security/baseline").status_code == 401
    ok = node_client.post("/api/security/baseline", headers={"Authorization": "Bearer HARNESS_tok"})
    assert ok.status_code == 200


def test_baseline_capture_write_failure_is_500(node_client, monkeypatch, tmp_path):
    _live(monkeypatch, [])
    monkeypatch.setattr(sys_monitor, "_HS_BASELINE_FILE", tmp_path / "missing_dir" / "b.json")
    r = node_client.post("/api/security/baseline")
    assert r.status_code == 500 and r.get_json()["success"] is False


def test_corrupt_baseline_surfaces_critical_finding(monkeypatch):
    _live(monkeypatch, [])
    sys_monitor._HS_BASELINE_FILE.write_text("{not json")
    cats = [f["category"] for f in sys_monitor.get_security_status()["findings"]]
    assert cats == ["baseline.error"]


def test_watch_tick_records_once_per_cooldown(monkeypatch):
    _live(monkeypatch, [BAD])
    tracker = sys_monitor._hs.AlertTracker(cooldown=300)
    assert sys_monitor._watch_tick(tracker, set(), True) == 1
    assert sys_monitor._watch_tick(tracker, set(), True) == 0  # deduped


def test_watch_tick_ignores_below_threshold(monkeypatch):
    plain = dict(BAD, rport=443, raddr="8.8.8.8:443")  # info severity
    _live(monkeypatch, [plain])
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_MIN_SEVERITY", "high")
    assert sys_monitor._watch_tick(sys_monitor._hs.AlertTracker(), set(), True) == 0


def test_watch_alert_survives_connection_close_then_ages_out(monkeypatch):
    _live(monkeypatch, [BAD])
    sys_monitor._watch_tick(sys_monitor._hs.AlertTracker(), set(), True)
    monkeypatch.setattr(sys_monitor._hs, "_connections", lambda: [])  # beacon closed

    status = sys_monitor.get_security_status()
    assert status["actionable_count"] == 1

    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_WATCH_RETENTION", -1)
    assert sys_monitor.get_security_status()["actionable_count"] == 0


def test_watch_alert_not_duplicated_while_connection_live(monkeypatch):
    _live(monkeypatch, [BAD])
    sys_monitor._watch_tick(sys_monitor._hs.AlertTracker(), set(), True)
    assert len(sys_monitor.get_security_status()["findings"]) == 1


def test_watch_log_appends_ndjson(monkeypatch, tmp_path):
    log = tmp_path / "HARNESS_watch.ndjson"
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_WATCH_LOG", str(log))
    _live(monkeypatch, [BAD])
    sys_monitor._watch_tick(sys_monitor._hs.AlertTracker(), set(), True)
    lines = log.read_text().splitlines()
    assert json.loads(lines[0])["category"] == "live.suspicious_port"


def test_start_watcher_disabled_paths(monkeypatch):
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_WATCH_INTERVAL", 0)
    assert sys_monitor.start_security_watcher() is False
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_WATCH_INTERVAL", 5)
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", False)
    assert sys_monitor.start_security_watcher() is False


# ── P3: first-seen destinations + deleted binaries ──────────────────────


def test_first_seen_alerts_once_after_warmup(monkeypatch):
    plain = dict(BAD, rport=443, raddr="8.8.8.8:443")  # info: below threshold
    _live(monkeypatch, [plain])
    tracker, seen = sys_monitor._hs.AlertTracker(), set()
    assert sys_monitor._watch_tick(tracker, seen, warmup=True) == 0  # silent baseline
    assert sys_monitor._watch_tick(tracker, seen) == 0  # already known

    new = dict(plain, rip="1.1.1.1", raddr="1.1.1.1:443")
    monkeypatch.setattr(sys_monitor._hs, "_connections", lambda: [plain, new])
    assert sys_monitor._watch_tick(tracker, seen) == 1
    assert sys_monitor._watch_tick(tracker, seen) == 0
    cats = [f["category"] for f in sys_monitor.get_security_status()["findings"]]
    assert "live.first_seen" in cats


def test_first_seen_set_is_capped(monkeypatch):
    _live(monkeypatch, [dict(BAD, rport=443)])
    monkeypatch.setattr(sys_monitor, "_WATCH_SEEN_MAX", 2)
    seen = {("a", "1.1.1.1"), ("b", "2.2.2.2")}
    sys_monitor._watch_tick(sys_monitor._hs.AlertTracker(), seen, warmup=True)
    assert seen == {("HARNESS_nc", "8.8.8.8")}


def test_deleted_exe_scored_even_for_private_destination(monkeypatch):
    conn = {"rip": "192.168.1.9", "rport": 22, "proc": "HARNESS_x", "pid": 7,
            "exe": "/usr/bin/x (deleted)"}
    f = sys_monitor_hs().score_connection(conn)
    assert f.category == "live.deleted_exe" and f.severity == "high"


def test_private_connection_with_live_binary_still_unscored():
    conn = {"rip": "192.168.1.9", "rport": 22, "proc": "ssh", "pid": 7, "exe": "/usr/bin/ssh"}
    assert sys_monitor_hs().score_connection(conn) is None


def sys_monitor_hs():
    return sys_monitor._hs


def test_status_exposes_internal_connections_and_declared_ports(monkeypatch):
    internal = {"rip": "192.168.1.9", "rport": 4444, "proc": "HARNESS_nc", "status": "ESTABLISHED"}
    loop = {"rip": "127.0.0.1", "rport": 8585, "proc": "x", "status": "ESTABLISHED"}
    _live(monkeypatch, [internal, loop])
    monkeypatch.setitem(sys_monitor.CONFIG, "services", ["ssh", "HARNESS_unknown"])
    st = sys_monitor.get_security_status()
    assert st["internal_connections"] == [{"rip": "192.168.1.9", "rport": 4444, "proc": "HARNESS_nc"}]
    assert 22 in st["declared_ports"] and sys_monitor.CONFIG["port"] in st["declared_ports"]
