"""sys_monitor.py's hiddenscope integration glue: get_security_status(),
allowlist load/save, the HIDDENSCOPE_AVAILABLE=False degrade path, and
the /api/security* routes.

get_security_status() calls exactly two functions on the real
hiddenscope_scanner module that touch the live system -- _hs._connections()
and _hs._listeners() (both shell out to ss/psutil). Every test here mocks
those two (never the real thing), so the rest of the function -- scoring
via the real _hs.score_connection(), severity filtering, listener
cross-referencing -- runs for real, deterministically.

Every module global touched here (HIDDENSCOPE_AVAILABLE, HIDDENSCOPE_SCAN_PATH,
_HS_ALLOWLIST_FILE) is set via monkeypatch.setattr, never plain assignment --
a plain assignment would be a real mutation with no automatic revert and
would leak into later tests.
"""
import json

import sys_monitor


def _isolate_allowlist_file(monkeypatch, tmp_path):
    monkeypatch.setattr(sys_monitor, "_HS_ALLOWLIST_FILE", tmp_path / "hiddenscope_allowlist.json")


# ── get_security_status: unavailable degrade path ───────────────────────


def test_get_security_status_unavailable(monkeypatch):
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", False)

    status = sys_monitor.get_security_status()

    assert status == {
        "available": False,
        "findings": [],
        "actionable_count": 0,
        "flagged_listeners": [],
        "summary": {},
    }


# ── get_security_status: real scoring/aggregation against mocked I/O ───


def test_get_security_status_aggregates_correctly(monkeypatch, tmp_path):
    _isolate_allowlist_file(monkeypatch, tmp_path)
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", True)
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_MIN_SEVERITY", "high")

    conns = [
        {"rip": "8.8.8.8", "rport": 4444, "proc": "nc", "pid": 1, "exe": "/usr/bin/nc"},
        {
            "rip": "93.184.216.34",
            "rport": 443,
            "proc": "curl",
            "pid": 2,
            "exe": "/usr/bin/curl",
            "status": "ESTABLISHED",
        },
        {"rip": "192.168.1.1", "rport": 22, "proc": "ssh", "pid": 3},  # private -> unscored
    ]
    listeners = [
        {"port": 4444, "proc": "nc", "pid": 1, "iface": "0.0.0.0"},  # SUSPICIOUS_PORTS: Metasploit
        {"port": 8585, "proc": "sys-monitor", "pid": 4, "iface": "0.0.0.0"},  # not suspicious
    ]
    monkeypatch.setattr(sys_monitor._hs, "_connections", lambda: conns)
    monkeypatch.setattr(sys_monitor._hs, "_listeners", lambda: listeners)

    status = sys_monitor.get_security_status()

    assert status["available"] is True
    assert len(status["findings"]) == 2  # private conn produced no Finding
    assert status["actionable_count"] == 1  # only the "high" one clears the "high" threshold

    assert len(status["flagged_listeners"]) == 1
    flagged = status["flagged_listeners"][0]
    assert flagged["port"] == 4444
    assert flagged["label"] == "Metasploit"
    assert flagged["known_local_service"] is False  # 4444 isn't one of SysMonitor's own ports

    summary = status["summary"]
    assert summary["total_connections"] == 3
    assert summary["external_connections"] == 2  # private one excluded
    assert summary["total_listeners"] == 2
    assert summary["findings_by_severity"]["high"] == 1
    assert summary["findings_by_severity"]["info"] == 1


def test_get_security_status_min_severity_lower_admits_more_findings(monkeypatch, tmp_path):
    """Same data as above, but HIDDENSCOPE_MIN_SEVERITY lowered to "info" --
    the plain external connection now counts as actionable too."""
    _isolate_allowlist_file(monkeypatch, tmp_path)
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", True)
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_MIN_SEVERITY", "info")

    conns = [{"rip": "93.184.216.34", "rport": 443, "proc": "curl", "pid": 2, "exe": "/usr/bin/curl"}]
    monkeypatch.setattr(sys_monitor._hs, "_connections", lambda: conns)
    monkeypatch.setattr(sys_monitor._hs, "_listeners", lambda: [])

    status = sys_monitor.get_security_status()
    assert status["actionable_count"] == 1


# ── allowlist load/save ──────────────────────────────────────────────────


def test_load_hs_allowlist_missing_file_is_empty(monkeypatch, tmp_path):
    _isolate_allowlist_file(monkeypatch, tmp_path)
    al = sys_monitor._load_hs_allowlist()
    assert al.procs == set()
    assert al.ports == set()
    assert al.networks == []


def test_load_hs_allowlist_corrupt_json_is_empty(monkeypatch, tmp_path):
    _isolate_allowlist_file(monkeypatch, tmp_path)
    sys_monitor._HS_ALLOWLIST_FILE.write_text("{not valid json")
    al = sys_monitor._load_hs_allowlist()  # must not raise
    assert al.procs == set()


def test_save_and_load_hs_allowlist_round_trip(monkeypatch, tmp_path):
    _isolate_allowlist_file(monkeypatch, tmp_path)
    al = sys_monitor._hs.AllowList()
    al.procs.add("chrome")
    al.ports.add(4444)
    al.url_domains.add("example.com")
    import ipaddress

    al.networks.append(ipaddress.ip_network("10.0.0.0/8"))

    sys_monitor._save_hs_allowlist(al)
    reloaded = sys_monitor._load_hs_allowlist()

    assert reloaded.procs == {"chrome"}
    assert reloaded.ports == {4444}
    assert reloaded.url_domains == {"example.com"}
    assert [str(n) for n in reloaded.networks] == ["10.0.0.0/8"]


# ── /api/security ────────────────────────────────────────────────────────


def test_api_security_route_unavailable(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", False)
    resp = node_client.get("/api/security")
    assert resp.status_code == 200
    assert resp.get_json()["available"] is False


def test_api_security_route_passthrough(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "get_security_status", lambda: {"available": True, "sentinel": 1})
    resp = node_client.get("/api/security")
    assert resp.get_json() == {"available": True, "sentinel": 1}


# ── /api/security/allowlist ──────────────────────────────────────────────


def test_allowlist_add_and_get_round_trip(node_client, monkeypatch, tmp_path):
    _isolate_allowlist_file(monkeypatch, tmp_path)
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", True)

    resp = node_client.post("/api/security/allowlist", json={"port": 4444})
    assert resp.status_code == 201
    assert resp.get_json()["success"] is True

    resp = node_client.get("/api/security/allowlist")
    assert resp.get_json()["ports"] == [4444]


def test_allowlist_add_invalid_port(node_client, monkeypatch, tmp_path):
    _isolate_allowlist_file(monkeypatch, tmp_path)
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", True)

    resp = node_client.post("/api/security/allowlist", json={"port": "not-a-number"})
    assert resp.status_code == 400


def test_allowlist_add_invalid_network(node_client, monkeypatch, tmp_path):
    _isolate_allowlist_file(monkeypatch, tmp_path)
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", True)

    resp = node_client.post("/api/security/allowlist", json={"network": "not-a-cidr"})
    assert resp.status_code == 400


def test_allowlist_remove(node_client, monkeypatch, tmp_path):
    _isolate_allowlist_file(monkeypatch, tmp_path)
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", True)

    node_client.post("/api/security/allowlist", json={"port": 4444})
    resp = node_client.delete("/api/security/allowlist", json={"port": 4444})
    assert resp.status_code == 200
    assert resp.get_json()["removed"] == ["port 4444"]

    resp = node_client.get("/api/security/allowlist")
    assert resp.get_json()["ports"] == []


def test_allowlist_remove_not_found(node_client, monkeypatch, tmp_path):
    _isolate_allowlist_file(monkeypatch, tmp_path)
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", True)

    resp = node_client.delete("/api/security/allowlist", json={"port": 9999})
    assert resp.status_code == 404


def test_allowlist_routes_degrade_when_unavailable(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", False)

    resp = node_client.get("/api/security/allowlist")
    assert resp.status_code == 200
    assert resp.get_json() == {"procs": [], "ports": [], "networks": [], "url_domains": []}

    resp = node_client.post("/api/security/allowlist", json={"port": 4444})
    assert resp.status_code == 400

    resp = node_client.delete("/api/security/allowlist", json={"port": 4444})
    assert resp.status_code == 400


# ── /api/security/scan ────────────────────────────────────────────────────


def test_scan_route_no_path_configured(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", True)
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_SCAN_PATH", "")

    resp = node_client.post("/api/security/scan")
    assert resp.status_code == 400
    assert "not configured" in resp.get_json()["error"]


def test_scan_route_path_does_not_exist(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", True)
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_SCAN_PATH", "/no/such/path/on/this/host")

    resp = node_client.post("/api/security/scan")
    assert resp.status_code == 400
    assert "not found" in resp.get_json()["error"]


def test_scan_route_success(node_client, monkeypatch, tmp_path):
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", True)
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_SCAN_PATH", str(tmp_path))
    monkeypatch.setattr(sys_monitor, "run_security_scan", lambda path: [{"severity": "medium"}])

    resp = node_client.post("/api/security/scan")

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["success"] is True
    assert body["findings"] == [{"severity": "medium"}]


def test_scan_route_unavailable(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", False)
    resp = node_client.post("/api/security/scan")
    assert resp.status_code == 400
