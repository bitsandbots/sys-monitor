"""Fleet-aware lateral-movement scoring in the Hub (_find_lateral)."""
import socket

import sys_monitor_hub as hub


def _fleet(monkeypatch, b_declared):
    a, _ = hub._add_node("10.0.0.1", 8585, label="HARNESS_a")
    b, _ = hub._add_node("10.0.0.2", 8585, label="HARNESS_b")
    monkeypatch.setattr(hub, "_resolve_host", lambda h: h)
    if b_declared is not None:
        hub._nodes[b]["security"] = {"declared_ports": b_declared}
    return a, b


def _sec(rport, rip="10.0.0.2"):
    return {"internal_connections": [{"rip": rip, "rport": rport, "proc": "HARNESS_nc"}]}


def test_undeclared_port_to_fleet_node_flagged(monkeypatch):
    a, _ = _fleet(monkeypatch, [22, 8585])
    found = hub._find_lateral(a, _sec(4444))
    assert [f["category"] for f in found] == ["fleet.undeclared_port"]
    assert "HARNESS_b:4444" in found[0]["detail"]


def test_declared_port_not_flagged(monkeypatch):
    a, _ = _fleet(monkeypatch, [22, 8585])
    assert hub._find_lateral(a, _sec(8585)) == []


def test_unknown_destination_or_declared_ports_not_flagged(monkeypatch):
    a, _ = _fleet(monkeypatch, None)  # b's security not polled yet
    assert hub._find_lateral(a, _sec(4444)) == []
    assert hub._find_lateral(a, _sec(4444, rip="10.0.0.99")) == []  # not a fleet node


def test_self_connection_not_flagged(monkeypatch):
    a, _ = _fleet(monkeypatch, [8585])
    assert hub._find_lateral(a, _sec(4444, rip="10.0.0.1")) == []


def test_poll_counts_lateral_toward_actionable(monkeypatch):
    a, b = _fleet(monkeypatch, [8585])
    sec = {"available": True, "actionable_count": 0, **_sec(4444)}

    def fetch(node, path, **k):
        return {"ok": True} if path == "ping" else (sec if path == "security" else {})

    monkeypatch.setattr(hub, "_fetch_node", fetch)
    seen = {}
    monkeypatch.setattr(hub, "_check_alerts", lambda nid, online, status=None, security=None: seen.update(s=security))
    hub._poll_node(a)
    assert seen["s"]["actionable_count"] == 1
    assert hub._nodes[a]["security_lateral"][0]["category"] == "fleet.undeclared_port"


def test_resolve_host_caches_and_handles_failure(monkeypatch):
    hub._ip_cache.clear()
    calls = []

    def fake(h):
        calls.append(h)
        if h == "bad.local":
            raise socket.gaierror
        return "10.0.0.7"

    monkeypatch.setattr(hub.socket, "gethostbyname", fake)
    assert hub._resolve_host("ok.local") == "10.0.0.7"
    assert hub._resolve_host("ok.local") == "10.0.0.7"
    assert hub._resolve_host("bad.local") is None
    assert calls == ["ok.local", "bad.local"]
    hub._ip_cache.clear()
