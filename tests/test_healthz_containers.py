"""Tests for /healthz and read-only Docker container monitoring."""
import json
import os
import socketserver
import tempfile
import threading
import http.server

import pytest

import sys_monitor


@pytest.fixture(autouse=True)
def clean_state():
    sys_monitor._bg_threads.clear()
    prev = list(sys_monitor.CONFIG["docker_sockets"])
    yield
    sys_monitor._bg_threads.clear()
    sys_monitor.CONFIG["docker_sockets"] = prev


def test_healthz_ok_with_no_threads(node_client):
    r = node_client.get("/healthz")
    assert r.status_code == 200 and r.get_json()["ok"] is True


def test_healthz_reports_dead_thread(node_client):
    t = threading.Thread(target=lambda: None, name="history-sampler")
    t.start()
    t.join()
    sys_monitor._bg_threads["history-sampler"] = t
    r = node_client.get("/healthz")
    assert r.status_code == 503
    assert r.get_json()["dead"] == ["history-sampler"]


def test_healthz_ok_with_live_thread(node_client):
    ev = threading.Event()
    t = threading.Thread(target=ev.wait, daemon=True)
    t.start()
    sys_monitor._bg_threads["alert-sampler"] = t
    try:
        assert node_client.get("/healthz").status_code == 200
    finally:
        ev.set()


def test_healthz_needs_no_auth(node_client):
    sys_monitor.CONFIG["auth_token"] = "HARNESS_secret"
    assert node_client.get("/healthz").status_code == 200


class _UnixServer(socketserver.UnixStreamServer):
    pass


def _serve_docker(payload, status=200):
    d = tempfile.mkdtemp()
    path = os.path.join(d, "docker.sock")
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def address_string(self):
            return "unix"

        def log_message(self, *a):
            pass

    srv = _UnixServer(path, H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, path, seen


def test_containers_disabled_by_default(node_client):
    sys_monitor.CONFIG["docker_sockets"] = []
    assert node_client.get("/api/containers").get_json() == {"enabled": False, "daemons": []}


def test_containers_parse_state_and_health():
    srv, path, seen = _serve_docker(
        [
            {"Names": ["/web"], "Image": "nginx", "State": "running", "Status": "Up 2 hours (healthy)"},
            {"Names": ["/db"], "Image": "pg", "State": "running", "Status": "Up 1 hour (unhealthy)"},
            {"Names": ["/old"], "Image": "x", "State": "exited", "Status": "Exited (0) 3 days ago"},
        ]
    )
    try:
        sys_monitor.CONFIG["docker_sockets"] = [path]
        d = sys_monitor.get_containers()["daemons"][0]
    finally:
        srv.shutdown()
    assert d["available"] is True
    by = {c["name"]: c for c in d["containers"]}
    assert by["web"]["health"] == "healthy"
    assert by["db"]["health"] == "unhealthy"
    assert by["old"]["health"] is None and by["old"]["state"] == "exited"
    assert seen == ["/containers/json?all=1"]  # read-only: one GET, nothing else


def test_containers_unreachable_daemon_is_reported_not_raised():
    sys_monitor.CONFIG["docker_sockets"] = ["/nonexistent/HARNESS.sock"]
    d = sys_monitor.get_containers()["daemons"][0]
    assert d["available"] is False and d["error"] and d["containers"] == []


def test_containers_http_error_reported():
    srv, path, _ = _serve_docker({"message": "x"}, status=500)
    try:
        sys_monitor.CONFIG["docker_sockets"] = [path]
        d = sys_monitor.get_containers()["daemons"][0]
    finally:
        srv.shutdown()
    assert d["available"] is False and "500" in d["error"]


def test_unhealthy_container_raises_alert_condition(monkeypatch):
    monkeypatch.setattr(sys_monitor, "get_temperature_status", lambda: {"level": "normal"})
    monkeypatch.setattr(sys_monitor, "get_storage", lambda: [])
    monkeypatch.setattr(sys_monitor, "get_gpu", lambda: {"available": False, "gpus": [], "processes": []})
    monkeypatch.setattr(sys_monitor, "get_critical_services_status", lambda: [])
    monkeypatch.setattr(sys_monitor, "HIDDENSCOPE_AVAILABLE", False)
    sys_monitor.CONFIG["docker_sockets"] = ["x"]
    monkeypatch.setattr(
        sys_monitor, "get_containers",
        lambda: {"enabled": True, "daemons": [{"containers": [
            {"name": "db", "state": "running", "health": "unhealthy"},
            {"name": "ok", "state": "running", "health": "healthy"}]}]},
    )
    assert list(sys_monitor._collect_alert_conditions()) == ["container:db"]
