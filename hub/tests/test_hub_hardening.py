"""Hub hardening: exact-origin CSRF, Host guard, strict power auth, lockout,
0600 atomic registry write, and input validation on proxy/add/discover routes.

Tokens and node data are HARNESS_-prefixed fixtures.
"""

import os
import stat

import pytest

import sys_monitor_hub as hub

TOKEN = "HARNESS_hub_token"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    hub._auth_failures.clear()
    monkeypatch.setattr(hub, "_ALLOWED_HOSTS", {"localhost", "hub.lan"})
    yield
    hub._auth_failures.clear()


def _node():
    nid, _ = hub._add_node("10.0.0.9", 8585, label="HARNESS_n")
    return nid


def _env(ip="127.0.0.1", host="localhost"):
    return {"REMOTE_ADDR": ip, "HTTP_HOST": host}


# ── CSRF + Host ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "origin,blocked",
    [
        ("http://hub.lan", False),
        ("http://hub.lan.evil.com", True),
        ("http://hub.lan:8080", True),
        ("https://hub.lan", True),
    ],
)
def test_csrf_origin_exact_match(hub_client, origin, blocked):
    r = hub_client.post(
        "/api/nodes/none/power/reboot",
        headers={"Origin": origin},
        environ_overrides=_env(host="hub.lan"),
    )
    assert (r.status_code == 403) is blocked


def test_unknown_host_rejected(hub_client):
    r = hub_client.get("/api/ping", environ_overrides=_env(host="evil.example"))
    assert r.status_code == 400


def test_ip_literal_host_allowed(hub_client):
    r = hub_client.get("/api/ping", environ_overrides=_env(host="10.0.0.5:8686"))
    assert r.status_code == 200


# ── Strict power auth ───────────────────────────────────────────────────


def test_power_without_token_is_loopback_only(hub_client):
    nid = _node()
    url = f"/api/nodes/{nid}/power/reboot"
    assert hub_client.post(url, environ_overrides=_env("192.168.1.50")).status_code == 403
    assert hub_client.post(url, environ_overrides=_env("127.0.0.1")).status_code != 403


def test_power_with_token_needs_it_from_everyone(hub_client):
    hub.HUB_CONFIG["auth_token"] = TOKEN
    nid = _node()
    url = f"/api/nodes/{nid}/power/reboot"
    assert hub_client.post(url, environ_overrides=_env("127.0.0.1")).status_code == 401
    ok = hub_client.post(
        url,
        headers={"Authorization": f"Bearer {TOKEN}"},
        environ_overrides=_env("192.168.1.50"),
    )
    assert ok.status_code != 401 and ok.status_code != 403


# ── Bearer compare + lockout ────────────────────────────────────────────


def test_lockout_after_repeated_failures(hub_client):
    hub.HUB_CONFIG["auth_token"] = TOKEN
    bad = {"Authorization": "Bearer nope"}
    for _ in range(hub._AUTH_FAIL_MAX):
        assert hub_client.get("/api/fleet", headers=bad).status_code == 401
    good = {"Authorization": f"Bearer {TOKEN}"}
    assert hub_client.get("/api/fleet", headers=good).status_code == 429
    other = hub_client.get("/api/fleet", headers=good, environ_overrides=_env("1.1.1.1"))
    assert other.status_code == 200


def test_non_ascii_auth_header_does_not_raise(hub_client):
    hub.HUB_CONFIG["auth_token"] = TOKEN
    r = hub_client.get("/api/fleet", headers={"Authorization": "Bearer héllo".encode("latin-1")})
    assert r.status_code == 401


# ── Registry file: 0600, atomic, errors surfaced ────────────────────────


def test_registry_written_0600_with_token(tmp_path):
    hub._add_node("10.0.0.7", 8585, label="HARNESS_x", token="HARNESS_secret")
    mode = stat.S_IMODE(os.stat(hub._NODES_FILE).st_mode)
    assert mode == 0o600
    assert "HARNESS_secret" in hub._NODES_FILE.read_text()
    assert not hub._NODES_FILE.with_name(hub._NODES_FILE.name + ".tmp").exists()


def test_registry_save_failure_is_reported_not_swallowed(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(hub, "_NODES_FILE", tmp_path / "missing_dir" / "hub_nodes.json")
    hub._add_node("10.0.0.8", 8585)
    assert "could not save node registry" in capsys.readouterr().out


# ── Input validation ────────────────────────────────────────────────────


@pytest.mark.parametrize("port", ["abc", 0, 70000, True, "1@evil.test", []])
def test_add_node_rejects_bad_port(hub_client, port):
    r = hub_client.post("/api/nodes", json={"host": "10.0.0.5", "port": port})
    assert r.status_code == 400


def test_add_node_rejects_non_string_fields(hub_client):
    r = hub_client.post("/api/nodes", json={"host": "10.0.0.5", "label": 5})
    assert r.status_code == 400


def test_update_node_rejects_non_string(hub_client):
    nid = _node()
    assert hub_client.put(f"/api/nodes/{nid}", json={"label": ["x"]}).status_code == 400


@pytest.mark.parametrize("path", ["../quarantine", "..%2Fx", "a/b"])
def test_service_action_rejects_path_tricks(hub_client, path, monkeypatch):
    calls = []
    monkeypatch.setattr(hub, "_fetch_node", lambda *a, **k: calls.append(a) or {"ok": 1})
    nid = _node()
    for url in (f"/api/nodes/{nid}/services/{path}/restart", f"/api/nodes/{nid}/services/nginx/{path}"):
        assert hub_client.post(url).status_code in (400, 404)
    assert calls == []


def test_service_action_dotdot_segment_rejected(hub_client, monkeypatch):
    calls = []
    monkeypatch.setattr(hub, "_fetch_node", lambda *a, **k: calls.append(a) or {"ok": 1})
    nid = _node()
    assert hub_client.post(f"/api/nodes/{nid}/services/../quarantine").status_code in (400, 404)
    assert hub_client.post(f"/api/nodes/{nid}/services/..//quarantine").status_code in (308, 400, 404)
    assert calls == []


def test_service_action_valid_names_pass_through(hub_client, monkeypatch):
    calls = []
    monkeypatch.setattr(hub, "_fetch_node", lambda *a, **k: calls.append(a) or {"success": True})
    nid = _node()
    r = hub_client.post(f"/api/nodes/{nid}/services/ssh.service/restart")
    assert r.status_code == 200 and calls[0][1] == "services/ssh.service/restart"


def test_discover_rejects_bad_port(hub_client):
    r = hub_client.post("/api/discover", json={"method": "scan", "port": "1@evil.test"})
    assert r.status_code == 400


def test_discover_timeout_returns_partial_not_500(monkeypatch):
    from concurrent.futures import TimeoutError as FT

    def boom(*a, **k):
        raise FT()
        yield  # pragma: no cover

    monkeypatch.setattr(hub, "as_completed", boom)
    monkeypatch.setattr(hub.requests, "get", lambda *a, **k: (_ for _ in ()).throw(OSError("HARNESS")))
    assert hub._discover_subnet("10.9.9.0/30", 8585) == []
