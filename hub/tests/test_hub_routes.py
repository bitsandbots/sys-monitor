"""Route-level tests for the 14 Fleet Hub routes not already covered by
test_fleet_api.py (fleet aggregation, auth, CSRF, status/power proxy).
Every test here relies on the autouse mock_fetch_node fixture (default:
every node unreachable) so nothing can reach a real host; /api/discover
tests additionally mock requests.get directly since _discover_subnet
doesn't go through _fetch_node.
"""
import sys_monitor_hub


def test_index_route_renders(hub_client):
    resp = hub_client.get("/")
    assert resp.status_code == 200


def test_api_ping(hub_client):
    resp = hub_client.get("/api/ping")
    assert resp.status_code == 200
    assert resp.get_json()["hub"] is True


# ── Node CRUD ────────────────────────────────────────────────────────────


def test_add_node_success_triggers_poll(hub_client, monkeypatch):
    polled = []
    monkeypatch.setattr(sys_monitor_hub, "_poll_node", lambda nid: polled.append(nid))
    resp = hub_client.post("/api/nodes", json={"host": "10.0.0.9", "port": 8585, "label": "kitchen"})
    assert resp.status_code == 201
    assert resp.get_json()["success"] is True


def test_add_node_requires_host(hub_client):
    resp = hub_client.post("/api/nodes", json={})
    assert resp.status_code == 400


def test_add_node_rejects_invalid_host(hub_client):
    resp = hub_client.post("/api/nodes", json={"host": "10.0.0.9; rm -rf /"})
    assert resp.status_code == 400


def test_add_node_rejects_duplicate(hub_client):
    sys_monitor_hub._add_node("10.0.0.9", 8585, label="a")
    resp = hub_client.post("/api/nodes", json={"host": "10.0.0.9", "port": 8585})
    assert resp.status_code == 409


def test_remove_node(hub_client):
    nid, _ = sys_monitor_hub._add_node("10.0.0.9", 8585)
    resp = hub_client.delete(f"/api/nodes/{nid}")
    assert resp.status_code == 200
    assert sys_monitor_hub._get_node(nid) is None


def test_remove_node_not_found(hub_client):
    resp = hub_client.delete("/api/nodes/does-not-exist")
    assert resp.status_code == 404


def test_update_node_label_and_token(hub_client):
    nid, _ = sys_monitor_hub._add_node("10.0.0.9", 8585, label="old")
    resp = hub_client.put(f"/api/nodes/{nid}", json={"label": "new-label", "token": "tok"})
    assert resp.status_code == 200
    node = sys_monitor_hub._get_node(nid)
    assert node["label"] == "new-label"
    assert node["token"] == "tok"


def test_update_node_not_found(hub_client):
    resp = hub_client.put("/api/nodes/does-not-exist", json={"label": "x"})
    assert resp.status_code == 404


# ── /api/discover ─────────────────────────────────────────────────────────


def test_discover_rejects_wider_than_24(hub_client, monkeypatch):
    def fail(*a, **k):
        raise AssertionError("requests.get must never be called for a rejected subnet")

    monkeypatch.setattr(sys_monitor_hub.requests, "get", fail)
    resp = hub_client.post("/api/discover", json={"subnet": "10.0.0.0/8"})
    assert resp.status_code == 200
    assert resp.get_json() == {"found": [], "count": 0}


def test_discover_rejects_invalid_subnet(hub_client):
    resp = hub_client.post("/api/discover", json={"subnet": "not-a-cidr"})
    assert resp.get_json() == {"found": [], "count": 0}


def test_discover_scans_a_24_subnet(hub_client, monkeypatch):
    class FakePingResponse:
        status_code = 200

        def json(self):
            return {"ok": True}

    class FakeBootResponse:
        status_code = 200

        def json(self):
            return {"hostname": "kitchen-pi", "model": "Pi 5"}

    def fake_get(url, timeout=None):
        if "://127.0.0.5:" not in url:
            raise ConnectionError("refused")
        if url.endswith("/api/ping"):
            return FakePingResponse()
        return FakeBootResponse()

    monkeypatch.setattr(sys_monitor_hub.requests, "get", fake_get)
    resp = hub_client.post("/api/discover", json={"subnet": "127.0.0.0/24", "port": 8585})
    body = resp.get_json()
    assert body["count"] == 1
    assert body["found"][0]["host"] == "127.0.0.5"
    assert body["found"][0]["hostname"] == "kitchen-pi"


# ── Proxy routes (structurally identical shape) ──────────────────────────


import pytest

PROXY_ROUTES = [
    ("boot", "/api/nodes/{nid}/boot"),
    ("llm", "/api/nodes/{nid}/llm"),
    ("security", "/api/nodes/{nid}/security"),
    ("services", "/api/nodes/{nid}/services"),
    ("storage", "/api/nodes/{nid}/storage"),
    ("processes", "/api/nodes/{nid}/processes"),
    ("network", "/api/nodes/{nid}/network"),
    ("logs", "/api/nodes/{nid}/logs"),
]


@pytest.mark.parametrize("fetch_path,route_template", PROXY_ROUTES)
def test_proxy_route_passthrough(hub_client, monkeypatch, fetch_path, route_template):
    nid, _ = sys_monitor_hub._add_node("10.0.0.5", 8585)
    calls = []

    def fake_fetch_node(node, path, **k):
        calls.append(path)
        return {"sentinel": fetch_path}

    monkeypatch.setattr(sys_monitor_hub, "_fetch_node", fake_fetch_node)
    resp = hub_client.get(route_template.format(nid=nid))
    assert resp.status_code == 200
    assert resp.get_json() == {"sentinel": fetch_path}
    assert calls and calls[0].startswith(fetch_path)


@pytest.mark.parametrize("fetch_path,route_template", PROXY_ROUTES)
def test_proxy_route_404_for_unknown_node(hub_client, fetch_path, route_template):
    resp = hub_client.get(route_template.format(nid="does-not-exist"))
    assert resp.status_code == 404


@pytest.mark.parametrize("fetch_path,route_template", PROXY_ROUTES)
def test_proxy_route_502_when_unreachable(hub_client, fetch_path, route_template):
    # mock_fetch_node autouse fixture already makes every node unreachable
    nid, _ = sys_monitor_hub._add_node("10.0.0.5", 8585)
    resp = hub_client.get(route_template.format(nid=nid))
    assert resp.status_code == 502


def test_security_allowlist_add_passthrough(hub_client, monkeypatch):
    nid, _ = sys_monitor_hub._add_node("10.0.0.5", 8585)
    calls = []

    def fake_fetch_node(node, path, method="GET", **k):
        calls.append((path, method, k.get("json_body")))
        return {"success": True}

    monkeypatch.setattr(sys_monitor_hub, "_fetch_node", fake_fetch_node)
    resp = hub_client.post(f"/api/nodes/{nid}/security/allowlist", json={"port": 4444})
    assert resp.status_code == 200
    assert calls == [("security/allowlist", "POST", {"port": 4444})]


def test_node_service_action_passthrough(hub_client, monkeypatch):
    nid, _ = sys_monitor_hub._add_node("10.0.0.5", 8585)
    calls = []

    def fake_fetch_node(node, path, method="GET", **k):
        calls.append((path, method))
        return {"success": True}

    monkeypatch.setattr(sys_monitor_hub, "_fetch_node", fake_fetch_node)
    resp = hub_client.post(f"/api/nodes/{nid}/services/nginx/restart")
    assert resp.status_code == 200
    assert calls == [("services/nginx/restart", "POST")]
