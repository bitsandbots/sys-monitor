"""/api/fleet aggregation, auth, CSRF, and a couple of representative
proxy routes -- including the power route, to prove it's a pure
passthrough to the mocked _fetch_node and never reaches a real host."""
import sys_monitor_hub


def test_api_fleet_never_leaks_raw_token(hub_client):
    sys_monitor_hub._add_node("10.0.0.5", 8585, label="kitchen-pi", token="super-secret-token")

    resp = hub_client.get("/api/fleet")

    assert resp.status_code == 200
    body_text = resp.get_data(as_text=True)
    assert "super-secret-token" not in body_text
    node = resp.get_json()["nodes"][0]
    assert node["token_set"] is True
    assert "token" not in node


def test_api_fleet_reports_total_and_online_counts(hub_client, monkeypatch):
    nid1, _ = sys_monitor_hub._add_node("10.0.0.1", 8585, label="a")
    nid2, _ = sys_monitor_hub._add_node("10.0.0.2", 8585, label="b")
    with sys_monitor_hub._nodes_lock:
        sys_monitor_hub._nodes[nid1]["online"] = True

    resp = hub_client.get("/api/fleet")
    body = resp.get_json()

    assert body["total"] == 2
    assert body["online"] == 1


def test_require_auth_blocks_without_token(hub_client):
    sys_monitor_hub.HUB_CONFIG["auth_token"] = "sekrit"

    resp = hub_client.get("/api/fleet")

    assert resp.status_code == 401


def test_require_auth_allows_with_correct_token(hub_client):
    sys_monitor_hub.HUB_CONFIG["auth_token"] = "sekrit"

    resp = hub_client.get("/api/fleet", headers={"Authorization": "Bearer sekrit"})

    assert resp.status_code == 200


def test_require_auth_unset_allows_all(hub_client):
    sys_monitor_hub.HUB_CONFIG["auth_token"] = ""

    resp = hub_client.get("/api/fleet")

    assert resp.status_code == 200


def test_csrf_guard_blocks_cross_origin_post(hub_client):
    nid, _ = sys_monitor_hub._add_node("10.0.0.5", 8585)

    resp = hub_client.post(
        f"/api/nodes/{nid}/power/reboot",
        headers={"Origin": "http://evil.example"},
    )

    assert resp.status_code == 403


def test_csrf_guard_allows_same_origin_post(hub_client, monkeypatch):
    nid, _ = sys_monitor_hub._add_node("10.0.0.5", 8585)
    monkeypatch.setattr(sys_monitor_hub, "_fetch_node", lambda node, path, **k: {"success": True})

    resp = hub_client.post(
        f"/api/nodes/{nid}/power/reboot",
        headers={"Origin": "http://localhost"},
    )

    assert resp.status_code == 200


def test_proxy_status_route_passes_through_fetch_node(hub_client, monkeypatch):
    nid, _ = sys_monitor_hub._add_node("10.0.0.5", 8585)
    monkeypatch.setattr(
        sys_monitor_hub, "_fetch_node", lambda node, path, **k: {"cpu": {"usage": 42.0}}
    )

    resp = hub_client.get(f"/api/nodes/{nid}/status")

    assert resp.status_code == 200
    assert resp.get_json() == {"cpu": {"usage": 42.0}}


def test_proxy_status_route_502_when_unreachable(hub_client):
    # mock_fetch_node autouse fixture already makes every node unreachable
    nid, _ = sys_monitor_hub._add_node("10.0.0.5", 8585)

    resp = hub_client.get(f"/api/nodes/{nid}/status")

    assert resp.status_code == 502


def test_proxy_status_route_404_for_unknown_node(hub_client):
    resp = hub_client.get("/api/nodes/does-not-exist/status")
    assert resp.status_code == 404


def test_proxy_power_route_is_a_pure_passthrough(hub_client, monkeypatch):
    """The dangerous one: prove it never does anything but call the
    (mocked) _fetch_node -- no real power command is reachable through
    this path in tests."""
    nid, _ = sys_monitor_hub._add_node("10.0.0.5", 8585)
    calls = []

    def fake_fetch_node(node, path, method="GET", **k):
        calls.append((path, method))
        return {"success": True}

    monkeypatch.setattr(sys_monitor_hub, "_fetch_node", fake_fetch_node)

    resp = hub_client.post(f"/api/nodes/{nid}/power/reboot", headers={"Origin": "http://localhost"})

    assert resp.status_code == 200
    assert calls == [("power/reboot", "POST")]


def test_proxy_power_route_rejects_invalid_action(hub_client):
    nid, _ = sys_monitor_hub._add_node("10.0.0.5", 8585)

    resp = hub_client.post(f"/api/nodes/{nid}/power/erase-disk", headers={"Origin": "http://localhost"})

    assert resp.status_code == 400
