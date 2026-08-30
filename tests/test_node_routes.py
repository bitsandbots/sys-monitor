"""Route-level tests for the node-agent routes not covered elsewhere
(mutation routes are in test_mutation_routes.py, /api/security* in
test_hiddenscope_glue.py). These assert response shape and status code by
stubbing the underlying get_*() functions directly -- metric correctness
itself is covered at the unit level in test_node_metrics.py.
"""
import sys_monitor


def test_index_route_renders(node_client):
    resp = node_client.get("/")
    assert resp.status_code == 200


def test_api_ping(node_client):
    resp = node_client.get("/api/ping")
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True


def test_api_boot(node_client):
    sys_monitor._BOOT_INFO.clear()
    sys_monitor._BOOT_INFO.update({"platform": "raspberry-pi", "model": "Pi 5"})
    resp = node_client.get("/api/boot")
    assert resp.status_code == 200
    assert resp.get_json()["model"] == "Pi 5"


def test_api_status(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "get_network", lambda: {"interfaces": [], "rates": {"eth0": {"rx_rate": 0, "tx_rate": 0}}})
    monkeypatch.setattr(sys_monitor, "get_temperature_status", lambda: {"temp_c": 40.0, "level": "normal"})
    monkeypatch.setattr(sys_monitor, "get_power_status", lambda: {"available": False})
    monkeypatch.setattr(sys_monitor, "get_cpu_usage", lambda: 12.3)
    monkeypatch.setattr(sys_monitor, "get_cpu_temperature", lambda: 40.0)
    monkeypatch.setattr(sys_monitor, "get_memory", lambda: {"percent": 50.0})
    monkeypatch.setattr(sys_monitor, "get_uptime", lambda: {"seconds": 100})

    resp = node_client.get("/api/status")
    body = resp.get_json()
    assert resp.status_code == 200
    assert body["cpu"] == 12.3
    assert body["network_rates"] == {"eth0": {"rx_rate": 0, "tx_rate": 0}}


def test_api_storage(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "get_storage", lambda: [{"mount": "/", "percent": 42}])
    resp = node_client.get("/api/storage")
    assert resp.get_json() == [{"mount": "/", "percent": 42}]


def test_api_network(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "get_network", lambda: {"interfaces": [], "rates": {}})
    resp = node_client.get("/api/network")
    assert resp.status_code == 200


def test_api_processes_caps_limit_at_50(node_client, monkeypatch):
    captured = {}

    def fake_top(limit=12):
        captured["limit"] = limit
        return []

    monkeypatch.setattr(sys_monitor, "get_top_processes", fake_top)
    resp = node_client.get("/api/processes?limit=500")
    assert resp.status_code == 200
    assert captured["limit"] == 50


def test_api_services(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "get_services", lambda: [{"name": "nginx", "active": True}])
    resp = node_client.get("/api/services")
    assert resp.get_json() == [{"name": "nginx", "active": True}]


def test_api_services_with_ports(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "get_services_with_ports", lambda: [])
    resp = node_client.get("/api/services-with-ports")
    assert resp.status_code == 200


def test_api_logs_without_system(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "get_log", lambda limit: [{"ts": "10:00:00", "msg": "hi", "level": "info"}])
    resp = node_client.get("/api/logs")
    assert resp.get_json() == [{"ts": "10:00:00", "msg": "hi", "level": "info"}]


def test_api_logs_merges_system_errors_when_requested(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "get_log", lambda limit: [{"ts": "10:00:01", "msg": "event", "level": "info"}])
    monkeypatch.setattr(
        sys_monitor, "get_system_errors",
        lambda limit: [{"ts": "10:00:00", "unit": "nginx.service", "msg": "boom"}],
    )
    resp = node_client.get("/api/logs?system=true")
    body = resp.get_json()
    assert any("[nginx.service]" in e["msg"] for e in body)


def test_api_ports(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "get_open_ports", lambda: [{"port": 22, "protocol": "tcp"}])
    resp = node_client.get("/api/ports")
    assert resp.get_json() == [{"port": 22, "protocol": "tcp"}]


def test_api_llm(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "get_llm_services", lambda: {"services": []})
    resp = node_client.get("/api/llm")
    assert resp.status_code == 200


def test_api_system_health(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "get_critical_services_status", lambda: [])
    monkeypatch.setattr(sys_monitor, "get_system_stability", lambda: {"stable": True, "issues": []})
    resp = node_client.get("/api/system-health")
    body = resp.get_json()
    assert body == {"stable": True, "issues": [], "critical_services_failed": [], "all_critical_ok": True}


def test_api_system_errors(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "get_system_errors", lambda limit: [{"unit": "x", "msg": "err"}])
    resp = node_client.get("/api/system-errors")
    assert resp.get_json() == [{"unit": "x", "msg": "err"}]


# ── /api/services/config CRUD ───────────────────────────────────────────


def test_services_config_get(node_client):
    sys_monitor.CONFIG["services"] = ["nginx", "sshd"]
    resp = node_client.get("/api/services/config")
    assert resp.get_json() == ["nginx", "sshd"]


def test_services_config_add(node_client, monkeypatch):
    sys_monitor.CONFIG["services"] = []
    monkeypatch.setattr(sys_monitor, "_save_services", lambda: None)
    resp = node_client.post("/api/services/config", json={"name": "nginx"})
    assert resp.status_code == 201
    assert sys_monitor.CONFIG["services"] == ["nginx"]


def test_services_config_add_rejects_empty_name(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "_save_services", lambda: None)
    resp = node_client.post("/api/services/config", json={"name": "  "})
    assert resp.status_code == 400


def test_services_config_add_rejects_invalid_chars(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "_save_services", lambda: None)
    resp = node_client.post("/api/services/config", json={"name": "nginx; rm -rf /"})
    assert resp.status_code == 400


def test_services_config_add_rejects_duplicate(node_client, monkeypatch):
    sys_monitor.CONFIG["services"] = ["nginx"]
    monkeypatch.setattr(sys_monitor, "_save_services", lambda: None)
    resp = node_client.post("/api/services/config", json={"name": "nginx"})
    assert resp.status_code == 409


def test_services_config_add_requires_config_token_when_set(node_client, monkeypatch):
    sys_monitor.CONFIG["services"] = []
    sys_monitor.CONFIG["config_token"] = "sekrit"
    monkeypatch.setattr(sys_monitor, "_save_services", lambda: None)
    resp = node_client.post("/api/services/config", json={"name": "nginx"})
    assert resp.status_code == 401

    resp = node_client.post(
        "/api/services/config", json={"name": "nginx"},
        headers={"X-Config-Token": "sekrit"},
    )
    assert resp.status_code == 201


def test_services_config_remove(node_client, monkeypatch):
    sys_monitor.CONFIG["services"] = ["nginx"]
    monkeypatch.setattr(sys_monitor, "_save_services", lambda: None)
    resp = node_client.delete("/api/services/config/nginx")
    assert resp.status_code == 200
    assert sys_monitor.CONFIG["services"] == []


def test_services_config_remove_not_found(node_client, monkeypatch):
    sys_monitor.CONFIG["services"] = []
    monkeypatch.setattr(sys_monitor, "_save_services", lambda: None)
    resp = node_client.delete("/api/services/config/ghost")
    assert resp.status_code == 404


def test_services_config_rename(node_client, monkeypatch):
    sys_monitor.CONFIG["services"] = ["nginx"]
    monkeypatch.setattr(sys_monitor, "_save_services", lambda: None)
    resp = node_client.put("/api/services/config/nginx", json={"name": "nginx2"})
    assert resp.status_code == 200
    assert sys_monitor.CONFIG["services"] == ["nginx2"]


def test_services_config_rename_conflict(node_client, monkeypatch):
    sys_monitor.CONFIG["services"] = ["nginx", "sshd"]
    monkeypatch.setattr(sys_monitor, "_save_services", lambda: None)
    resp = node_client.put("/api/services/config/nginx", json={"name": "sshd"})
    assert resp.status_code == 409
