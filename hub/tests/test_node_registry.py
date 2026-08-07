"""Node registry CRUD tests -- add/remove/load/save round-trip via an
isolated _NODES_FILE (never the real hub_nodes.json)."""
import sys_monitor_hub


def test_add_node_creates_entry_with_runtime_defaults():
    nid, created = sys_monitor_hub._add_node("10.0.0.5", 8585, label="kitchen-pi", token="secret")

    assert created is True
    node = sys_monitor_hub._get_node(nid)
    assert node["host"] == "10.0.0.5"
    assert node["port"] == 8585
    assert node["label"] == "kitchen-pi"
    assert node["token"] == "secret"
    assert node["online"] is False
    assert node["last_seen"] is None
    assert node["_alert_state"] == {
        "online": False,
        "temp_level": "normal",
        "security_alert": False,
        "power_alert": False,
    }


def test_add_node_duplicate_is_not_created_twice():
    nid1, created1 = sys_monitor_hub._add_node("10.0.0.5", 8585)
    nid2, created2 = sys_monitor_hub._add_node("10.0.0.5", 8585)

    assert created1 is True
    assert created2 is False
    assert nid1 == nid2
    assert len(sys_monitor_hub._get_all_nodes()) == 1


def test_remove_node():
    nid, _ = sys_monitor_hub._add_node("10.0.0.5", 8585)
    assert sys_monitor_hub._remove_node(nid) is True
    assert sys_monitor_hub._get_node(nid) is None
    assert sys_monitor_hub._remove_node(nid) is False  # already gone


def test_save_nodes_persists_only_config_fields():
    """Runtime-only fields (online, last_seen, boot, status, _alert_state)
    must never be written to disk -- only what's needed to re-register the
    node on next startup."""
    nid, _ = sys_monitor_hub._add_node("10.0.0.5", 8585, label="kitchen-pi", token="secret")
    with sys_monitor_hub._nodes_lock:
        sys_monitor_hub._nodes[nid]["online"] = True
        sys_monitor_hub._nodes[nid]["status"] = {"cpu": {"usage": 12.3}}

    sys_monitor_hub._save_nodes()
    on_disk = sys_monitor_hub._NODES_FILE.read_text()
    import json

    persisted = json.loads(on_disk)

    assert set(persisted[nid].keys()) == {"host", "port", "label", "token", "added"}
    assert persisted[nid]["host"] == "10.0.0.5"
    assert persisted[nid]["token"] == "secret"


def test_load_nodes_round_trip():
    nid, _ = sys_monitor_hub._add_node("10.0.0.5", 8585, label="kitchen-pi", token="secret")
    sys_monitor_hub._save_nodes()

    sys_monitor_hub._nodes.clear()
    sys_monitor_hub._load_nodes()

    node = sys_monitor_hub._get_node(nid)
    assert node is not None
    assert node["host"] == "10.0.0.5"
    assert node["label"] == "kitchen-pi"
    assert node["token"] == "secret"
    # Runtime state resets on load, regardless of what it was before saving
    assert node["online"] is False
    assert node["_alert_state"]["online"] is False


def test_load_nodes_missing_file_is_a_noop():
    assert not sys_monitor_hub._NODES_FILE.exists()
    sys_monitor_hub._load_nodes()  # must not raise
    assert sys_monitor_hub._get_all_nodes() == {}


def test_load_nodes_corrupt_json_is_swallowed():
    sys_monitor_hub._NODES_FILE.write_text("{not valid json")
    sys_monitor_hub._load_nodes()  # must not raise
    assert sys_monitor_hub._get_all_nodes() == {}
