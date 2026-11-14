"""Tests for mDNS (avahi-browse) fleet discovery."""
import subprocess

import sys_monitor_hub

SAMPLE = r"""+;enp1s0;IPv4;SysMonitor\032on\032cake;_sysmonitor._tcp;local
+;enp1s0;IPv6;SysMonitor\032on\032cake;_sysmonitor._tcp;local
=;enp1s0;IPv4;SysMonitor\032on\032cake;_sysmonitor._tcp;local;cake.local;192.168.0.150;8585;"app=sys-monitor" "version=2.5.1"
=;wlan0;IPv4;SysMonitor\032on\032cake;_sysmonitor._tcp;local;cake.local;192.168.0.150;8585;"app=sys-monitor" "version=2.5.1"
=;enp1s0;IPv6;SysMonitor\032on\032cake;_sysmonitor._tcp;local;cake.local;fe80::1;8585;"app=sys-monitor"
=;wlan0;IPv4;SysMonitor\032on\032pecan;_sysmonitor._tcp;local;pecan.local;192.168.0.249;8585;"hostname=pecan" "model=Raspberry Pi 5"
=;wlan0;IPv4;bad;_sysmonitor._tcp;local;x.local;not-an-ip;8585;
=;wlan0;IPv4;bad2;_sysmonitor._tcp;local;x.local;10.0.0.1;notaport;
"""


def test_parse_keeps_resolved_ipv4_and_dedupes():
    out = sys_monitor_hub._parse_avahi_browse(SAMPLE)
    assert [(e["host"], e["port"]) for e in out] == [("192.168.0.150", 8585), ("192.168.0.249", 8585)]
    cake, pecan = out
    assert cake["hostname"] == "cake" and cake["version"] == "2.5.1"
    assert pecan["hostname"] == "pecan" and pecan["model"] == "Raspberry Pi 5"


def test_avahi_unescape_decodes_decimal_bytes():
    assert sys_monitor_hub._avahi_unescape(r"a\032b\058c") == "a b:c"


def test_discover_mdns_none_without_avahi(monkeypatch):
    monkeypatch.setattr(sys_monitor_hub.shutil, "which", lambda n: None)
    assert sys_monitor_hub._discover_mdns() is None


def test_discover_mdns_marks_registered(monkeypatch):
    monkeypatch.setattr(sys_monitor_hub.shutil, "which", lambda n: "/usr/bin/avahi-browse")
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=SAMPLE, stderr="")

    monkeypatch.setattr(sys_monitor_hub.subprocess, "run", fake_run)
    rid = sys_monitor_hub._generate_id("192.168.0.150", 8585)
    monkeypatch.setattr(sys_monitor_hub, "_get_all_nodes", lambda: {rid: {}})
    found = sys_monitor_hub._discover_mdns()
    assert calls[0][:3] == ["avahi-browse", "-rpt", "_sysmonitor._tcp"]  # list args, no shell
    assert {e["host"]: e["already_registered"] for e in found} == {
        "192.168.0.150": True,
        "192.168.0.249": False,
    }


def test_discover_mdns_timeout_returns_empty(monkeypatch):
    monkeypatch.setattr(sys_monitor_hub.shutil, "which", lambda n: "/x")

    def boom(*a, **k):
        raise subprocess.TimeoutExpired("avahi-browse", 8)

    monkeypatch.setattr(sys_monitor_hub.subprocess, "run", boom)
    assert sys_monitor_hub._discover_mdns() == []


def test_api_discover_mdns_route(hub_client, monkeypatch):
    monkeypatch.setattr(sys_monitor_hub, "_discover_mdns", lambda: [{"host": "10.0.0.5", "port": 8585}])
    r = hub_client.post("/api/discover", json={"method": "mdns"})
    assert r.status_code == 200
    assert r.get_json()["method"] == "mdns" and r.get_json()["count"] == 1


def test_api_discover_mdns_without_avahi_is_501(hub_client, monkeypatch):
    monkeypatch.setattr(sys_monitor_hub, "_discover_mdns", lambda: None)
    r = hub_client.post("/api/discover", json={"method": "mdns"})
    assert r.status_code == 501 and "avahi" in r.get_json()["error"]


def test_api_discover_rejects_unknown_method(hub_client):
    assert hub_client.post("/api/discover", json={"method": "carrier-pigeon"}).status_code == 400


def test_api_discover_default_is_scan(hub_client, monkeypatch):
    monkeypatch.setattr(sys_monitor_hub, "_discover_subnet", lambda s, p: [])
    # scan responses keep their original shape (no "method" key) for old clients
    assert hub_client.post("/api/discover", json={}).get_json() == {"found": [], "count": 0}
