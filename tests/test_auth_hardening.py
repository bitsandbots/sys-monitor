"""require_auth hardening: constant-time compare, per-IP lockout, LAN bypass
toggle, DNS-rebinding Host guard, and security headers.

Tokens here are HARNESS_-prefixed fixtures, never real credentials.
"""

import pytest

import sys_monitor

TOKEN = "HARNESS_token_0123456789"
URL = "/api/boot"  # a plain GET route behind @require_auth


@pytest.fixture(autouse=True)
def _auth_state(monkeypatch):
    sys_monitor._auth_failures.clear()
    monkeypatch.setitem(sys_monitor.CONFIG, "auth_token", TOKEN)
    monkeypatch.setitem(sys_monitor.CONFIG, "lan_no_auth", False)
    monkeypatch.setattr(sys_monitor, "log_event", lambda *a, **k: None)
    yield
    sys_monitor._auth_failures.clear()


def _get(ip="8.8.8.8", headers=None, host="localhost"):
    client = sys_monitor.app.test_client()
    return client.get(
        URL,
        headers=headers or {},
        environ_overrides={"REMOTE_ADDR": ip, "HTTP_HOST": host},
    )


def test_missing_token_rejected():
    assert _get().status_code == 401


def test_correct_token_accepted():
    r = _get(headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200


def test_wrong_token_rejected():
    assert _get(headers={"Authorization": "Bearer HARNESS_wrong"}).status_code == 401


def test_non_ascii_header_does_not_raise():
    # compare_digest on str raises for non-ASCII; the bytes form must not.
    r = _get(headers={"Authorization": "Bearer héllo".encode("latin-1")})
    assert r.status_code == 401


def test_lockout_after_repeated_failures():
    for _ in range(sys_monitor._AUTH_FAIL_MAX):
        assert _get(headers={"Authorization": "Bearer nope"}).status_code == 401
    # Even the right token is refused while locked out.
    assert _get(headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 429
    # A different client is unaffected.
    other = _get(ip="1.1.1.1", headers={"Authorization": f"Bearer {TOKEN}"})
    assert other.status_code == 200


@pytest.mark.parametrize("ip", ["127.0.0.1", "192.168.1.50", "10.1.2.3", "::1"])
def test_lan_client_skips_token_when_enabled(monkeypatch, ip):
    monkeypatch.setitem(sys_monitor.CONFIG, "lan_no_auth", True)
    assert _get(ip=ip).status_code == 200


def test_public_client_still_needs_token_when_lan_bypass_enabled(monkeypatch):
    monkeypatch.setitem(sys_monitor.CONFIG, "lan_no_auth", True)
    assert _get(ip="8.8.8.8").status_code == 401


def test_lan_bypass_off_requires_token_from_lan_clients():
    assert _get(ip="192.168.1.50").status_code == 401


def test_lan_bypass_is_off_by_default():
    import os
    import subprocess
    import sys

    env = {k: v for k, v in os.environ.items() if k != "SYSMONITOR_LAN_NO_AUTH"}
    out = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys_monitor as m; print(m.CONFIG['lan_no_auth'])",
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    assert out.stdout.strip() == "False", out.stderr


def test_unknown_host_header_rejected():
    r = _get(headers={"Authorization": f"Bearer {TOKEN}"}, host="evil.example")
    assert r.status_code == 400


def test_ip_literal_host_allowed():
    r = _get(headers={"Authorization": f"Bearer {TOKEN}"}, host="10.0.0.5:8585")
    assert r.status_code == 200


def test_security_headers_present():
    r = _get(headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Cache-Control"] == "no-store"
