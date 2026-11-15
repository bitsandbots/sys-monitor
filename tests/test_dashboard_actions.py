"""The dashboard must send the API token for the dangerous actions.

Quarantine and unblock are refused without a token even from the LAN
(SYSMONITOR_STRICT_ACTIONS), so the buttons go through ``actionFetch``, which asks
for the token once per browser session.
"""

from pathlib import Path

HTML = (Path(__file__).parent.parent / "templates" / "index.html").read_text()


def test_dangerous_actions_use_actionfetch():
    for endpoint in ("'/api/quarantine'", "'/api/blocks/'"):
        assert f"fetch({endpoint}" not in HTML, endpoint  # no bare fetch
        assert f"actionFetch({endpoint}" in HTML, endpoint


def test_tokens_live_in_sessionstorage_only():
    body = HTML.split("async function actionFetch")[1].split("async function api(")[0]
    assert "sessionStorage" in HTML and "localStorage" not in body
    assert "Authorization" in body and "X-Config-Token" in body
