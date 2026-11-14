"""The hub must serve the shared stylesheet (from hub/static or the repo's static/)."""


def test_hub_serves_shared_css(hub_client):
    r = hub_client.get("/static/cc-base.css")
    assert r.status_code == 200 and b"--blue" in r.data


def test_hub_serves_fonts(hub_client):
    r = hub_client.get("/static/fonts/exo-2-latin-700-normal.woff2")
    assert r.status_code == 200
