"""Guards for the shared static/cc-base.css used by the node UI and the hub."""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / "static" / "cc-base.css"
TEMPLATES = [ROOT / "templates" / "index.html", ROOT / "hub" / "templates" / "hub.html"]
# Tokens owned by cc-base.css; templates must not redeclare them (that is how
# the two UIs drifted apart in the first place).
OWNED = ["--blue", "--orange", "--font-display", "--font-body", "--font-mono"]


@pytest.mark.parametrize("tpl", TEMPLATES, ids=lambda p: p.name)
def test_template_links_shared_css(tpl):
    assert 'href="/static/cc-base.css"' in tpl.read_text()


@pytest.mark.parametrize("tpl", TEMPLATES, ids=lambda p: p.name)
def test_template_does_not_redeclare_owned_tokens(tpl):
    text = tpl.read_text()
    for tok in OWNED:
        assert not re.search(rf"^\s*{re.escape(tok)}\s*:", text, re.M), (
            f"{tpl.name} redeclares {tok}; change it in static/cc-base.css instead"
        )


@pytest.mark.parametrize("tpl", TEMPLATES, ids=lambda p: p.name)
def test_template_has_no_inline_font_faces(tpl):
    assert "@font-face" not in tpl.read_text()


def test_base_defines_brand_tokens_and_fonts():
    css = BASE.read_text()
    assert "--blue: #2b7de9" in css and "--orange: #e07018" in css
    assert css.count("@font-face") == 4


def test_font_files_referenced_exist():
    for rel in re.findall(r'url\("/static/([^"]+)"\)', BASE.read_text()):
        assert (ROOT / "static" / rel).is_file(), rel


def test_node_serves_shared_css(node_client):
    r = node_client.get("/static/cc-base.css")
    assert r.status_code == 200 and b"--blue" in r.data
