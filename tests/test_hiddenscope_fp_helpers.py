"""hiddenscope_scanner.py: false-positive-reduction helpers used by the
static file scanner. All pure functions -- no I/O, nothing to mock."""
from pathlib import Path

import hiddenscope_scanner as hs


# ── _entropy ────────────────────────────────────────────────────────────


def test_entropy_short_strings_are_zero():
    assert hs._entropy("") == 0.0
    assert hs._entropy("a") == 0.0


def test_entropy_repeated_char_is_zero():
    assert hs._entropy("aaaaaaaa") == 0.0


def test_entropy_all_distinct_chars_is_log2_n():
    # 8 distinct characters, each frequency 1/8 -> entropy == log2(8) == 3.0
    assert hs._entropy("aB3kL9zQ") == 3.0


# ── _is_placeholder_cred ────────────────────────────────────────────────


def test_is_placeholder_cred_known_placeholder():
    assert hs._is_placeholder_cred("enter_key_here") is True


def test_is_placeholder_cred_too_short():
    assert hs._is_placeholder_cred("ab1") is True


def test_is_placeholder_cred_low_entropy_repeated():
    assert hs._is_placeholder_cred("xxxxxxxx") is True


def test_is_placeholder_cred_all_digits():
    assert hs._is_placeholder_cred("1234567890") is True


def test_is_placeholder_cred_real_looking_secret_is_not_placeholder():
    assert hs._is_placeholder_cred("kX9$mQ2!zR7#wP4@") is False


# ── _ip_is_documentation ─────────────────────────────────────────────────


def test_ip_is_documentation_rfc5737_test_net():
    assert hs._ip_is_documentation("192.0.2.1") is True  # TEST-NET-1
    assert hs._ip_is_documentation("198.51.100.5") is True  # TEST-NET-2
    assert hs._ip_is_documentation("203.0.113.10") is True  # TEST-NET-3


def test_ip_is_documentation_real_public_ip_is_false():
    assert hs._ip_is_documentation("8.8.8.8") is False


def test_ip_is_documentation_malformed_fails_toward_not_flagging():
    assert hs._ip_is_documentation("not-an-ip") is True


# ── _extract_url_domain / _domain_is_benign ──────────────────────────────


def test_extract_url_domain():
    assert hs._extract_url_domain(b"https://example.com/path?query=1") == "example.com"
    assert hs._extract_url_domain(b"https://api.example.com:8443/x") == "api.example.com"


def test_domain_is_benign_exact_and_subdomain():
    assert hs._domain_is_benign("example.com", set()) is True
    assert hs._domain_is_benign("api.example.com", set()) is True  # subdomain of a benign domain


def test_domain_is_benign_unrelated_domain_is_false():
    assert hs._domain_is_benign("evil.example-lookalike.net", set()) is False


def test_domain_is_benign_respects_extra_allowlist():
    assert hs._domain_is_benign("mycompany.internal", set()) is False
    assert hs._domain_is_benign("mycompany.internal", {"mycompany.internal"}) is True


def test_domain_is_benign_empty_domain_is_false():
    assert hs._domain_is_benign("", set()) is False


# ── _is_comment_line / _byte_is_comment_line ─────────────────────────────


def test_is_comment_line_detects_hash_and_slash_comments():
    text = "real_code = 1\n  # this line is a comment with a secret=hunter2\nmore_code = 2"
    comment_pos = text.index("secret=hunter2")
    real_code_pos = text.index("real_code")
    assert hs._is_comment_line(text, comment_pos) is True
    assert hs._is_comment_line(text, real_code_pos) is False


def test_byte_is_comment_line_mirrors_text_version():
    data = b"real_code = 1\n  // this line is a comment\nmore_code = 2"
    comment_pos = data.index(b"comment")
    real_code_pos = data.index(b"real_code")
    assert hs._byte_is_comment_line(data, comment_pos) is True
    assert hs._byte_is_comment_line(data, real_code_pos) is False


# ── _in_test_path ─────────────────────────────────────────────────────────


def test_in_test_path_detects_test_directories():
    assert hs._in_test_path(Path("/repo/tests/foo.py")) is True
    assert hs._in_test_path(Path("/repo/src/fixtures/data.json")) is True
    assert hs._in_test_path(Path("/repo/examples/demo.py")) is True


def test_in_test_path_ordinary_source_path_is_false():
    assert hs._in_test_path(Path("/repo/src/main.py")) is False
