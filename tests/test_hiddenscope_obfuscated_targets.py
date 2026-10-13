"""SOURCE_PATTERNS additions: network targets hidden via encoding."""
import pytest

import hiddenscope_scanner as hs

CASES = [
    ("import socket, struct\nh = socket.inet_ntoa(struct.pack('!I', 3232235777))\n",
     "IP address built from packed/integer value", "high"),
    ("h = socket.inet_ntoa(3232235777)\n",
     "IP address built from packed/integer value", "high"),
    ("ipaddress.ip_address(3232235777)\n", "IP address from integer literal", "high"),
    ("h = '.'.join([str(a), str(b), str(c), str(d)])\n",
     "IP address assembled from joined octets", "medium"),
    ("u = bytes([104,116,116,112,58,47,47]).decode()\n",
     "String decoded from literal byte list", "medium"),
    ("requests.get(base64.b64decode(CFG))\n",
     "Network call target decoded from base64", "high"),
]


@pytest.mark.parametrize("src,desc,sev", CASES)
def test_obfuscated_target_detected(tmp_path, src, desc, sev):
    f = tmp_path / "HARNESS_mod.py"
    f.write_text(src)
    hits = [x for x in hs.scan_file(f) if x.description == desc]
    assert hits and hits[0].severity == sev


@pytest.mark.parametrize(
    "src",
    [
        "h = socket.inet_ntoa(raw_bytes[4:8])\n",       # packed from a received buffer
        "name = bytes([1, 2]).decode()\n",              # too short to hide a host
        "requests.get('https://api.example.com')\n",    # literal target
        "# socket.inet_ntoa(struct.pack('!I', 1))\n",   # commented out
    ],
)
def test_benign_code_not_flagged(tmp_path, src):
    f = tmp_path / "HARNESS_ok.py"
    f.write_text(src)
    descs = {x.description for x in hs.scan_file(f)}
    assert not descs & {c[1] for c in CASES}


def test_test_path_downgrades_one_level(tmp_path):
    d = tmp_path / "tests"
    d.mkdir()
    f = d / "HARNESS_t.py"
    f.write_text("ipaddress.ip_address(3232235777)\n")
    hit = next(x for x in hs.scan_file(f) if x.description == "IP address from integer literal")
    assert hit.severity == "medium"
