"""Unit tests for LLM model-serving detection.

Covers gap-analysis items 2 (LLM-detection probing, mocked HTTP) and 6
(regression guard for the port-range constant) -- see TESTING_STRATEGY.md.

_http_get_json() uses stdlib urllib.request, not requests, so these tests
mock urllib.request.urlopen directly -- no HTTP-mocking dependency needed.
"""
import json
import urllib.error
from contextlib import contextmanager

import sys_monitor


class _FakeResponse:
    def __init__(self, status: int, body: dict):
        self.status = status
        self._body = json.dumps(body).encode("utf-8")

    def read(self):
        return self._body


def _urlopen_router(responses: dict):
    """responses maps a URL suffix (e.g. "/api/tags") to either a dict
    (200 JSON body) or None (raise URLError, simulating connection
    refused / not this kind of server)."""

    @contextmanager
    def fake_urlopen(req, timeout=None):
        url = req.full_url
        for suffix, body in responses.items():
            if url.endswith(suffix):
                if body is None:
                    raise urllib.error.URLError("connection refused")
                yield _FakeResponse(200, body)
                return
        raise urllib.error.URLError("connection refused")

    return fake_urlopen


def test_max_scanned_port_includes_ollama():
    """Regression guard: this exact bug already shipped once -- the port
    scan was capped at 9999, excluding Ollama's default port 11434, so
    Ollama instances silently never appeared. _MAX_SCANNED_PORT must
    always cover at least Ollama's well-known port."""
    assert sys_monitor._MAX_SCANNED_PORT >= 11434
    assert 11434 in sys_monitor.LLM_PORTS


def test_probe_llm_port_ollama_native_api(monkeypatch):
    monkeypatch.setattr(
        sys_monitor.urllib.request,
        "urlopen",
        _urlopen_router({"/api/tags": {"models": [{"name": "llama3:8b"}, {"model": "qwen2.5:7b"}]}}),
    )
    result = sys_monitor._probe_llm_port(11434)
    assert result == {"serving": True, "api": "ollama", "models": ["llama3:8b", "qwen2.5:7b"]}


def test_probe_llm_port_openai_compatible(monkeypatch):
    """Ollama's endpoint isn't present (404/refused) but /v1/models is --
    the llama.cpp/vLLM/LM Studio shape."""
    monkeypatch.setattr(
        sys_monitor.urllib.request,
        "urlopen",
        _urlopen_router({"/api/tags": None, "/v1/models": {"data": [{"id": "mistral-7b-instruct"}]}}),
    )
    result = sys_monitor._probe_llm_port(8000)
    assert result == {"serving": True, "api": "openai-compatible", "models": ["mistral-7b-instruct"]}


def test_probe_llm_port_open_but_not_serving(monkeypatch):
    """Port is open (that's how we got here) but neither known API
    responds with a real model list -- must report not-serving, never
    raise, per _http_get_json's documented any-failure-returns-None
    contract."""
    monkeypatch.setattr(
        sys_monitor.urllib.request,
        "urlopen",
        _urlopen_router({"/api/tags": None, "/v1/models": None}),
    )
    result = sys_monitor._probe_llm_port(4000)
    assert result == {"serving": False, "api": None, "models": []}


def test_probe_llm_port_prefers_ollama_when_both_present(monkeypatch):
    """If a port somehow answers both shapes, Ollama's native API wins --
    it's checked first and returns immediately on a non-empty model list."""
    monkeypatch.setattr(
        sys_monitor.urllib.request,
        "urlopen",
        _urlopen_router(
            {
                "/api/tags": {"models": [{"name": "llama3:8b"}]},
                "/v1/models": {"data": [{"id": "should-not-be-used"}]},
            }
        ),
    )
    result = sys_monitor._probe_llm_port(11434)
    assert result["api"] == "ollama"
    assert result["models"] == ["llama3:8b"]
