"""Tests for the HTTP client (net/client.py): retries, caching, limits, offline mode."""

from __future__ import annotations

import httpx
import pytest
import respx

from chainsentry import config
from chainsentry.net.cache import Cache
from chainsentry.net.client import HttpClient, HttpError, OfflineError, quote_segment

URL = "https://api.example.test/thing"


@respx.mock
def test_get_json_decodes_response(client):
    respx.get(URL).mock(return_value=httpx.Response(200, json={"ok": True}))
    assert client.get_json(URL) == {"ok": True}


@respx.mock
def test_sends_user_agent(client):
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={}))
    client.get_json(URL)
    assert route.calls[0].request.headers["User-Agent"].startswith("chainsentry/")


@respx.mock
def test_retries_on_503_then_succeeds(client):
    route = respx.get(URL).mock(
        side_effect=[httpx.Response(503), httpx.Response(503), httpx.Response(200, json=1)]
    )
    assert client.get_json(URL) == 1
    assert route.call_count == 3


@respx.mock
def test_retries_on_connection_error(client):
    route = respx.get(URL).mock(
        side_effect=[httpx.ConnectError("boom"), httpx.Response(200, json=2)]
    )
    assert client.get_json(URL) == 2
    assert route.call_count == 2


@respx.mock
def test_gives_up_after_max_retries():
    waits: list[float] = []
    client = HttpClient(Cache(None), sleep=waits.append)
    route = respx.get(URL).mock(return_value=httpx.Response(500))
    with pytest.raises(HttpError, match="failed after"):
        client.get_json(URL)
    assert route.call_count == config.HTTP_MAX_RETRIES + 1
    assert len(waits) == config.HTTP_MAX_RETRIES


@respx.mock
def test_honours_retry_after_header():
    waits: list[float] = []
    client = HttpClient(Cache(None), sleep=waits.append)
    respx.get(URL).mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "7"}), httpx.Response(200, json=0)]
    )
    client.get_json(URL)
    assert waits == [7.0]


@respx.mock
def test_404_is_none_when_allowed(client):
    respx.get(URL).mock(return_value=httpx.Response(404))
    assert client.get_json(URL, not_found_ok=True) is None


@respx.mock
def test_404_raises_by_default(client):
    respx.get(URL).mock(return_value=httpx.Response(404))
    with pytest.raises(HttpError, match="404"):
        client.get_json(URL)


@respx.mock
def test_invalid_json_raises(client):
    respx.get(URL).mock(return_value=httpx.Response(200, content=b"<html>"))
    with pytest.raises(HttpError, match="not valid JSON"):
        client.get_json(URL)


@respx.mock
def test_cache_prevents_second_request(tmp_path):
    client = HttpClient(Cache(tmp_path / "c.sqlite3"))
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={"v": 1}))
    for _ in range(3):
        assert client.get_json(URL, cache_key="k", ttl=60) == {"v": 1}
    assert route.call_count == 1
    assert client.network_requests == 1


@respx.mock
def test_response_size_limit(client, monkeypatch):
    # SECURITY: a huge response is rejected instead of filling memory.
    monkeypatch.setattr(config, "MAX_RESPONSE_BYTES", 10)
    respx.get(URL).mock(return_value=httpx.Response(200, content=b"[" + b"1," * 50 + b"1]"))
    with pytest.raises(HttpError, match="larger than"):
        client.get_json(URL)


def test_offline_mode_refuses_network():
    client = HttpClient(Cache(None), offline=True)
    with pytest.raises(OfflineError):
        client.get_json(URL)


@pytest.mark.parametrize(
    ("value", "safe", "expected"),
    [
        ("lodash", "", "lodash"),
        ("@types/node", "@", "@types%2Fnode"),
        ("../../admin", "", "..%2F..%2Fadmin"),  # SECURITY: no path traversal
        ("GHSA-xxxx-yyyy", "", "GHSA-xxxx-yyyy"),
    ],
)
def test_quote_segment(value, safe, expected):
    assert quote_segment(value, safe=safe) == expected
