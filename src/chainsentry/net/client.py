"""HTTP client shared by every network check (OSV, npm registry, PyPI).

Responsibilities, all in one place so no check can forget them:

* **Timeouts on every request** - a hung connection must never hang CI.
* **Retries with exponential backoff + jitter** for transient failures
  (connection errors, timeouts, HTTP 429 "too many requests", 5xx), and
  honouring the server's ``Retry-After`` header.
* **Caching** of JSON responses through :class:`~chainsentry.net.cache.Cache`.
* **Offline mode** - ``--offline`` turns any network access into a clear
  error instead of a silent hang.
* **Response size limit** - a hostile or broken server cannot exhaust memory.
* **Safe URL building** - :func:`quote_segment` makes a package name one
  path segment, whatever characters it contains.

Why httpx? Its timeouts are explicit and it has a first-class mocking
library (``respx``), so the unit tests never touch the real network.
"""

from __future__ import annotations

import json
import random
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

import httpx

from chainsentry import config
from chainsentry.net.cache import MISS, Cache

#: Status codes worth retrying: rate limited, or a temporary server problem.
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})


class HttpError(Exception):
    """A request failed for good (after retries) or returned an unexpected status."""


class OfflineError(HttpError):
    """Network access was attempted while running with ``--offline``."""


def quote_segment(value: str, *, safe: str = "") -> str:
    """Percent-encode ``value`` so it is exactly one URL path segment.

    SECURITY: without this, a package called ``../../-/user/admin`` would
    change *which endpoint* we call (path traversal against the API). With
    it, ``/`` becomes ``%2F`` and the name stays inside its segment.

    >>> quote_segment("@types/node", safe="@")
    '@types%2Fnode'
    """
    return quote(value, safe=safe)


class HttpClient:
    """Thin wrapper around ``httpx.Client`` adding retries, caching and limits.

    Args:
        cache: Response cache (``Cache(None)`` to disable).
        offline: Refuse all network access.
        transport: Custom httpx transport (tests use ``respx`` instead).
        sleep: Function used to wait between retries; tests pass a no-op.
    """

    def __init__(
        self,
        cache: Cache | None = None,
        *,
        offline: bool = False,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.cache = cache or Cache(None)
        self.offline = offline
        self._sleep = sleep
        self._client = httpx.Client(
            timeout=httpx.Timeout(config.HTTP_READ_TIMEOUT, connect=config.HTTP_CONNECT_TIMEOUT),
            headers={"User-Agent": config.USER_AGENT, "Accept": "application/json"},
            follow_redirects=True,
            transport=transport,
        )
        #: Number of requests that actually went over the network (for stats/tests).
        self.network_requests = 0

    # -- public API ---------------------------------------------------------

    def get_json(
        self,
        url: str,
        *,
        cache_key: str | None = None,
        ttl: float = 0,
        headers: dict[str, str] | None = None,
        not_found_ok: bool = False,
    ) -> Any:
        """GET ``url`` and decode JSON.

        Args:
            cache_key: If given, the decoded response is cached under this key.
            ttl: Cache lifetime in seconds.
            headers: Extra request headers.
            not_found_ok: Return ``None`` on HTTP 404 instead of raising
                (used for "does this package exist?" lookups). A 404 is
                cached for ``config.TTL_NOT_FOUND``.
        """
        return self._cached_request(
            "GET", url, cache_key=cache_key, ttl=ttl, headers=headers, not_found_ok=not_found_ok
        )

    def post_json(
        self, url: str, payload: Any, *, cache_key: str | None = None, ttl: float = 0
    ) -> Any:
        """POST ``payload`` as JSON to ``url`` and decode the JSON response."""
        return self._cached_request("POST", url, cache_key=cache_key, ttl=ttl, json_body=payload)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- internals ----------------------------------------------------------

    def _cached_request(
        self,
        method: str,
        url: str,
        *,
        cache_key: str | None,
        ttl: float,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        not_found_ok: bool = False,
    ) -> Any:
        if cache_key is not None:
            cached = self.cache.get_json(cache_key)
            if cached is not MISS:
                return cached

        status, data = self._request(method, url, headers=headers, json_body=json_body)
        if status == 404 and not_found_ok:
            if cache_key is not None:
                self.cache.set_json(cache_key, None, config.TTL_NOT_FOUND)
            return None
        if status >= 400:
            raise HttpError(f"{method} {url} -> HTTP {status}")

        if cache_key is not None and ttl > 0:
            self.cache.set_json(cache_key, data, ttl)
        return data

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None,
        json_body: Any,
    ) -> tuple[int, Any]:
        """Send one request with retries. Returns (status, decoded JSON or None)."""
        if self.offline:
            raise OfflineError(f"offline mode: refusing to fetch {url}")

        last_error: str = ""
        for attempt in range(config.HTTP_MAX_RETRIES + 1):
            wait: float | None = None
            try:
                self.network_requests += 1
                status, body, retry_after = self._send(method, url, headers, json_body)
            except httpx.TransportError as exc:
                # Connection refused, DNS failure, timeout... all transient-ish.
                last_error = f"{type(exc).__name__}: {exc}"
            else:
                if status not in _RETRY_STATUS:
                    if status >= 400:
                        return status, None
                    try:
                        return status, _decode_json(body)
                    except ValueError as exc:
                        raise HttpError(f"{method} {url}: response is not valid JSON") from exc
                last_error = f"HTTP {status}"
                wait = retry_after

            if attempt == config.HTTP_MAX_RETRIES:
                break
            if wait is None:
                # Exponential backoff with "full jitter": spreading retries out
                # randomly stops many clients from retrying in lock-step.
                wait = config.HTTP_BACKOFF_BASE * (2**attempt) * (0.5 + random.random())  # noqa: S311
            self._sleep(min(wait, config.HTTP_MAX_RETRY_AFTER))

        raise HttpError(
            f"{method} {url} failed after {config.HTTP_MAX_RETRIES + 1} tries: {last_error}"
        )

    def _send(
        self, method: str, url: str, headers: dict[str, str] | None, json_body: Any
    ) -> tuple[int, bytes, float | None]:
        """Stream the response, enforcing the size limit while reading."""
        with self._client.stream(method, url, headers=headers, json=json_body) as response:
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                # SECURITY: stop reading as soon as the limit is crossed rather
                # than buffering a multi-GB body first.
                if size > config.MAX_RESPONSE_BYTES:
                    raise HttpError(
                        f"{method} {url}: response larger than {config.MAX_RESPONSE_BYTES} bytes"
                    )
                chunks.append(chunk)
            return response.status_code, b"".join(chunks), _retry_after(response)


def _decode_json(body: bytes) -> Any:
    """Decode a JSON body; an empty body decodes to ``None``."""
    return json.loads(body) if body else None


def _retry_after(response: httpx.Response) -> float | None:
    """Parse a ``Retry-After: <seconds>`` header (the HTTP-date form is ignored)."""
    value = response.headers.get("Retry-After")
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None
