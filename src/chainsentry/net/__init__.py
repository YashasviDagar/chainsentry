"""Networking layer: one HTTP client (timeouts, retries, limits) plus an on-disk cache.

Checks never create their own ``httpx`` clients; they receive an
:class:`HttpClient`, which keeps network policy in one place and lets tests
swap in mocked responses.
"""

from chainsentry.net.cache import MISS, Cache, make_key
from chainsentry.net.client import HttpClient, HttpError, OfflineError, quote_segment

__all__ = ["MISS", "Cache", "HttpClient", "HttpError", "OfflineError", "make_key", "quote_segment"]
