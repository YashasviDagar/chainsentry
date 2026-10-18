"""Tests for the SQLite TTL cache (net/cache.py)."""

from __future__ import annotations

from chainsentry.net.cache import MISS, Cache, make_key


class FakeClock:
    """A controllable clock so expiry can be tested without sleeping."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


def test_round_trip(tmp_path):
    cache = Cache(tmp_path / "c.sqlite3")
    cache.set_json("k", {"a": [1, 2]}, ttl=60)
    assert cache.get_json("k") == {"a": [1, 2]}


def test_missing_key_is_miss(tmp_path):
    assert Cache(tmp_path / "c.sqlite3").get_json("nope") is MISS


def test_none_is_a_valid_cached_value(tmp_path):
    # "package not found" is cached as None; it must not look like a miss.
    cache = Cache(tmp_path / "c.sqlite3")
    cache.set_json("k", None, ttl=60)
    assert cache.get_json("k") is None


def test_entries_expire(tmp_path):
    clock = FakeClock()
    cache = Cache(tmp_path / "c.sqlite3", clock=clock)
    cache.set_json("k", 1, ttl=10)
    clock.now += 11
    assert cache.get_json("k") is MISS
    assert cache.purge_expired() == 1


def test_persists_across_instances(tmp_path):
    Cache(tmp_path / "c.sqlite3").set_json("k", "v", ttl=60)
    assert Cache(tmp_path / "c.sqlite3").get_json("k") == "v"


def test_clear(tmp_path):
    cache = Cache(tmp_path / "c.sqlite3")
    cache.set_json("a", 1, ttl=60)
    cache.set_json("b", 2, ttl=60)
    assert cache.clear() == 2
    assert cache.get_json("a") is MISS


def test_disabled_cache_stores_nothing():
    cache = Cache(None)
    cache.set_json("k", 1, ttl=60)
    assert cache.get_json("k") is MISS
    assert not cache.enabled


def test_make_key_is_stable_and_order_independent():
    assert make_key({"a": 1, "b": 2}) == make_key({"b": 2, "a": 1})
    assert make_key("x") != make_key("y")
