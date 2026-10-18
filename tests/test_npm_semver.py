"""Tests for the npm range matcher (parsers/npm_semver.py).

Expected results follow npm's node-semver documentation.
"""

from __future__ import annotations

import pytest

from chainsentry.parsers.npm_semver import SemVer, UnsupportedRange, max_satisfying, satisfies

VERSIONS = [
    "0.0.3", "0.0.4", "0.2.3", "0.2.9", "0.3.0",
    "1.2.2", "1.2.3", "1.2.9", "1.3.0-beta.1", "1.3.0", "1.9.9",
    "2.0.0-rc.1", "2.0.0", "2.1.0",
]  # fmt: skip


@pytest.mark.parametrize(
    ("range_text", "expected"),
    [
        ("^1.2.3", "1.9.9"),  # same major
        ("~1.2.3", "1.2.9"),  # same minor
        ("1.x", "1.9.9"),
        ("1", "1.9.9"),
        ("1.2", "1.2.9"),
        ("*", "2.1.0"),
        ("", "2.1.0"),
        (">1.2", "2.1.0"),
        (">=1.2.4 <1.3.0", "1.2.9"),
        ("<1.3", "1.2.9"),
        ("<=1.2", "1.2.9"),
        ("1.2.3 - 1.9", "1.9.9"),  # partial upper bound is inclusive of 1.9.x
        ("1.2.3 - 2.0.0", "2.0.0"),
        ("^0.2.3", "0.2.9"),  # ^ on 0.x only allows patch updates within the minor
        ("^0.0.3", "0.0.3"),  # ^0.0.x pins the exact patch
        ("~1", "1.9.9"),
        ("^1.2.3 || ^2.0.0", "2.1.0"),
        ("1.2.3", "1.2.3"),
        ("=1.2.3", "1.2.3"),
        ("^3.0.0", None),
    ],
)
def test_max_satisfying(range_text, expected):
    assert max_satisfying(VERSIONS, range_text) == expected


def test_prereleases_are_excluded_unless_requested():
    assert not satisfies("1.3.0-beta.1", "^1.2.0")
    assert satisfies("1.3.0-beta.1", "^1.3.0-beta.0")
    assert max_satisfying(VERSIONS, "2.0.0-rc.1") == "2.0.0-rc.1"


@pytest.mark.parametrize(
    ("smaller", "bigger"),
    [
        ("1.0.0", "1.0.1"),
        ("1.0.0-alpha", "1.0.0"),  # a release beats its prereleases
        ("1.0.0-alpha", "1.0.0-alpha.1"),
        ("1.0.0-alpha.1", "1.0.0-alpha.beta"),  # numeric < alphanumeric
        ("1.0.0-beta.2", "1.0.0-beta.11"),  # numeric compare, not string
        ("1.0.0-rc.1", "1.0.0"),
    ],
)
def test_semver_ordering(smaller, bigger):
    assert SemVer.parse(smaller) < SemVer.parse(bigger)


def test_invalid_versions_in_list_are_ignored():
    assert max_satisfying(["not-a-version", "1.0.0"], "^1") == "1.0.0"


def test_unsupported_range_raises():
    with pytest.raises(UnsupportedRange):
        max_satisfying(VERSIONS, "^banana")
