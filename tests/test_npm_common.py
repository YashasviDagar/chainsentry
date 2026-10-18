"""Tests for npm spec classification and name validation (parsers/npm_common.py)."""

from __future__ import annotations

import pytest

from chainsentry.parsers.npm_common import (
    SpecKind,
    classify_spec,
    exact_npm_version,
    is_official_registry_url,
    is_valid_npm_name,
)


@pytest.mark.parametrize(
    ("spec", "kind"),
    [
        ("4.17.21", SpecKind.EXACT),
        ("=4.17.21", SpecKind.EXACT),
        ("v4.17.21", SpecKind.EXACT),
        ("1.0.0-beta.2", SpecKind.EXACT),
        ("^4.17.0", SpecKind.RANGE),
        ("~1.2.3", SpecKind.RANGE),
        (">=1.0.0 <2.0.0", SpecKind.RANGE),
        ("1.x", SpecKind.RANGE),
        ("1.2.3 - 2.3.4", SpecKind.RANGE),
        ("^1.0.0 || ^2.0.0", SpecKind.RANGE),
        ("*", SpecKind.ANY),
        ("", SpecKind.ANY),
        ("latest", SpecKind.ANY),
        ("npm:lodash@^4", SpecKind.ALIAS),
        ("github:user/repo", SpecKind.GIT),
        ("user/repo#v1.0.0", SpecKind.GIT),
        ("git+https://github.com/u/r.git", SpecKind.GIT),
        ("git+ssh://git@github.com/u/r.git", SpecKind.GIT),
        ("https://example.com/pkg.tgz", SpecKind.URL),
        ("file:../shared", SpecKind.LOCAL),
        ("workspace:*", SpecKind.LOCAL),
    ],
)
def test_classify_spec(spec, kind):
    assert classify_spec(spec).kind is kind


def test_exact_spec_carries_clean_version():
    assert classify_spec("=v1.2.3".lstrip("=")).version == "1.2.3"
    assert classify_spec("=1.2.3").version == "1.2.3"


@pytest.mark.parametrize(
    ("spec", "name", "sub_spec"),
    [
        ("npm:lodash@^4.17.0", "lodash", "^4.17.0"),
        ("npm:@babel/core@7.24.0", "@babel/core", "7.24.0"),
        ("npm:left-pad", "left-pad", "*"),
    ],
)
def test_alias_is_split_into_real_name_and_spec(spec, name, sub_spec):
    parsed = classify_spec(spec)
    assert (parsed.alias_name, parsed.alias_spec) == (name, sub_spec)


@pytest.mark.parametrize(
    ("name", "valid"),
    [
        ("lodash", True),
        ("@babel/core", True),
        ("JSONStream", True),  # legacy mixed-case names still exist
        ("left-pad", True),
        ("", False),
        ("../../etc/passwd", False),  # SECURITY: path traversal attempt
        ("has space", False),
        ("@scope/", False),
        (".hidden", False),
        ("a" * 215, False),  # npm's 214-character limit
    ],
)
def test_is_valid_npm_name(name, valid):
    assert is_valid_npm_name(name) is valid


def test_exact_npm_version_rejects_ranges():
    assert exact_npm_version("^1.0.0") is None
    assert exact_npm_version("1.0") is None


@pytest.mark.parametrize(
    ("url", "official"),
    [
        ("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", True),
        ("https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz", True),
        ("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", False),  # no TLS
        ("https://registry.npmjs.org.evil.com/lodash.tgz", False),  # look-alike host
        ("git+ssh://git@github.com/u/r.git", False),
    ],
)
def test_is_official_registry_url(url, official):
    assert is_official_registry_url(url) is official
