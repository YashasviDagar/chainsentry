"""Tests for the package.json parser (parsers/npm_package_json.py)."""

from __future__ import annotations

import pytest

from chainsentry.models import Ecosystem
from chainsentry.parsers.base import NON_REGISTRY_SOURCE, NPM_ALIAS, UNPINNED, ParseError
from chainsentry.parsers.npm_package_json import declared_names, parse_package_json


def by_name(result):
    return {d.name: d for d in result.dependencies}


def codes(result, dep):
    return [f.code for f in result.findings_for(dep)]


def test_sections_and_dev_flags(write_json):
    path = write_json(
        "package.json",
        {
            "dependencies": {"express": "4.18.2"},
            "optionalDependencies": {"fsevents": "2.3.3"},
            "devDependencies": {"jest": "29.7.0"},
            "peerDependencies": {"react": "^18"},
        },
    )
    deps = by_name(parse_package_json(path))
    assert set(deps) == {"express", "fsevents", "jest"}  # peers are not listed
    assert deps["jest"].dev and not deps["express"].dev
    assert all(d.direct and d.ecosystem is Ecosystem.NPM for d in deps.values())


def test_exact_version_has_no_findings(write_json):
    result = parse_package_json(write_json("package.json", {"dependencies": {"lodash": "4.17.21"}}))
    dep = by_name(result)["lodash"]
    assert dep.version == "4.17.21"
    assert codes(result, dep) == []


def test_range_is_unpinned(write_json):
    result = parse_package_json(write_json("package.json", {"dependencies": {"lodash": "^4.17.0"}}))
    dep = by_name(result)["lodash"]
    assert dep.version is None and dep.spec == "^4.17.0"
    assert codes(result, dep) == [UNPINNED]


def test_git_dependency_is_non_registry(write_json):
    result = parse_package_json(
        write_json("package.json", {"dependencies": {"lib": "github:org/lib#v1"}})
    )
    assert codes(result, by_name(result)["lib"]) == [NON_REGISTRY_SOURCE]


def test_alias_resolves_to_real_package(write_json):
    result = parse_package_json(
        write_json("package.json", {"dependencies": {"my-utils": "npm:left-pad@1.3.0"}})
    )
    deps = by_name(result)
    assert "my-utils" not in deps
    assert deps["left-pad"].version == "1.3.0"
    assert codes(result, deps["left-pad"]) == [NPM_ALIAS]


def test_local_path_dependency_is_skipped(write_json):
    result = parse_package_json(write_json("package.json", {"dependencies": {"x": "file:../x"}}))
    assert result.dependencies == []
    assert "local path" in result.warnings[0]


def test_invalid_name_is_skipped(write_json):
    result = parse_package_json(write_json("package.json", {"dependencies": {"../evil": "1.0.0"}}))
    assert result.dependencies == []
    assert "not a valid npm package name" in result.warnings[0]


def test_production_wins_when_listed_twice(write_json):
    result = parse_package_json(
        write_json(
            "package.json",
            {"dependencies": {"a": "1.0.0"}, "devDependencies": {"a": "1.0.0"}},
        )
    )
    assert by_name(result)["a"].dev is False


def test_wrong_section_type_warns(write_json):
    result = parse_package_json(write_json("package.json", {"dependencies": ["lodash"]}))
    assert result.dependencies == []
    assert "should be an object" in result.warnings[0]


def test_invalid_json_raises(write):
    with pytest.raises(ParseError, match="invalid JSON"):
        parse_package_json(write("package.json", "{ not json"))


def test_top_level_must_be_object(write_json):
    with pytest.raises(ParseError, match="JSON object"):
        parse_package_json(write_json("package.json", ["a", "b"]))


def test_declared_names_includes_peers():
    data = {"dependencies": {"a": "1"}, "peerDependencies": {"b": "2"}}
    assert declared_names(data) == {"a", "b"}
