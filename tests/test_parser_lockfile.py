"""Tests for the npm lockfile parser (parsers/npm_lockfile.py), lockfile v1-v3."""

from __future__ import annotations

import pytest

from chainsentry.parsers.base import (
    MISSING_INTEGRITY,
    NON_REGISTRY_SOURCE,
    NPM_ALIAS,
    ParseError,
)
from chainsentry.parsers.npm_lockfile import parse_npm_lockfile

REGISTRY = "https://registry.npmjs.org"


def entry(name: str, version: str, **extra):
    """A typical registry entry with resolved URL and integrity hash."""
    return {
        "version": version,
        "resolved": f"{REGISTRY}/{name}/-/{name.split('/')[-1]}-{version}.tgz",
        "integrity": "sha512-AAAA",
        **extra,
    }


def by_name_version(result):
    return {(d.name, d.version): d for d in result.dependencies}


def codes(result, dep):
    return [f.code for f in result.findings_for(dep)]


class TestV2V3PackagesMap:
    def lock(self, packages, version=3):
        return {"name": "app", "lockfileVersion": version, "packages": packages}

    def test_direct_transitive_and_nested_versions(self, write_json):
        path = write_json(
            "package-lock.json",
            self.lock(
                {
                    "": {"dependencies": {"express": "^4"}, "devDependencies": {"jest": "^29"}},
                    "node_modules/express": entry("express", "4.18.2"),
                    "node_modules/debug": entry("debug", "4.3.4"),
                    # express needs an older debug, installed nested:
                    "node_modules/express/node_modules/debug": entry("debug", "2.6.9"),
                    "node_modules/jest": entry("jest", "29.7.0", dev=True),
                }
            ),
        )
        deps = by_name_version(parse_npm_lockfile(path))
        assert deps[("express", "4.18.2")].direct
        assert not deps[("debug", "4.3.4")].direct
        assert not deps[("debug", "2.6.9")].direct  # both debug versions are kept
        assert deps[("jest", "29.7.0")].dev and deps[("jest", "29.7.0")].direct

    def test_nested_copy_of_direct_name_is_transitive(self, write_json):
        path = write_json(
            "package-lock.json",
            self.lock(
                {
                    "": {"dependencies": {"debug": "^4"}},
                    "node_modules/debug": entry("debug", "4.3.4"),
                    "node_modules/x/node_modules/debug": entry("debug", "2.6.9"),
                }
            ),
        )
        deps = by_name_version(parse_npm_lockfile(path))
        assert deps[("debug", "4.3.4")].direct
        assert not deps[("debug", "2.6.9")].direct

    def test_scoped_package_name(self, write_json):
        path = write_json(
            "package-lock.json",
            self.lock({"": {}, "node_modules/@babel/core": entry("@babel/core", "7.24.0")}),
        )
        assert ("@babel/core", "7.24.0") in by_name_version(parse_npm_lockfile(path))

    def test_alias_uses_real_name(self, write_json):
        path = write_json(
            "package-lock.json",
            self.lock(
                {
                    "": {"dependencies": {"my-utils": "npm:left-pad@1.3.0"}},
                    "node_modules/my-utils": {"name": "left-pad", **entry("left-pad", "1.3.0")},
                }
            ),
        )
        result = parse_npm_lockfile(path)
        dep = by_name_version(result)[("left-pad", "1.3.0")]
        assert dep.direct
        assert codes(result, dep) == [NPM_ALIAS]

    def test_workspace_folders_and_links_are_skipped(self, write_json):
        path = write_json(
            "package-lock.json",
            self.lock(
                {
                    "": {"workspaces": ["packages/*"]},
                    "packages/app": {"version": "1.0.0"},
                    "node_modules/app": {"resolved": "packages/app", "link": True},
                    "node_modules/lodash": entry("lodash", "4.17.21"),
                }
            ),
        )
        assert list(by_name_version(parse_npm_lockfile(path))) == [("lodash", "4.17.21")]

    def test_non_registry_resolved_url_is_flagged(self, write_json):
        path = write_json(
            "package-lock.json",
            self.lock(
                {
                    "": {},
                    "node_modules/lib": {
                        "version": "1.0.0",
                        "resolved": "git+ssh://git@github.com/org/lib.git#abc",
                    },
                }
            ),
        )
        result = parse_npm_lockfile(path)
        assert codes(result, result.dependencies[0]) == [NON_REGISTRY_SOURCE]

    def test_missing_integrity_is_flagged(self, write_json):
        path = write_json(
            "package-lock.json",
            self.lock(
                {
                    "": {},
                    "node_modules/lodash": {
                        "version": "4.17.21",
                        "resolved": f"{REGISTRY}/lodash/-/lodash-4.17.21.tgz",
                    },
                }
            ),
        )
        result = parse_npm_lockfile(path)
        assert codes(result, result.dependencies[0]) == [MISSING_INTEGRITY]

    def test_credentials_in_resolved_url_are_redacted(self, write_json):
        path = write_json(
            "package-lock.json",
            self.lock(
                {
                    "": {},
                    "node_modules/x": {
                        "version": "1.0.0",
                        "resolved": "https://user:TOKEN123@npm.corp.example/x/-/x-1.0.0.tgz",
                        "integrity": "sha512-AAAA",
                    },
                }
            ),
        )
        dep = parse_npm_lockfile(path).dependencies[0]
        assert "TOKEN123" not in (dep.resolved_url or "")

    def test_v2_prefers_packages_over_legacy_tree(self, write_json):
        path = write_json(
            "package-lock.json",
            {
                "lockfileVersion": 2,
                "packages": {"": {}, "node_modules/a": entry("a", "2.0.0")},
                # Legacy section deliberately disagrees - it must be ignored.
                "dependencies": {"a": entry("a", "1.0.0")},
            },
        )
        assert list(by_name_version(parse_npm_lockfile(path))) == [("a", "2.0.0")]


class TestV1Tree:
    def test_nested_tree_with_package_json(self, write_json):
        path = write_json(
            "package-lock.json",
            {
                "lockfileVersion": 1,
                "dependencies": {
                    "express": {
                        **entry("express", "4.17.1"),
                        "dependencies": {"debug": entry("debug", "2.6.9")},
                    },
                    "minimist": entry("minimist", "1.2.5", dev=True),
                },
            },
        )
        result = parse_npm_lockfile(
            path,
            package_json={
                "dependencies": {"express": "^4"},
                "devDependencies": {"minimist": "^1"},
            },
        )
        deps = by_name_version(result)
        assert deps[("express", "4.17.1")].direct
        assert not deps[("debug", "2.6.9")].direct
        assert deps[("minimist", "1.2.5")].dev
        assert result.warnings == []

    def test_v1_without_package_json_warns(self, write_json):
        path = write_json(
            "package-lock.json",
            {"lockfileVersion": 1, "dependencies": {"a": entry("a", "1.0.0")}},
        )
        result = parse_npm_lockfile(path)
        assert not result.dependencies[0].direct
        assert "cannot tell direct" in result.warnings[0]

    def test_v1_alias_in_version_field(self, write_json):
        path = write_json(
            "package-lock.json",
            {
                "lockfileVersion": 1,
                "dependencies": {
                    "my-pad": {**entry("left-pad", "1.3.0"), "version": "npm:left-pad@1.3.0"}
                },
            },
        )
        result = parse_npm_lockfile(path, package_json={"dependencies": {"my-pad": "x"}})
        assert ("left-pad", "1.3.0") in by_name_version(result)

    def test_v1_git_version_is_non_registry(self, write_json):
        path = write_json(
            "package-lock.json",
            {
                "lockfileVersion": 1,
                "dependencies": {"lib": {"version": "github:org/lib#abc123"}},
            },
        )
        result = parse_npm_lockfile(path)
        dep = result.dependencies[0]
        assert dep.version is None
        assert codes(result, dep) == [NON_REGISTRY_SOURCE]

    def test_deep_tree_is_walked_completely(self, write):
        # The v1 tree is walked with an explicit stack, so depth is no problem.
        depth = 300
        opening = "".join(
            f'{{"pkg{i}": {{"version": "1.0.0", "dependencies": ' for i in range(depth)
        )
        text = '{"lockfileVersion": 1, "dependencies": ' + opening + "{}" + "}}" * depth + "}"
        assert len(parse_npm_lockfile(write("package-lock.json", text)).dependencies) == depth


def test_absurdly_nested_json_is_a_parse_error_not_a_crash(write):
    # SECURITY: 100,000 nested arrays make json.loads raise RecursionError;
    # a hostile repository must not be able to crash the scanner that way.
    path = write("package-lock.json", "[" * 100_000 + "]" * 100_000)
    with pytest.raises(ParseError, match="nested too deeply"):
        parse_npm_lockfile(path)


def test_empty_lockfile_has_no_dependencies(write_json):
    path = write_json("package-lock.json", {"name": "app", "lockfileVersion": 3})
    result = parse_npm_lockfile(path)
    assert result.dependencies == [] and result.warnings == []


def test_entry_without_version_is_skipped(write_json):
    path = write_json(
        "package-lock.json",
        {"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"resolved": "x"}}},
    )
    result = parse_npm_lockfile(path)
    assert result.dependencies == []
    assert "no version" in result.warnings[0]
