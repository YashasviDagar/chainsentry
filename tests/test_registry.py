"""Tests for registry metadata summaries (registry.py) and --resolve (resolver.py)."""

from __future__ import annotations

import httpx
import respx

from chainsentry import config
from chainsentry.models import Dependency, Ecosystem, PackageReport, Severity
from chainsentry.parsers.base import NON_REGISTRY_SOURCE, parser_finding
from chainsentry.registry import PackageInfo, RegistryClient, summarise_npm, summarise_pypi
from chainsentry.resolver import Resolver, pick_npm, pick_pypi

NPM_DOC = {
    "name": "demo",
    "dist-tags": {"latest": "1.2.0"},
    "maintainers": [{"name": "a"}, {"name": "b"}],
    "repository": {"type": "git", "url": "git+https://github.com/o/demo.git"},
    "time": {
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2024-01-01T00:00:00.000Z",
        "1.0.0": "2020-01-01T00:00:00.000Z",
        "1.2.0": "2023-06-01T00:00:00.000Z",
    },
    "versions": {
        "1.0.0": {"deprecated": "use 1.2"},
        "1.2.0": {"scripts": {"postinstall": "node x.js", "test": "jest"}, "gypfile": True},
    },
}

PYPI_DOC = {
    "info": {
        "version": "2.0.0",
        "classifiers": ["Development Status :: 7 - Inactive"],
        "project_urls": {"Source": "https://github.com/o/demo"},
    },
    "releases": {
        "1.0.0": [{"upload_time_iso_8601": "2019-01-01T00:00:00Z", "yanked": False}],
        "1.5.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z", "yanked": True}],
        "2.0.0": [{"upload_time_iso_8601": "2021-01-01T00:00:00Z", "yanked": False}],
        "3.0.0rc1": [{"upload_time_iso_8601": "2021-06-01T00:00:00Z", "yanked": False}],
        "0.0.1": [],  # no files uploaded -> not installable
    },
}


def test_summarise_npm():
    info = summarise_npm("demo", NPM_DOC)
    assert info.versions == ["1.0.0", "1.2.0"]
    assert info.latest == "1.2.0"
    assert info.maintainers == 2
    assert info.created == "2020-01-01T00:00:00.000Z"
    assert info.last_release == "2023-06-01T00:00:00.000Z"
    assert info.install_scripts == {"1.2.0": ["postinstall", "install (node-gyp)"]}
    assert info.deprecation_for("1.0.0") == "use 1.2"
    assert info.repository and "github.com" in info.repository


def test_summarise_pypi():
    info = summarise_pypi("demo", PYPI_DOC)
    assert info.versions == ["1.0.0", "2.0.0", "3.0.0rc1"]
    assert info.yanked == ["1.5.0"]
    assert info.created == "2019-01-01T00:00:00Z"
    assert info.maintainers is None  # PyPI does not expose it
    assert info.deprecation_for("2.0.0")  # whole project marked Inactive
    assert info.repository == "https://github.com/o/demo"


@respx.mock
def test_registry_client_encodes_scoped_names(client):
    route = respx.get(f"{config.NPM_REGISTRY_URL}/@types%2Fnode").mock(
        return_value=httpx.Response(200, json=NPM_DOC)
    )
    assert RegistryClient(client).info(Ecosystem.NPM, "@types/node") is not None
    assert route.called


@respx.mock
def test_registry_client_not_found(client):
    respx.get(f"{config.PYPI_JSON_URL}/nope/json").mock(return_value=httpx.Response(404))
    assert RegistryClient(client).info(Ecosystem.PYPI, "nope") is None


def test_pick_npm():
    info = PackageInfo("npm", "x", versions=["1.0.0", "1.4.0", "2.0.0"], latest="2.0.0")
    assert pick_npm(info, "^1.0.0") == "1.4.0"
    assert pick_npm(info, "*") == "2.0.0"


def test_pick_pypi_excludes_prereleases():
    info = summarise_pypi("demo", PYPI_DOC)
    assert pick_pypi(info, ">=1.0") == "2.0.0"
    assert pick_pypi(info, "<2") == "1.0.0"  # yanked 1.5.0 is never chosen
    assert pick_pypi(info, None) == "2.0.0"


@respx.mock
def test_resolver_sets_version_and_flag(client):
    respx.get(f"{config.NPM_REGISTRY_URL}/demo").mock(
        return_value=httpx.Response(200, json=NPM_DOC)
    )
    report = PackageReport(Dependency("demo", None, "^1.0.0", Ecosystem.NPM, "package.json"))
    assert Resolver(RegistryClient(client)).resolve([report]) == []
    assert report.dependency.version == "1.2.0"
    assert report.resolved


def test_resolver_skips_non_registry_sources(client):
    report = PackageReport(Dependency("lib", None, "github:o/lib", Ecosystem.NPM, "package.json"))
    report.add_finding(parser_finding(NON_REGISTRY_SOURCE, Severity.MEDIUM, "git"))
    # No HTTP mock: a request would raise, so success proves none was made.
    assert Resolver(RegistryClient(client)).resolve([report]) == []
    assert report.dependency.version is None
