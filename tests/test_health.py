"""Tests for package health rules (checks/health.py)."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import respx

from chainsentry import config
from chainsentry.checks.health import (
    ABANDONED,
    DEPRECATED,
    INSTALL_SCRIPT,
    NEW_PACKAGE,
    NEW_VERSION,
    NO_REPOSITORY,
    NOT_IN_REGISTRY,
    SINGLE_MAINTAINER,
    VERSION_NOT_IN_REGISTRY,
    YANKED,
    HealthCheck,
    evaluate,
)
from chainsentry.models import Dependency, Ecosystem, PackageReport, Severity
from chainsentry.parsers.base import NON_REGISTRY_SOURCE, parser_finding
from chainsentry.registry import PackageInfo, RegistryClient

NOW = datetime(2026, 10, 19, tzinfo=UTC)


def npm_dep(version: str | None = "1.0.0", name: str = "pkg") -> Dependency:
    return Dependency(name, version, None, Ecosystem.NPM, "package-lock.json")


def healthy(**overrides) -> PackageInfo:
    """Metadata for a boring, healthy package; tests override one field at a time."""
    info = PackageInfo(
        ecosystem="npm",
        name="pkg",
        versions=["1.0.0", "1.1.0"],
        latest="1.1.0",
        release_times={"1.0.0": "2024-01-01T00:00:00.000Z", "1.1.0": "2026-01-01T00:00:00.000Z"},
        created="2024-01-01T00:00:00.000Z",
        maintainers=3,
        repository="git+https://github.com/o/pkg.git",
    )
    for key, value in overrides.items():
        setattr(info, key, value)
    return info


def codes(findings) -> list[str]:
    return [f.code for f in findings]


def test_healthy_package_has_no_findings():
    assert evaluate(npm_dep(), healthy(), NOW) == []


def test_missing_package_is_dependency_confusion_risk():
    findings = evaluate(npm_dep(), None, NOW)
    assert codes(findings) == [NOT_IN_REGISTRY]
    assert findings[0].severity is Severity.HIGH
    assert "dependency confusion" in findings[0].message


def test_unpublished_package():
    assert codes(evaluate(npm_dep(), healthy(unpublished=True), NOW)) == [NOT_IN_REGISTRY]


def test_install_scripts():
    info = healthy(install_scripts={"1.0.0": ["postinstall"]})
    findings = evaluate(npm_dep(), info, NOW)
    assert codes(findings) == [INSTALL_SCRIPT]
    assert findings[0].details["scripts"] == ["postinstall"]


def test_install_scripts_of_other_versions_do_not_count():
    info = healthy(install_scripts={"1.1.0": ["preinstall"]})
    assert evaluate(npm_dep("1.0.0"), info, NOW) == []


def test_new_package():
    info = healthy(created="2026-10-10T00:00:00Z")
    assert NEW_PACKAGE in codes(evaluate(npm_dep(), info, NOW))


def test_new_version():
    info = healthy(release_times={"1.0.0": "2026-10-17T00:00:00Z"})
    assert NEW_VERSION in codes(evaluate(npm_dep(), info, NOW))


def test_abandoned():
    info = healthy(release_times={"1.0.0": "2019-01-01T00:00:00Z"})
    findings = evaluate(npm_dep(), info, NOW)
    assert codes(findings) == [ABANDONED]
    assert "7 year(s)" in findings[0].message


def test_abandoned_threshold_is_configurable(monkeypatch):
    monkeypatch.setattr(config, "ABANDONED_DAYS", 100)
    assert ABANDONED in codes(evaluate(npm_dep(), healthy(), NOW))


def test_single_maintainer():
    assert codes(evaluate(npm_dep(), healthy(maintainers=1), NOW)) == [SINGLE_MAINTAINER]


def test_unknown_maintainers_are_not_flagged():
    # PyPI does not publish maintainers; "unknown" must not look like "one".
    assert evaluate(npm_dep(), healthy(maintainers=None), NOW) == []


def test_deprecated_version():
    info = healthy(deprecated={"1.0.0": "use something else"})
    assert codes(evaluate(npm_dep(), info, NOW)) == [DEPRECATED]


def test_no_repository():
    assert codes(evaluate(npm_dep(), healthy(repository=None), NOW)) == [NO_REPOSITORY]


def test_version_missing_from_registry():
    assert codes(evaluate(npm_dep("0.9.9"), healthy(), NOW)) == [VERSION_NOT_IN_REGISTRY]


def test_pypi_yanked_and_version_normalisation():
    info = healthy(ecosystem="PyPI", versions=["3.2"], yanked=["3.1"], maintainers=None)
    dep = Dependency("django", "3.2.0", None, Ecosystem.PYPI, "requirements.txt")
    assert evaluate(dep, info, NOW) == []  # 3.2.0 == 3.2 under PEP 440
    yanked = Dependency("django", "3.1", None, Ecosystem.PYPI, "requirements.txt")
    assert codes(evaluate(yanked, info, NOW)) == [YANKED]


def test_unpinned_dependency_gets_package_level_checks_only():
    info = healthy(maintainers=1, install_scripts={"1.1.0": ["postinstall"]})
    assert codes(evaluate(npm_dep(None), info, NOW)) == [SINGLE_MAINTAINER]


@respx.mock
def test_check_fetches_each_package_once(client):
    route = respx.get(f"{config.NPM_REGISTRY_URL}/pkg").mock(
        return_value=httpx.Response(
            200,
            json={
                "dist-tags": {"latest": "1.0.0"},
                "maintainers": [{"name": "solo"}],
                "repository": "github:o/pkg",
                "time": {"created": "2024-01-01T00:00:00Z", "1.0.0": "2026-01-01T00:00:00Z"},
                "versions": {"1.0.0": {"scripts": {"postinstall": "node evil.js"}}},
            },
        )
    )
    a = PackageReport(npm_dep())
    b = PackageReport(Dependency("pkg", "1.0.0", None, Ecosystem.NPM, "other/package-lock.json"))
    check = HealthCheck(RegistryClient(client), now=lambda: NOW)
    assert check.run([a, b]) == []
    assert route.call_count == 1
    assert set(codes(a.findings)) == {INSTALL_SCRIPT, SINGLE_MAINTAINER}


@respx.mock
def test_registry_failure_is_reported(client):
    respx.get(f"{config.NPM_REGISTRY_URL}/pkg").mock(return_value=httpx.Response(500))
    errors = HealthCheck(RegistryClient(client), now=lambda: NOW).run([PackageReport(npm_dep())])
    assert errors and "health" in errors[0]


def test_non_registry_and_transitive_filters(client):
    git_dep = PackageReport(npm_dep(name="lib"))
    git_dep.add_finding(parser_finding(NON_REGISTRY_SOURCE, Severity.MEDIUM, "git"))
    transitive = PackageReport(
        Dependency("deep", "1.0.0", None, Ecosystem.NPM, "package-lock.json", direct=False)
    )
    # No HTTP mocks: any lookup would fail, so an empty result proves none happened.
    check = HealthCheck(RegistryClient(client), direct_only=True, now=lambda: NOW)
    assert check.run([git_dep, transitive]) == []
