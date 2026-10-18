"""Package health: signals from registry metadata that a package is risky.

A package can have zero known CVEs and still be dangerous. This check uses
the npm registry / PyPI metadata (see :mod:`chainsentry.registry`) to flag:

=========================  ===================================================
code                       why it matters
=========================  ===================================================
NOT_IN_REGISTRY            The name does not exist publicly. If it is an
                           internal package, anyone can register it on the
                           public registry -> **dependency confusion**.
VERSION_NOT_IN_REGISTRY    The locked version is gone. Registries delete
                           malicious versions, so this deserves a look.
INSTALL_SCRIPT             npm ``preinstall``/``install``/``postinstall`` run
                           arbitrary code on ``npm install`` - the most common
                           malware delivery mechanism.
NEW_PACKAGE                First published < 30 days ago: no track record.
NEW_VERSION                This exact version is < 7 days old: account
                           takeovers ship fresh versions (ua-parser-js 2021).
ABANDONED                  No release in 2+ years: no security fixes coming.
SINGLE_MAINTAINER          npm: one account controls the package.
DEPRECATED / YANKED        The author says "do not use this".
NO_REPOSITORY              No source link: the code cannot be audited.
=========================  ===================================================

All thresholds live in :mod:`chainsentry.config`.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from packaging.version import InvalidVersion, Version

from chainsentry import config
from chainsentry.checks.base import parallel_map
from chainsentry.models import Dependency, Ecosystem, Finding, PackageReport, Severity
from chainsentry.net.client import HttpError
from chainsentry.parsers.base import NON_REGISTRY_SOURCE
from chainsentry.registry import PackageInfo, RegistryClient

NOT_IN_REGISTRY = "NOT_IN_REGISTRY"
VERSION_NOT_IN_REGISTRY = "VERSION_NOT_IN_REGISTRY"
INSTALL_SCRIPT = "INSTALL_SCRIPT"
NEW_PACKAGE = "NEW_PACKAGE"
NEW_VERSION = "NEW_VERSION"
ABANDONED = "ABANDONED"
SINGLE_MAINTAINER = "SINGLE_MAINTAINER"
DEPRECATED = "DEPRECATED"
YANKED = "YANKED"
NO_REPOSITORY = "NO_REPOSITORY"


class HealthCheck:
    """Evaluate registry metadata for every package."""

    name = "health"
    needs_network = True

    def __init__(
        self,
        registry: RegistryClient,
        *,
        direct_only: bool = False,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.registry = registry
        self.direct_only = direct_only
        self._now = now

    def run(self, packages: list[PackageReport]) -> list[str]:
        targets = [
            r
            for r in packages
            # git/URL dependencies are not installed from the registry, so its
            # metadata says nothing about them.
            if not any(f.code == NON_REGISTRY_SOURCE for f in r.findings)
            and (r.dependency.direct or not self.direct_only)
        ]
        names = sorted({(r.dependency.ecosystem, r.dependency.name) for r in targets})
        results = dict(zip(names, parallel_map(self._fetch, names), strict=True))

        failed = [n for n, (_, error) in results.items() if error]
        now = self._now()
        for report in targets:
            info, error = results[(report.dependency.ecosystem, report.dependency.name)]
            if error is None:
                for finding in evaluate(report.dependency, info, now):
                    report.add_finding(finding)

        if failed:
            return [
                f"health: registry lookup failed for {len(failed)} package(s), e.g. {failed[0][1]}"
            ]
        return []

    def _fetch(self, key: tuple[Ecosystem, str]) -> tuple[PackageInfo | None, str | None]:
        ecosystem, name = key
        try:
            return self.registry.info(ecosystem, name), None
        except HttpError as exc:
            return None, str(exc)


def evaluate(dep: Dependency, info: PackageInfo | None, now: datetime) -> list[Finding]:
    """Apply every health rule to one dependency. Pure function -> easy to test."""
    registry = "npm registry" if dep.ecosystem is Ecosystem.NPM else "PyPI"

    if info is None or info.unpublished:
        state = "was unpublished from" if info else "does not exist on"
        return [
            _finding(
                NOT_IN_REGISTRY,
                Severity.HIGH,
                f"'{dep.name}' {state} the public {registry}. If it is an internal package, an "
                "attacker can publish a public package with this name (dependency confusion).",
            )
        ]

    findings: list[Finding] = []
    version = dep.version

    if version and dep.ecosystem is Ecosystem.PYPI:
        if _pypi_in(version, info.yanked):
            findings.append(
                _finding(
                    YANKED, Severity.MEDIUM, f"version {version} was yanked by its author on PyPI"
                )
            )
        elif not _pypi_in(version, info.versions):
            findings.append(_missing_version(version, registry))
    elif version and version not in info.versions:
        findings.append(_missing_version(version, registry))

    if version and (scripts := info.install_scripts.get(version)):
        findings.append(
            _finding(
                INSTALL_SCRIPT,
                Severity.MEDIUM,
                f"runs code during install ({', '.join(scripts)}); review it or install with "
                "--ignore-scripts",
                scripts=scripts,
            )
        )

    created = _parse_time(info.created)
    if created and (age := (now - created).days) < config.NEW_PACKAGE_DAYS:
        findings.append(
            _finding(
                NEW_PACKAGE,
                Severity.MEDIUM,
                f"package was first published only {age} day(s) ago",
                created=info.created,
            )
        )

    released = _parse_time(info.release_times.get(version or ""))
    if released and (age := (now - released).days) < config.NEW_VERSION_DAYS:
        findings.append(
            _finding(
                NEW_VERSION,
                Severity.LOW,
                f"version {version} was published {age} day(s) ago",
                published=info.release_times.get(version or ""),
            )
        )

    last = _parse_time(info.last_release)
    if last and (idle := (now - last).days) > config.ABANDONED_DAYS:
        findings.append(
            _finding(
                ABANDONED,
                Severity.LOW,
                f"no release for {idle // 365} year(s) (last: {last.date().isoformat()}); "
                "security fixes are unlikely",
                last_release=info.last_release,
            )
        )

    if info.maintainers is not None and info.maintainers <= config.SINGLE_MAINTAINER_MAX:
        findings.append(
            _finding(
                SINGLE_MAINTAINER,
                Severity.LOW,
                f"only {info.maintainers} maintainer(s): a single compromised account controls it",
                maintainers=info.maintainers,
            )
        )

    if message := info.deprecation_for(version):
        findings.append(_finding(DEPRECATED, Severity.MEDIUM, f"deprecated: {message[:200]}"))

    if not info.repository:
        findings.append(
            _finding(
                NO_REPOSITORY,
                Severity.LOW,
                "no source repository linked; the code is hard to audit",
            )
        )
    return findings


def _finding(code: str, severity: Severity, message: str, **details: object) -> Finding:
    return Finding(check="health", code=code, severity=severity, message=message, details=details)


def _missing_version(version: str, registry: str) -> Finding:
    return _finding(
        VERSION_NOT_IN_REGISTRY,
        Severity.MEDIUM,
        f"version {version} is not (or no longer) available on the {registry}; registries remove "
        "malicious versions, so check why",
    )


def _pypi_in(version: str, candidates: list[str]) -> bool:
    """PEP 440-aware membership: "3.2" and "3.2.0" are the same version."""
    try:
        wanted = Version(version)
    except InvalidVersion:
        return version in candidates
    for candidate in candidates:
        try:
            if Version(candidate) == wanted:
                return True
        except InvalidVersion:
            continue
    return False


def _parse_time(value: str | None) -> datetime | None:
    """Parse registry ISO-8601 timestamps such as ``2020-01-01T00:00:00.000Z``."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
