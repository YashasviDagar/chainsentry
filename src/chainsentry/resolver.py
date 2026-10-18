"""``--resolve``: turn unpinned version ranges into concrete versions.

Without a lockfile, ``requests>=2.20`` or ``"express": "^4.17.1"`` does not
say which version is installed, so OSV cannot be queried. With
``--resolve`` we ask the registry which versions exist and pick the one the
package manager *would* install today: the highest version satisfying the
range (PEP 440 rules for PyPI via ``packaging``, npm rules via
:mod:`chainsentry.parsers.npm_semver`).

LIMITATION: the result is "what would be installed now", not what is
actually deployed. Reports mark such packages as *resolved* so nobody
mistakes them for locked versions. The real fix is to commit a lockfile.
"""

from __future__ import annotations

from dataclasses import replace

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from chainsentry.checks.base import parallel_map
from chainsentry.models import Ecosystem, PackageReport
from chainsentry.net.client import HttpError
from chainsentry.parsers.base import NON_REGISTRY_SOURCE
from chainsentry.parsers.npm_semver import UnsupportedRange, max_satisfying
from chainsentry.registry import PackageInfo, RegistryClient


class Resolver:
    """Resolve unpinned dependencies in place."""

    def __init__(self, registry: RegistryClient) -> None:
        self.registry = registry

    def resolve(self, packages: list[PackageReport]) -> list[str]:
        """Set ``dependency.version`` for unpinned packages. Returns error messages."""
        todo = [
            r
            for r in packages
            if r.dependency.version is None
            # A git/URL dependency is not on the registry: nothing to resolve.
            and not any(f.code == NON_REGISTRY_SOURCE for f in r.findings)
        ]
        errors: list[str] = []
        for report, (version, error) in zip(
            todo, parallel_map(self._resolve_one, todo), strict=True
        ):
            if error:
                errors.append(error)
            elif version:
                report.dependency = replace(report.dependency, version=version)
                report.resolved = True
        return errors

    def _resolve_one(self, report: PackageReport) -> tuple[str | None, str | None]:
        """Return ``(chosen version or None, error message or None)``."""
        dep = report.dependency
        try:
            info = self.registry.info(dep.ecosystem, dep.name)
        except HttpError as exc:
            return None, f"resolve: {dep.name}: {exc}"
        if info is None:
            return None, None  # not on the registry; the health check reports that
        try:
            if dep.ecosystem is Ecosystem.NPM:
                return pick_npm(info, dep.spec), None
            return pick_pypi(info, dep.spec), None
        except (UnsupportedRange, InvalidSpecifier) as exc:
            return None, f"resolve: {dep.name}: cannot interpret range {dep.spec!r} ({exc})"


def pick_npm(info: PackageInfo, spec: str | None) -> str | None:
    """Highest npm version satisfying ``spec``; dist-tags other than "latest" are not supported."""
    if spec in (None, "", "*", "latest", "x", "X"):
        return info.latest
    return max_satisfying(info.versions, spec)


def pick_pypi(info: PackageInfo, spec: str | None) -> str | None:
    """Highest PyPI version satisfying ``spec`` (prereleases excluded, like pip)."""
    if not spec:
        return info.latest
    candidates = []
    for text in SpecifierSet(spec).filter(info.versions):
        try:
            candidates.append((Version(text), text))
        except InvalidVersion:
            continue
    return max(candidates)[1] if candidates else None
