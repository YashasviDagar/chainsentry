"""The orchestrator: the only module that wires parsers, checks and scoring together.

Pipeline::

    parse_project()          manifests  -> Dependencies (+ parser findings)
      filter                 drop dev deps / --exclude patterns
      Resolver (optional)    ranges     -> concrete versions (--resolve)
      checks                 osv, typosquat, health -> findings / vulns
      scoring                findings   -> 0-100 scores          (Phase 5)
    ScanResult               -> reporters (table / JSON / SBOM / Markdown)

Design decisions
----------------
* **Checks are independent and failure-tolerant.** If one check's API is
  down, the others still run; the problem is recorded in
  ``ScanResult.errors`` and shown to the user ("results incomplete").
* **The HTTP client is injectable.** Tests pass a client whose responses are
  mocked; the CLI lets ``scan()`` build the real one.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from pathlib import Path

from chainsentry import __version__, config
from chainsentry.checks.base import Check
from chainsentry.checks.osv import OsvCheck
from chainsentry.checks.typosquat import TyposquatCheck
from chainsentry.models import Dependency, PackageReport, ScanResult
from chainsentry.net.cache import Cache
from chainsentry.net.client import HttpClient
from chainsentry.parsers import ParseResult, parse_project
from chainsentry.registry import RegistryClient
from chainsentry.resolver import Resolver

CACHE_FILE = "cache.sqlite3"


@dataclass(frozen=True)
class ScanOptions:
    """User-selectable behaviour of a scan (mirrors the CLI flags)."""

    recursive: bool = False
    #: Also scan development-only dependencies.
    include_dev: bool = False
    #: Resolve version ranges to the newest matching release (see resolver.py).
    resolve: bool = False
    #: No network at all: only offline checks run.
    offline: bool = False
    use_cache: bool = True
    #: Check names to skip, e.g. {"health"}.
    skip: frozenset[str] = field(default_factory=frozenset)
    #: Glob patterns of package names to leave out entirely, e.g. "@mycorp/*".
    #: SECURITY/PRIVACY: excluded names are never sent to any public API,
    #: which matters for internal package names.
    exclude: tuple[str, ...] = ()


def open_cache(use_cache: bool) -> Cache:
    """Open the on-disk cache, falling back to no cache if it cannot be created."""
    if not use_cache:
        return Cache(None)
    try:
        return Cache(config.cache_dir() / CACHE_FILE)
    except (OSError, sqlite3.Error):
        # e.g. a read-only home directory in some CI containers
        return Cache(None)


def build_checks(client: HttpClient) -> list[Check]:
    """All checks, in the order they run."""
    return [OsvCheck(client), TyposquatCheck()]


def scan(
    target: Path | str,
    options: ScanOptions | None = None,
    *,
    client: HttpClient | None = None,
) -> ScanResult:
    """Scan a project directory or manifest file.

    Args:
        target: Directory or manifest file.
        options: Scan behaviour; defaults to ``ScanOptions()``.
        client: HTTP client to use. If ``None`` one is created (and closed).

    Raises:
        ParseError: if the target cannot be parsed at all.
    """
    options = options or ScanOptions()
    started = time.monotonic()
    scanned_at = datetime.now(UTC).isoformat(timespec="seconds")

    parsed = parse_project(target, recursive=options.recursive)
    reports = _select(parsed.dependencies, options, parsed)

    own_client = client is None
    if client is None:
        client = HttpClient(open_cache(options.use_cache), offline=options.offline)

    errors: list[str] = []
    ran: list[str] = []
    try:
        if options.resolve and not options.offline:
            errors += Resolver(RegistryClient(client)).resolve(reports)
            reports = _merge_duplicates(reports)

        for check in build_checks(client):
            if check.name in options.skip:
                continue
            if check.needs_network and options.offline:
                errors.append(f"{check.name}: skipped (offline mode)")
                continue
            errors += check.run(reports)
            ran.append(check.name)
    finally:
        if own_client:
            client.close()

    return ScanResult(
        target=str(target),
        packages=reports,
        files=parsed.files,
        warnings=parsed.warnings,
        errors=errors,
        checks=ran,
        tool_version=__version__,
        scanned_at=scanned_at,
        duration_seconds=round(time.monotonic() - started, 2),
    )


def _select(
    deps: Iterable[Dependency], options: ScanOptions, parsed: ParseResult
) -> list[PackageReport]:
    """Apply --include-dev / --exclude and wrap each dependency in a report."""
    reports: list[PackageReport] = []
    for dep in deps:
        if dep.dev and not options.include_dev:
            continue
        # fnmatchcase: npm names are case-sensitive; plain fnmatch is not on Windows.
        if any(fnmatchcase(dep.name, pattern) for pattern in options.exclude):
            continue
        report = PackageReport(dependency=dep)
        for finding in parsed.findings_for(dep):
            report.add_finding(finding)
        reports.append(report)
    return reports


def _merge_duplicates(reports: list[PackageReport]) -> list[PackageReport]:
    """After resolving, ``requests>=2`` may now equal a pinned ``requests==2.32.3``; merge them."""
    merged: dict[tuple, PackageReport] = {}
    for report in reports:
        existing = merged.get(report.dependency.key)
        if existing is None:
            merged[report.dependency.key] = report
            continue
        for finding in report.findings:
            existing.add_finding(finding)
        existing.resolved = existing.resolved and report.resolved
    return list(merged.values())
