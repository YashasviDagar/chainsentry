"""Tests for the scan orchestrator (scanner.py)."""

from __future__ import annotations

import httpx
import respx

from chainsentry import config
from chainsentry.scanner import ScanOptions, scan

BATCH = f"{config.OSV_API_URL}/querybatch"
# Registry health lookups are tested in test_health.py; here we test orchestration.
NO_HEALTH = ScanOptions(skip=frozenset({"health"}))


def empty_osv(request: httpx.Request) -> httpx.Response:
    """OSV mock that answers 'no vulnerabilities' for however many queries it receives."""
    import json

    count = len(json.loads(request.content)["queries"])
    return httpx.Response(200, json={"results": [{} for _ in range(count)]})


@respx.mock
def test_dev_dependencies_excluded_by_default(demo_dir, client):
    respx.post(BATCH).mock(side_effect=empty_osv)
    names = {p.dependency.name for p in scan(demo_dir, NO_HEALTH, client=client).packages}
    assert "minimist" not in names and "pytest" not in names
    assert "lodash" in names


@respx.mock
def test_include_dev(demo_dir, client):
    respx.post(BATCH).mock(side_effect=empty_osv)
    result = scan(
        demo_dir, ScanOptions(include_dev=True, skip=frozenset({"health"})), client=client
    )
    assert "minimist" in {p.dependency.name for p in result.packages}


@respx.mock
def test_exclude_patterns_never_reach_the_api(demo_dir, client):
    route = respx.post(BATCH).mock(side_effect=empty_osv)
    scan(
        demo_dir, ScanOptions(exclude=("lodash", "dj*"), skip=frozenset({"health"})), client=client
    )
    body = route.calls[0].request.content
    assert b"lodash" not in body and b"django" not in body


def test_offline_skips_network_checks(demo_dir):
    result = scan(demo_dir, ScanOptions(offline=True, use_cache=False))
    assert "osv" not in result.checks
    assert any("offline" in e for e in result.errors)


def test_skip_option(demo_dir, client):
    result = scan(demo_dir, ScanOptions(skip=frozenset({"osv", "health"})), client=client)
    assert "osv" not in result.checks
    assert "typosquat" in result.checks  # offline check still runs


@respx.mock
def test_result_metadata(demo_dir, client):
    respx.post(BATCH).mock(side_effect=empty_osv)
    result = scan(demo_dir, NO_HEALTH, client=client)
    assert result.tool_version
    assert result.scanned_at.endswith("+00:00")
    assert "package-lock.json" in result.files
    assert any("dependency confusion" in w for w in result.warnings)
    # Parser findings travel into the package reports.
    left_pad = next(p for p in result.packages if p.dependency.name == "left-pad")
    assert [f.code for f in left_pad.findings] == ["NPM_ALIAS"]
