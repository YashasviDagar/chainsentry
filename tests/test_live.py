"""Opt-in end-to-end test against the real OSV, npm and PyPI APIs.

Skipped by default (see addopts in pyproject.toml). Run it with::

    pytest -m network

It guards against API changes the mocked unit tests cannot notice, such as a
renamed field in OSV records or a changed registry endpoint.
"""

from __future__ import annotations

import pytest

from chainsentry.models import Severity
from chainsentry.scanner import ScanOptions, scan


@pytest.mark.network
def test_demo_project_against_real_apis(demo_dir):
    result = scan(demo_dir, ScanOptions(include_dev=True, use_cache=False))
    assert result.errors == []
    assert result.checks == ["osv", "typosquat", "health"]
    packages = {p.dependency.name: p for p in result.packages}
    # lodash 4.17.15 has long-published advisories (e.g. CVE-2021-23337).
    assert any("CVE-2021-23337" in v.cve_ids for v in packages["lodash"].vulnerabilities)
    # Django 3.2.0 has critical SQL-injection advisories -> CRITICAL band.
    assert packages["django"].band is Severity.CRITICAL
    # colourama was removed from PyPI after the 2018 attack.
    assert {"TYPOSQUAT", "NOT_IN_REGISTRY"} <= {f.code for f in packages["colourama"].findings}
