"""Tests for the CVSS v3.x calculator (checks/cvss.py).

Expected scores were cross-checked against NVD's published scores for the
named CVEs and the FIRST.org CVSS v3.1 calculator.
"""

from __future__ import annotations

import pytest

from chainsentry.checks.cvss import base_score, parse_vector, roundup, severity_from_score
from chainsentry.models import Severity


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        # Unauthenticated remote code execution, scope unchanged.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        # Same with scope changed - Log4Shell (CVE-2021-44228) scores this 10.0.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        # Reflected XSS: needs a click (UI:R) and changes scope (browser).
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        # Authenticated information disclosure.
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
        # Local privilege escalation.
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        # Hard-to-exploit, low impact.
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
        # Denial of service only (lodash ReDoS-style).
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
        # v3.0 vectors use the same formula.
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        # No impact at all -> 0.0
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_base_score(vector, score):
    assert base_score(vector) == score


def test_roundup_avoids_float_artifacts():
    # 4.000000000000001 must stay 4.0, not become 4.1 (CVSS v3.1 Appendix A).
    assert roundup(4.000000000000001) == 4.0
    assert roundup(4.02) == 4.1


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",  # v2 is a different system
        "CVSS:3.1/AV:N/AC:L",  # incomplete
        "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # unknown value
        "garbage",
    ],
)
def test_invalid_vectors_raise(vector):
    with pytest.raises(ValueError):
        base_score(vector)


def test_parse_vector():
    assert parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")["AV"] == "N"


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        (10.0, Severity.CRITICAL),
        (9.0, Severity.CRITICAL),
        (8.9, Severity.HIGH),
        (7.0, Severity.HIGH),
        (6.9, Severity.MEDIUM),
        (4.0, Severity.MEDIUM),
        (3.9, Severity.LOW),
        (0.0, Severity.LOW),
    ],
)
def test_severity_bands(score, severity):
    assert severity_from_score(score) is severity
