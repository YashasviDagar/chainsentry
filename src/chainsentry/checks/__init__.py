"""Checks: ``PackageReport`` objects in, findings and vulnerabilities added.

Modules:
    base   the ``Check`` protocol and small concurrency helpers
    cvss   CVSS v3.x base-score calculator
    osv    known vulnerabilities from OSV.dev
"""

from chainsentry.checks.base import Check
from chainsentry.checks.osv import OsvCheck

__all__ = ["Check", "OsvCheck"]
