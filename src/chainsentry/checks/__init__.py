"""Checks: ``PackageReport`` objects in, findings and vulnerabilities added.

Modules:
    base       the ``Check`` protocol and small concurrency helpers
    cvss       CVSS v3.x base-score calculator
    health     registry metadata signals (install scripts, age, maintainers...)
    osv        known vulnerabilities from OSV.dev
    typosquat  look-alikes of popular package names (offline)
"""

from chainsentry.checks.base import Check
from chainsentry.checks.health import HealthCheck
from chainsentry.checks.osv import OsvCheck
from chainsentry.checks.typosquat import TyposquatCheck

__all__ = ["Check", "HealthCheck", "OsvCheck", "TyposquatCheck"]
