"""Aggregate numbers about a scan, shared by every reporter.

Computing the summary once (instead of in each reporter) guarantees the
terminal, JSON, Markdown and dashboard all show the *same* totals.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from chainsentry.models import ScanResult, Severity


@dataclass
class Summary:
    packages: int = 0
    direct: int = 0
    unchecked: int = 0  # no exact version -> not checked against OSV
    vulnerable_packages: int = 0
    vulnerabilities: int = 0
    vulnerabilities_by_severity: dict[str, int] = field(default_factory=dict)
    packages_by_band: dict[str, int] = field(default_factory=dict)
    findings_by_code: dict[str, int] = field(default_factory=dict)
    fixable_vulnerabilities: int = 0  # a fixed version exists


def summarise(result: ScanResult) -> Summary:
    """Compute totals for ``result``."""
    severities: Counter[str] = Counter()
    bands: Counter[str] = Counter()
    codes: Counter[str] = Counter()
    summary = Summary(packages=len(result.packages))
    for report in result.packages:
        summary.direct += report.dependency.direct
        summary.unchecked += report.dependency.version is None
        bands[report.band.value] += 1
        if report.vulnerabilities:
            summary.vulnerable_packages += 1
        for vuln in report.vulnerabilities:
            severities[vuln.severity.value] += 1
            summary.fixable_vulnerabilities += bool(vuln.fixed_versions)
        for finding in report.findings:
            codes[finding.code] += 1
    summary.vulnerabilities = sum(severities.values())
    # Fixed key order (most severe first) keeps JSON diffs and tables stable.
    order = [s.value for s in sorted(Severity, key=lambda s: -s.rank)]
    summary.vulnerabilities_by_severity = {k: severities[k] for k in order if severities[k]}
    summary.packages_by_band = {k: bands[k] for k in order if bands[k]}
    summary.findings_by_code = dict(codes.most_common())
    return summary
