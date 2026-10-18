"""Tests for risk scoring (scoring/risk.py).

These tests pin down the documented formula (docs/SCORING.md): if a weight
changes, a test here should change with it - on purpose.
"""

from __future__ import annotations

import pytest

from chainsentry import config
from chainsentry.models import (
    Dependency,
    Ecosystem,
    Finding,
    PackageReport,
    ScanResult,
    Severity,
    Vulnerability,
)
from chainsentry.scoring import (
    apply_scores,
    band_for,
    policy_violations,
    score_package,
    score_project,
)


def pkg(name: str = "pkg", *, vulns=(), findings=()) -> PackageReport:
    report = PackageReport(Dependency(name, "1.0.0", None, Ecosystem.NPM, "x"))
    report.vulnerabilities = [
        Vulnerability(id=f"GHSA-{i}", summary="", severity=sev) for i, sev in enumerate(vulns)
    ]
    report.findings = [
        Finding(check="t", code=code, severity=sev, message=code) for code, sev in findings
    ]
    return report


@pytest.mark.parametrize(
    ("score", "band"),
    [(0, Severity.LOW), (19, Severity.LOW), (20, Severity.MEDIUM), (49, Severity.MEDIUM),
     (50, Severity.HIGH), (74, Severity.HIGH), (75, Severity.CRITICAL), (100, Severity.CRITICAL)],
)  # fmt: skip
def test_bands(score, band):
    assert band_for(score) is band


class TestPackageScore:
    def test_clean_package_scores_zero(self):
        assert score_package(pkg()) == (0, [])

    @pytest.mark.parametrize(
        ("severity", "band"),
        [
            (Severity.CRITICAL, Severity.CRITICAL),
            (Severity.HIGH, Severity.HIGH),
            (Severity.MEDIUM, Severity.MEDIUM),
        ],
    )
    def test_band_is_never_below_worst_vulnerability(self, severity, band):
        score, _ = score_package(pkg(vulns=[severity]))
        assert band_for(score) is band

    def test_worst_vulnerability_plus_capped_extras(self):
        # 1 critical (75) + 2 more vulns (2 x 2 = 4) = 79
        score, parts = score_package(pkg(vulns=[Severity.LOW, Severity.CRITICAL, Severity.LOW]))
        assert score == 79
        assert parts[0].points == 75 and "CRITICAL" in parts[0].reason

    def test_extra_vulnerability_points_are_capped(self):
        score, _ = score_package(pkg(vulns=[Severity.LOW] * 30))
        assert score == config.VULN_POINTS["LOW"] + config.EXTRA_VULN_CAP

    def test_signals_add_up(self):
        score, parts = score_package(
            pkg(findings=[("INSTALL_SCRIPT", Severity.MEDIUM), ("ABANDONED", Severity.LOW)])
        )
        assert score == 15 + 10
        assert [p.reason for p in parts] == ["INSTALL_SCRIPT", "ABANDONED"]

    def test_each_code_counts_once(self):
        score, _ = score_package(pkg(findings=[("NON_REGISTRY_SOURCE", Severity.MEDIUM)] * 3))
        assert score == config.SIGNAL_POINTS["NON_REGISTRY_SOURCE"]

    def test_typosquat_points_follow_confidence(self):
        high, _ = score_package(pkg(findings=[("TYPOSQUAT", Severity.HIGH)]))
        medium, _ = score_package(pkg(findings=[("TYPOSQUAT", Severity.MEDIUM)]))
        assert (high, medium) == (50, 30)

    def test_score_is_capped_at_100(self):
        score, _ = score_package(
            pkg(
                vulns=[Severity.CRITICAL],
                findings=[("TYPOSQUAT", Severity.HIGH), ("NOT_IN_REGISTRY", Severity.HIGH)],
            )
        )
        assert score == 100

    def test_malware_is_always_100(self):
        report = pkg()
        report.vulnerabilities = [Vulnerability(id="MAL-2024-1", summary="", severity=Severity.LOW)]
        score, parts = score_package(report)
        assert score == 100 and "malicious" in parts[0].reason

    def test_unknown_codes_score_nothing(self):
        assert score_package(pkg(findings=[("SOMETHING_NEW", Severity.HIGH)]))[0] == 0


class TestProjectScore:
    def scored(self, *scores: int) -> list[PackageReport]:
        reports = []
        for s in scores:
            r = pkg()
            r.score = s
            reports.append(r)
        return reports

    def test_empty_project(self):
        assert score_project([]) == 0

    def test_max_not_average(self):
        # 99 clean packages must not dilute one critical package.
        assert score_project(self.scored(80, *[0] * 99)) == 80

    def test_other_risky_packages_nudge_it_up(self):
        # worst 60 + 2 other HIGH/CRITICAL packages x 2 points
        assert score_project(self.scored(60, 55, 50, 30, 10)) == 64

    def test_capped(self):
        assert score_project(self.scored(*[100] * 10)) == 100


def test_apply_scores_fills_everything():
    result = ScanResult(target=".", packages=[pkg(vulns=[Severity.HIGH]), pkg("ok")])
    apply_scores(result)
    assert [p.score for p in result.packages] == [50, 0]
    assert result.packages[0].band is Severity.HIGH
    assert result.project_score == 50 and result.project_band is Severity.HIGH


class TestPolicy:
    def result(self, *severities: Severity) -> ScanResult:
        result = ScanResult(
            target=".", packages=[pkg(f"p{i}", vulns=[s]) for i, s in enumerate(severities)]
        )
        apply_scores(result)
        return result

    def test_passes_below_threshold(self):
        assert policy_violations(self.result(Severity.HIGH), fail_on=Severity.CRITICAL) == []

    def test_fails_at_threshold(self):
        reasons = policy_violations(self.result(Severity.CRITICAL), fail_on=Severity.CRITICAL)
        assert reasons and "CRITICAL or worse" in reasons[0]

    def test_fail_on_none_disables_band_rule(self):
        assert policy_violations(self.result(Severity.CRITICAL), fail_on=None) == []

    def test_min_score(self):
        reasons = policy_violations(self.result(Severity.MEDIUM), fail_on=None, min_score=20)
        assert reasons and "project risk score" in reasons[0]
