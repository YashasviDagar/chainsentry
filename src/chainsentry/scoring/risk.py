"""Turn findings and vulnerabilities into 0-100 risk scores.

The formula is deliberately simple, additive and explainable in one breath
(full write-up with worked examples: ``docs/SCORING.md``)::

    package_score = min(100, vuln_points + sum(signal_points))

    vuln_points   = points(worst vulnerability severity)
                  + min(10, 2 * (number_of_vulnerabilities - 1))
                    CRITICAL 75 . HIGH 50 . MEDIUM 25 . LOW 5 . UNKNOWN 25

    signal_points = one entry per finding code, e.g.
                    TYPOSQUAT 50/30 . NOT_IN_REGISTRY 40 . NEW_PACKAGE 20
                    INSTALL_SCRIPT 15 . ABANDONED 10 . UNPINNED 5 ...

    bands: 0-19 LOW . 20-49 MEDIUM . 50-74 HIGH . 75-100 CRITICAL

    project_score = min(100, max(package_scores)
                             + 2 * (number of OTHER packages rated HIGH/CRITICAL))

Why these choices?
------------------
* **A package is never rated below its worst vulnerability.** The
  vulnerability points equal each band's lower bound, so one CRITICAL CVE
  alone makes the package CRITICAL - "fail on critical" means what it says.
* **Worst vulnerability, not the sum.** One critical RCE is what matters;
  adding up twelve low-severity bugs would rank a well-maintained
  framework (many small reported issues) above a tiny package with one RCE.
* **Each finding code counts once.** A package can't reach 100 just by
  having two different "abandoned"-style messages.
* **Project = max, not average.** Supply-chain security is a weakest-link
  problem: 499 clean packages do not dilute one compromised package.
* **Known malware (OSV ``MAL-`` IDs) is always 100.** No arithmetic needed.
* **Weights live in config.py**, so they can be tuned and the tests pin
  the behaviour down.

LIMITATION: these weights are expert judgement, not a statistical model.
They rank packages for human review; they are not a probability of
compromise.
"""

from __future__ import annotations

from chainsentry import config
from chainsentry.models import PackageReport, ScanResult, ScoreComponent, Severity

MAX_SCORE = 100


def band_for(score: int) -> Severity:
    """Map a 0-100 score to LOW / MEDIUM / HIGH / CRITICAL."""
    for threshold, label in config.BANDS:
        if score >= threshold:
            return Severity(label)
    return Severity.LOW


def score_package(report: PackageReport) -> tuple[int, list[ScoreComponent]]:
    """Compute one package's score and the list of reasons that add up to it."""
    parts: list[ScoreComponent] = []

    if any(v.is_malicious for v in report.vulnerabilities):
        return MAX_SCORE, [ScoreComponent("known malicious package (OSV MAL- advisory)", MAX_SCORE)]

    if report.vulnerabilities:
        worst = max(report.vulnerabilities, key=lambda v: (v.severity.rank, v.cvss_score or 0))
        parts.append(
            ScoreComponent(
                f"worst vulnerability {worst.id} is {worst.severity.value}",
                config.VULN_POINTS[worst.severity.value],
            )
        )
        extra = len(report.vulnerabilities) - 1
        if extra:
            parts.append(
                ScoreComponent(
                    f"{extra} more known vulnerabilit{'y' if extra == 1 else 'ies'}",
                    min(config.EXTRA_VULN_CAP, config.EXTRA_VULN_POINTS * extra),
                )
            )

    seen: set[str] = set()
    for finding in report.findings:
        if finding.code in seen:
            continue
        seen.add(finding.code)
        if finding.code == "TYPOSQUAT":
            points = config.TYPOSQUAT_POINTS.get(finding.severity.value, 0)
        else:
            points = config.SIGNAL_POINTS.get(finding.code, 0)
        if points:
            parts.append(ScoreComponent(finding.code, points))

    return min(MAX_SCORE, sum(p.points for p in parts)), parts


def score_project(packages: list[PackageReport]) -> int:
    """Overall score: the worst package, nudged up by other risky packages."""
    if not packages:
        return 0
    ranked = sorted((p.score for p in packages), reverse=True)
    risky_others = sum(1 for s in ranked[1:] if band_for(s).rank >= Severity.HIGH.rank)
    return min(MAX_SCORE, ranked[0] + config.PROJECT_POINTS_PER_RISKY_PACKAGE * risky_others)


def apply_scores(result: ScanResult) -> None:
    """Fill in every package's score/band/breakdown and the project score, in place."""
    for report in result.packages:
        report.score, report.score_breakdown = score_package(report)
        report.band = band_for(report.score)
    result.project_score = score_project(result.packages)
    result.project_band = band_for(result.project_score)


def policy_violations(
    result: ScanResult, *, fail_on: Severity | None, min_score: int | None = None
) -> list[str]:
    """Reasons the scan should fail CI (empty list = pass).

    Args:
        fail_on: Fail if any package's band is at or above this severity.
            ``None`` disables the band rule.
        min_score: Fail if the project score is at or above this value.
    """
    reasons: list[str] = []
    if fail_on is not None:
        offending = [p for p in result.packages if p.band.rank >= fail_on.rank and p.score > 0]
        if offending:
            names = ", ".join(p.dependency.display for p in offending[:5])
            more = f" and {len(offending) - 5} more" if len(offending) > 5 else ""
            reasons.append(
                f"{len(offending)} package(s) rated {fail_on.value} or worse: {names}{more}"
            )
    if min_score is not None and result.project_score >= min_score:
        reasons.append(f"project risk score {result.project_score} >= threshold {min_score}")
    return reasons
