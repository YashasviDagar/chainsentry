"""Markdown report for GitHub PR comments and job summaries.

Kept compact on purpose: a PR comment should answer "is this change safe?"
at a glance. The full detail lives in the JSON report / SBOM artifacts.

SECURITY: package names, versions and advisory summaries are untrusted text
that ends up in a GitHub comment. :func:`md_escape` neutralises characters
that would break the table (``|``), inject HTML (``<``/``>``), or - easy to
miss - **@-mention** people or teams (an advisory summary containing
``@org/security`` would otherwise ping that team on every PR).
"""

from __future__ import annotations

from chainsentry.models import PackageReport, ScanResult, Severity
from chainsentry.reporters.summary import summarise

#: Hidden marker the GitHub Action uses to find and update its own comment
#: instead of posting a new one on every push.
COMMENT_MARKER = "<!-- chainsentry-report -->"

_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🟢",
    Severity.UNKNOWN: "⚪",
}

MAX_PACKAGE_ROWS = 15
MAX_VULN_ROWS = 10


def md_escape(text: str) -> str:
    """Make untrusted text safe inside a Markdown table cell."""
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("@", "@&#8203;")  # zero-width space: no @-mention
        .replace("\n", " ")
    )


def md_code(text: str) -> str:
    """Untrusted text as an inline code span inside a table cell.

    Code spans are rendered literally (no HTML, no @-mentions), so only the
    backtick that would end the span and the table's ``|`` need handling.
    """
    return "`" + text.replace("`", "'").replace("|", "\\|").replace("\n", " ") + "`"


def render(result: ScanResult, *, failed_reasons: list[str] | None = None) -> str:
    """Render ``result`` as GitHub-flavoured Markdown."""
    summary = summarise(result)
    lines = [
        COMMENT_MARKER,
        f"## {_ICON[result.project_band]} ChainSentry: project risk "
        f"**{result.project_score}/100** ({result.project_band.value})",
        "",
    ]
    if failed_reasons:
        lines += ["> [!CAUTION]", "> **Check failed:** " + md_escape("; ".join(failed_reasons)), ""]

    by_sev = summary.vulnerabilities_by_severity
    lines += [
        "| Packages | Known vulnerabilities | Critical | High | Medium | Low | Other findings |",
        "|---:|---:|---:|---:|---:|---:|---:|",
        f"| {summary.packages} | {summary.vulnerabilities} "
        f"| {by_sev.get('CRITICAL', 0)} | {by_sev.get('HIGH', 0)} | {by_sev.get('MEDIUM', 0)} "
        f"| {by_sev.get('LOW', 0) + by_sev.get('UNKNOWN', 0)} "
        f"| {sum(summary.findings_by_code.values())} |",
        "",
    ]

    risky = sorted((p for p in result.packages if p.score > 0), key=lambda p: -p.score)
    if risky:
        lines += [
            "### Riskiest packages",
            "",
            "| | Package | Version | Score | Why |",
            "|---|---|---|---:|---|",
        ]
        for report in risky[:MAX_PACKAGE_ROWS]:
            lines.append(_package_row(report))
        if len(risky) > MAX_PACKAGE_ROWS:
            lines.append(f"\n_…and {len(risky) - MAX_PACKAGE_ROWS} more in the JSON report._")
        lines.append("")
    else:
        lines += ["✅ No risky dependencies found.", ""]

    vulns = sorted(
        ((r, v) for r in result.packages for v in r.vulnerabilities),
        key=lambda rv: (-rv[1].severity.rank, -(rv[1].cvss_score or 0)),
    )
    if vulns:
        lines += [
            "<details><summary><b>Top vulnerabilities</b></summary>",
            "",
            "| Severity | Package | Advisory | Fixed in | Summary |",
            "|---|---|---|---|---|",
        ]
        for report, vuln in vulns[:MAX_VULN_ROWS]:
            cve = f" ({', '.join(vuln.cve_ids)})" if vuln.cve_ids else ""
            lines.append(
                f"| {_ICON[vuln.severity]} {vuln.severity.value} "
                f"| {md_code(report.dependency.display)} "
                f"| [{vuln.id}](https://osv.dev/vulnerability/{vuln.id}){cve} "
                f"| {md_escape(', '.join(vuln.fixed_versions) or 'no fix yet')} "
                f"| {md_escape(vuln.summary)} |"
            )
        lines += ["", "</details>", ""]

    notes = result.errors + result.warnings
    if notes:
        lines += ["<details><summary>Warnings and incomplete checks</summary>", ""]
        lines += [f"- {md_escape(n)}" for n in notes]
        lines += ["", "</details>", ""]

    lines.append(
        f"<sub>ChainSentry {result.tool_version} · {len(result.files)} manifest(s) · "
        f"checks: {', '.join(result.checks) or 'none'} · {result.scanned_at}</sub>"
    )
    return "\n".join(lines) + "\n"


def _package_row(report: PackageReport) -> str:
    """One table row: icon, name, version, score and a short "why"."""
    dep = report.dependency
    why: list[str] = []
    if report.vulnerabilities:
        worst = max(report.vulnerabilities, key=lambda v: v.severity.rank)
        why.append(f"{len(report.vulnerabilities)} vuln(s), worst {worst.severity.value}")
    why += [f.code for f in report.findings]
    return (
        f"| {_ICON[report.band]} | {md_code(dep.name)} "
        f"| {md_escape(dep.version or dep.spec or '?')} "
        f"| {report.score} | {md_escape(', '.join(why))} |"
    )
