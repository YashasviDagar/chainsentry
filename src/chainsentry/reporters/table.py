"""Coloured terminal output using ``rich``.

Layout (top to bottom)::

    ┌ ChainSentry ──────────────────────────────┐
    │ Project risk 87/100 CRITICAL  ...counts... │   summary panel
    └────────────────────────────────────────────┘
    Packages at risk          one row per package with score > 0
    Known vulnerabilities     worst first; capped unless --details
    Findings (--details)      every finding message per package
    warnings / incomplete checks

Reporters only *present* a :class:`~chainsentry.models.ScanResult`; they never
compute risk. That keeps the terminal, JSON, SBOM and Markdown outputs
consistent - they all read the same numbers (see ``summary.py``).

SECURITY: package names, specs and advisory text come from untrusted
sources (manifests, registries, OSV). Everything interpolated into rich
markup goes through ``escape()`` so text like ``[link=...]`` cannot inject
styling or clickable links into the terminal.
"""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from chainsentry.models import PackageReport, ScanResult, Severity
from chainsentry.reporters.summary import summarise

#: rich style per severity / risk band.
SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "green",
    Severity.UNKNOWN: "dim",
}

#: Vulnerability rows shown without --details.
DEFAULT_VULN_ROWS = 15


def styled(severity: Severity, text: str | None = None) -> str:
    """``text`` (default: the severity name) wrapped in the severity's colour."""
    return f"[{SEVERITY_STYLE[severity]}]{escape(text or severity.value)}[/]"


def render(result: ScanResult, console: Console, *, details: bool = False) -> None:
    """Print the full report for ``result``."""
    console.print(_summary_panel(result))
    _packages_table(result.packages, console)
    _vulnerability_table(result.packages, console, limit=None if details else DEFAULT_VULN_ROWS)
    if details:
        _findings(result.packages, console)
    _notes(result, console)


def _summary_panel(result: ScanResult) -> Panel:
    s = summarise(result)
    sev = s.vulnerabilities_by_severity
    lines = [
        "Project risk: "
        + styled(result.project_band, f"{result.project_score}/100 {result.project_band.value}"),
        f"Packages: [bold]{s.packages}[/] ({s.direct} direct)   "
        + "   ".join(f"{styled(Severity(b))}: {n}" for b, n in s.packages_by_band.items()),
        f"Known vulnerabilities: [bold]{s.vulnerabilities}[/] in {s.vulnerable_packages} package(s)"
        + ("  (" + ", ".join(f"{n} {k.lower()}" for k, n in sev.items()) + ")" if sev else "")
        + (
            f"  - {s.fixable_vulnerabilities} have a fix available"
            if s.fixable_vulnerabilities
            else ""
        ),
        f"[dim]{escape(', '.join(result.files) or 'no manifests')} | checks: "
        f"{', '.join(result.checks) or 'none'} | {result.duration_seconds:.1f}s[/]",
    ]
    if s.unchecked:
        lines.append(
            f"[yellow]{s.unchecked} package(s) have no exact version and were not checked for "
            "vulnerabilities (commit a lockfile, pin versions, or use --resolve).[/]"
        )
    return Panel(
        "\n".join(lines),
        title="[bold]ChainSentry[/]",
        border_style=SEVERITY_STYLE[result.project_band].split()[-1],
    )


def _packages_table(packages: list[PackageReport], console: Console) -> None:
    risky = sorted(
        (p for p in packages if p.score > 0), key=lambda p: (-p.score, p.dependency.name)
    )
    if not risky:
        console.print("[green]No risky packages found.[/]")
        return
    table = Table(title="Packages at risk", header_style="bold cyan", title_justify="left")
    table.add_column("Score", justify="right")
    table.add_column("Package", style="bold", overflow="fold")
    table.add_column("Version", overflow="fold")
    table.add_column("Type")
    table.add_column("Vulns", justify="right")
    table.add_column("Issues", overflow="fold")
    for report in risky:
        dep = report.dependency
        version = escape(dep.version or dep.spec or "?")
        if report.resolved:
            version += " [dim](resolved)[/]"
        kind = ("direct" if dep.direct else "transitive") + (", dev" if dep.dev else "")
        vulns = _vuln_counts(report)
        issues = ", ".join(f.code for f in report.findings)
        table.add_row(
            styled(report.band, str(report.score)), escape(dep.name), version, kind, vulns, issues
        )
    console.print(table)
    clean = len(packages) - len(risky)
    if clean:
        console.print(f"[dim]{clean} other package(s) have no known issues.[/]")


def _vuln_counts(report: PackageReport) -> str:
    """Compact "2C 1H 3M" style counts."""
    counts: dict[Severity, int] = {}
    for vuln in report.vulnerabilities:
        counts[vuln.severity] = counts.get(vuln.severity, 0) + 1
    order = sorted(counts, key=lambda s: -s.rank)
    return " ".join(styled(s, f"{counts[s]}{s.value[0]}") for s in order) or "-"


def _vulnerability_table(
    packages: list[PackageReport], console: Console, *, limit: int | None
) -> None:
    rows = [(report, vuln) for report in packages for vuln in report.vulnerabilities]
    if not rows:
        return
    rows.sort(
        key=lambda rv: (-rv[1].severity.rank, -(rv[1].cvss_score or 0), rv[0].dependency.name)
    )

    table = Table(title="Known vulnerabilities", header_style="bold cyan", title_justify="left")
    table.add_column("Severity")
    table.add_column("CVSS", justify="right")
    table.add_column("Package", style="bold", overflow="fold")
    table.add_column("Advisory", overflow="fold")
    table.add_column("Fixed in", style="green", overflow="fold")
    table.add_column("Summary", overflow="fold", max_width=60)
    for report, vuln in rows[:limit]:
        table.add_row(
            styled(vuln.severity),
            f"{vuln.cvss_score:.1f}" if vuln.cvss_score is not None else "-",
            escape(report.dependency.display),
            escape(", ".join([vuln.id, *vuln.cve_ids])),
            escape(", ".join(vuln.fixed_versions) or "no fix yet"),
            escape(vuln.summary),
        )
    console.print(table)
    if limit is not None and len(rows) > limit:
        console.print(
            f"[dim]Showing {limit} of {len(rows)} vulnerabilities - use --details or the JSON "
            "report for all of them.[/]"
        )


def _findings(packages: list[PackageReport], console: Console) -> None:
    with_findings = sorted((p for p in packages if p.findings), key=lambda p: -p.score)
    if not with_findings:
        return
    console.print("\n[bold cyan]Findings[/]")
    for report in with_findings:
        console.print(f"[bold]{escape(report.dependency.display)}[/] (score {report.score})")
        for finding in report.findings:
            console.print(f"  {styled(finding.severity)} {finding.code}: {escape(finding.message)}")


def _notes(result: ScanResult, console: Console) -> None:
    for error in result.errors:
        console.print(f"[bold yellow]incomplete:[/] {escape(error)}")
    if result.warnings:
        console.print(f"\n[bold yellow]{len(result.warnings)} warning(s):[/]")
        for warning in result.warnings:
            console.print(f"  - {warning}", markup=False, highlight=False)
