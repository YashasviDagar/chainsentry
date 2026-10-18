"""Coloured terminal output using ``rich``.

Reporters only *present* a :class:`~chainsentry.models.ScanResult`; they never
compute risk. That keeps the terminal, JSON, SBOM and Markdown outputs
consistent with each other - they all read the same numbers.

SECURITY: package names, specs and advisory text come from untrusted
sources (manifests, registries, OSV). Everything interpolated into rich
markup goes through ``escape()`` so text like ``[link=...]`` cannot inject
styling or clickable links into the terminal.
"""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from chainsentry.models import PackageReport, ScanResult, Severity

#: rich style per severity / risk band.
SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "green",
    Severity.UNKNOWN: "dim",
}


def styled(severity: Severity) -> str:
    """``severity`` wrapped in its colour, ready for a rich table cell."""
    return f"[{SEVERITY_STYLE[severity]}]{severity.value}[/]"


def render(result: ScanResult, console: Console) -> None:
    """Print the full report for ``result``."""
    _vulnerability_table(result.packages, console)
    _summary(result, console)


def _vulnerability_table(packages: list[PackageReport], console: Console) -> None:
    rows = [(report, vuln) for report in packages for vuln in report.vulnerabilities]
    if not rows:
        return
    rows.sort(
        key=lambda rv: (-rv[1].severity.rank, -(rv[1].cvss_score or 0), rv[0].dependency.name)
    )

    table = Table(title="Known vulnerabilities", header_style="bold cyan")
    table.add_column("Package", style="bold", overflow="fold")
    table.add_column("Version")
    table.add_column("Advisory", overflow="fold")
    table.add_column("Severity")
    table.add_column("CVSS", justify="right")
    table.add_column("Affected", overflow="fold")
    table.add_column("Fixed in", style="green", overflow="fold")
    table.add_column("Summary", overflow="fold", max_width=50)

    for report, vuln in rows:
        dep = report.dependency
        version = escape(dep.version or "?") + (" [dim](resolved)[/]" if report.resolved else "")
        advisory = escape(", ".join([vuln.id, *vuln.cve_ids]))
        table.add_row(
            escape(dep.name),
            version,
            advisory,
            styled(vuln.severity),
            f"{vuln.cvss_score:.1f}" if vuln.cvss_score is not None else "-",
            escape("; ".join(vuln.affected_ranges) or "-"),
            escape(", ".join(vuln.fixed_versions) or "none yet"),
            escape(vuln.summary),
        )
    console.print(table)


def _summary(result: ScanResult, console: Console) -> None:
    packages = result.packages
    vulnerable = [p for p in packages if p.vulnerabilities]
    total_vulns = sum(len(p.vulnerabilities) for p in packages)
    unchecked = sum(1 for p in packages if p.dependency.version is None)

    files = escape(", ".join(result.files) or "-")
    console.print(
        f"\nScanned [bold]{len(packages)}[/] package(s) from {files} "
        f"in {result.duration_seconds:.1f}s - checks: {', '.join(result.checks) or 'none'}"
    )
    if total_vulns:
        console.print(
            f"[bold red]{total_vulns} known vulnerabilit{'y' if total_vulns == 1 else 'ies'}[/] "
            f"in {len(vulnerable)} package(s)."
        )
    elif "osv" in result.checks:
        console.print("[green]No known vulnerabilities found.[/]")
    if unchecked:
        console.print(
            f"[yellow]{unchecked} package(s) have no exact version and could not be checked "
            "for vulnerabilities[/] (add a lockfile / pin versions, or use --resolve)."
        )
    for error in result.errors:
        console.print(f"[bold yellow]incomplete:[/] {escape(error)}")
    if result.warnings:
        console.print(f"\n[bold yellow]{len(result.warnings)} warning(s):[/]")
        for warning in result.warnings:
            console.print(f"  - {warning}", markup=False, highlight=False)
