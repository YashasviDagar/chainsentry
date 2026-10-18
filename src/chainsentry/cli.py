"""Command-line interface.

Design decisions
----------------
* **argparse (stdlib)** instead of click/typer: zero extra dependencies and
  every Python developer can read it.
* ``main()`` takes ``argv`` and **returns** an exit code instead of calling
  ``sys.exit`` itself. That makes it trivially testable
  (``assert main(["--version"]) == 0``) and keeps exiting in one place
  (``__main__.py`` / the console-script wrapper).
* Exit codes are part of the public API because CI systems only understand
  exit codes:

  ====  ===========================================================
  0     success / no risk above threshold
  1     risk threshold exceeded (``--fail-on`` / ``--min-score``)
  2     usage error, unreadable or invalid input
  ====  ===========================================================

Commands
--------
``chainsentry deps [PATH]``
    Lists the dependencies ChainSentry found, without any network lookups.
    Useful on its own for checking what will be scanned.
``chainsentry scan [PATH]``
    Runs every check and prints the risk report.
``chainsentry cache clear``
    Empties the on-disk HTTP cache.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from chainsentry import __version__, config
from chainsentry.models import Dependency, ScanResult, Severity
from chainsentry.parsers import ParseError, ParseResult, parse_project
from chainsentry.reporters import cyclonedx, json_report, markdown
from chainsentry.reporters import table as table_reporter
from chainsentry.scanner import CACHE_FILE, ScanOptions, open_cache, scan
from chainsentry.scoring import policy_violations

#: Check names accepted by --skip.
CHECK_NAMES = ("osv", "typosquat", "health")
#: --format value -> file name written into --output-dir ("table" prints instead).
OUTPUT_FILES = {"json": "report.json", "sbom": "sbom.cdx.json", "markdown": "report.md"}
FAIL_ON_CHOICES = ("none", "low", "medium", "high", "critical")

EXIT_OK = 0
EXIT_RISK = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    """Create the top-level argument parser and its sub-commands."""
    parser = argparse.ArgumentParser(
        prog="chainsentry",
        description="Dependency & supply-chain risk scanner for npm and PyPI projects.",
    )
    parser.add_argument("--version", action="version", version=f"chainsentry {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    deps = sub.add_parser(
        "deps",
        help="list the dependencies found in a project (no network access)",
        description="Parse manifest files and list every dependency found.",
    )
    deps.add_argument(
        "path",
        nargs="?",
        default=".",
        help="project directory or a single manifest file (default: current directory)",
    )
    deps.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="also search sub-directories (node_modules, venvs, .git are always skipped)",
    )
    deps.add_argument(
        "--direct-only",
        action="store_true",
        help="hide transitive dependencies (lockfiles can list thousands)",
    )
    deps.add_argument("--no-dev", action="store_true", help="hide development-only dependencies")

    scan_cmd = sub.add_parser(
        "scan",
        help="scan a project for vulnerable and risky dependencies",
        description="Parse manifests, run every check and report the risks found.",
    )
    _add_scan_arguments(scan_cmd)

    cache_cmd = sub.add_parser("cache", help="manage the local HTTP cache")
    cache_sub = cache_cmd.add_subparsers(dest="cache_command", metavar="<action>", required=True)
    cache_sub.add_parser("clear", help="delete every cached API response")
    cache_sub.add_parser("path", help="print where the cache is stored")
    return parser


def _add_scan_arguments(cmd: argparse.ArgumentParser) -> None:
    """Flags of ``chainsentry scan`` (kept separate so the list stays readable)."""
    cmd.add_argument(
        "path",
        nargs="?",
        default=".",
        help="project directory or a single manifest file (default: current directory)",
    )
    cmd.add_argument("-r", "--recursive", action="store_true", help="also search sub-directories")
    cmd.add_argument(
        "--include-dev", action="store_true", help="also scan development-only dependencies"
    )
    cmd.add_argument(
        "--resolve",
        action="store_true",
        help="resolve version ranges to the newest matching release so they can be checked",
    )
    cmd.add_argument(
        "--skip",
        action="append",
        default=[],
        choices=CHECK_NAMES,
        metavar="CHECK",
        help=f"skip a check; repeatable ({', '.join(CHECK_NAMES)})",
    )
    cmd.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="leave out packages whose name matches GLOB (e.g. '@mycorp/*'); "
        "excluded names are never sent to public APIs",
    )
    cmd.add_argument(
        "--health-direct-only",
        action="store_true",
        help="run registry health checks only for direct dependencies (faster)",
    )
    cmd.add_argument(
        "--offline", action="store_true", help="no network access; only offline checks run"
    )
    cmd.add_argument("--no-cache", action="store_true", help="do not read or write the HTTP cache")

    out = cmd.add_argument_group("output and CI gating")
    out.add_argument(
        "-f",
        "--format",
        action="append",
        choices=("table", *OUTPUT_FILES),
        help="output format; repeatable (default: table). json/sbom/markdown are written to "
        "--output-dir",
    )
    out.add_argument(
        "-o",
        "--output-dir",
        default="chainsentry-report",
        help="directory for report files (default: ./chainsentry-report)",
    )
    out.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default="critical",
        help="exit with code 1 if any package is rated at this level or worse (default: critical)",
    )
    out.add_argument(
        "--min-score",
        type=int,
        metavar="N",
        help="also exit with code 1 if the project risk score is N or higher",
    )
    out.add_argument(
        "--details", action="store_true", help="show every vulnerability and finding message"
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point used by the ``chainsentry`` console script.

    Args:
        argv: Arguments without the program name. ``None`` means "use
            ``sys.argv[1:]``" (argparse's default behaviour).

    Returns:
        The process exit code (see module docstring).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "deps":
        return _cmd_deps(args, Console())
    if args.command == "scan":
        return _cmd_scan(args, Console())
    if args.command == "cache":
        return _cmd_cache(args, Console())

    # No sub-command given: show help rather than doing nothing silently.
    parser.print_help()
    return EXIT_OK


def options_from_args(args: argparse.Namespace) -> ScanOptions:
    """Translate parsed CLI flags into :class:`ScanOptions`."""
    return ScanOptions(
        recursive=args.recursive,
        include_dev=args.include_dev,
        resolve=args.resolve,
        offline=args.offline,
        use_cache=not args.no_cache,
        skip=frozenset(args.skip),
        exclude=tuple(args.exclude),
        health_direct_only=args.health_direct_only,
    )


def _cmd_scan(args: argparse.Namespace, console: Console) -> int:
    """Implementation of ``chainsentry scan``."""
    try:
        with console.status("Scanning dependencies...", spinner="dots"):
            result = scan(args.path, options_from_args(args))
    except ParseError as exc:
        console.print(f"[bold red]error:[/] {escape(str(exc))}")
        return EXIT_ERROR

    fail_on = None if args.fail_on == "none" else Severity(args.fail_on.upper())
    reasons = policy_violations(result, fail_on=fail_on, min_score=args.min_score)

    formats = args.format or ["table"]
    if "table" in formats:
        table_reporter.render(result, console, details=args.details)
    for path in write_reports(result, formats, Path(args.output_dir), reasons):
        console.print(f"[dim]wrote {escape(str(path))}[/]")

    if reasons:
        for reason in reasons:
            console.print(f"[bold red]FAIL:[/] {escape(reason)}")
        return EXIT_RISK
    return EXIT_OK


def write_reports(
    result: ScanResult, formats: Sequence[str], output_dir: Path, reasons: list[str]
) -> list[Path]:
    """Write every requested file format into ``output_dir``; returns the paths written."""
    written: list[Path] = []
    for fmt in dict.fromkeys(formats):  # de-duplicate, keep order
        if fmt not in OUTPUT_FILES:
            continue
        path = output_dir / OUTPUT_FILES[fmt]
        path.parent.mkdir(parents=True, exist_ok=True)
        if fmt == "json":
            json_report.write(result, path)
        elif fmt == "sbom":
            cyclonedx.write(result, path)
        else:
            path.write_text(markdown.render(result, failed_reasons=reasons), encoding="utf-8")
        written.append(path)
    return written


def _cmd_cache(args: argparse.Namespace, console: Console) -> int:
    """Implementation of ``chainsentry cache clear|path``."""
    if args.cache_command == "path":
        console.print(str(config.cache_dir() / CACHE_FILE), markup=False, highlight=False)
        return EXIT_OK
    cache = open_cache(use_cache=True)
    removed = cache.clear()
    cache.close()
    console.print(f"Removed {removed} cached response(s).")
    return EXIT_OK


def _cmd_deps(args: argparse.Namespace, console: Console) -> int:
    """Implementation of ``chainsentry deps``."""
    try:
        result = parse_project(args.path, recursive=args.recursive)
    except ParseError as exc:
        # Expected, user-facing failure: print one clear line, no traceback.
        console.print(f"[bold red]error:[/] {escape(str(exc))}")
        return EXIT_ERROR

    deps = result.dependencies
    if args.direct_only:
        deps = [d for d in deps if d.direct]
    if args.no_dev:
        deps = [d for d in deps if not d.dev]

    if deps:
        console.print(_deps_table(deps, result))
    _print_summary(result, shown=len(deps), console=console)
    return EXIT_OK


def _deps_table(deps: list[Dependency], result: ParseResult) -> Table:
    """Build the rich table for ``deps``: one row per dependency."""
    table = Table(title="Dependencies", header_style="bold cyan", show_lines=False)
    # overflow="fold" wraps long values onto the next line instead of
    # cutting them off with "...", so names are never hidden in narrow terminals.
    table.add_column("Ecosystem")
    table.add_column("Package", style="bold", overflow="fold")
    table.add_column("Version", overflow="fold")
    table.add_column("Type")
    table.add_column("Source", style="dim", overflow="fold")
    table.add_column("Notes", style="yellow", overflow="fold")

    # Direct deps first, then alphabetical: what you declared is what you
    # usually want to read first.
    for dep in sorted(deps, key=lambda d: (not d.direct, d.ecosystem, d.name.lower())):
        # escape(): specs/paths come from untrusted files and may contain "["
        # characters that rich would otherwise treat as style markup.
        version = escape(dep.version) if dep.version else f"[dim]{escape(dep.spec or 'any')}[/]"
        kind = "direct" if dep.direct else "transitive"
        if dep.dev:
            kind += ", dev"
        notes = ", ".join(f.code for f in result.findings_for(dep))
        table.add_row(
            dep.ecosystem.value, escape(dep.name), version, kind, escape(dep.source_file), notes
        )
    return table


def _print_summary(result: ParseResult, *, shown: int, console: Console) -> None:
    """Print totals, the files that were read and any parser warnings."""
    deps = result.dependencies
    direct = sum(d.direct for d in deps)
    pinned = sum(d.version is not None for d in deps)
    console.print(
        f"\n[bold]{len(deps)}[/] dependencies ({direct} direct, {len(deps) - direct} transitive, "
        f"{pinned} with an exact version) from {len(result.files)} file(s): "
        f"{escape(', '.join(result.files)) or '-'}"
    )
    if shown != len(deps):
        console.print(f"[dim]showing {shown} after filters[/]")
    if result.warnings:
        console.print(f"\n[bold yellow]{len(result.warnings)} warning(s):[/]")
        for warning in result.warnings:
            # markup=False: file names/specs may contain "[" which rich would
            # otherwise try to interpret as style tags.
            console.print(f"  - {warning}", markup=False, highlight=False)
