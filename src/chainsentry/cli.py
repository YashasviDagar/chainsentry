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
  1     risk threshold exceeded (Phase 5)
  2     usage error, unreadable or invalid input
  ====  ===========================================================

Commands
--------
``chainsentry deps [PATH]``
    Phase 1. Lists the dependencies ChainSentry found, without any network
    lookups. Useful on its own for checking what will be scanned.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from chainsentry import __version__
from chainsentry.models import Dependency
from chainsentry.parsers import ParseError, ParseResult, parse_project

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
    return parser


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

    # No sub-command given: show help rather than doing nothing silently.
    parser.print_help()
    return EXIT_OK


def _cmd_deps(args: argparse.Namespace, console: Console) -> int:
    """Implementation of ``chainsentry deps``."""
    try:
        result = parse_project(args.path, recursive=args.recursive)
    except ParseError as exc:
        # Expected, user-facing failure: print one clear line, no traceback.
        console.print(f"[bold red]error:[/] {exc}")
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
