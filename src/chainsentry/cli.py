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
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from chainsentry import __version__

EXIT_OK = 0
EXIT_RISK = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    """Create the top-level argument parser (sub-commands are added per phase)."""
    parser = argparse.ArgumentParser(
        prog="chainsentry",
        description="Dependency & supply-chain risk scanner for npm and PyPI projects.",
    )
    parser.add_argument("--version", action="version", version=f"chainsentry {__version__}")
    # Sub-commands (`deps`, `scan`, `cache`) register themselves here in later phases.
    parser.add_subparsers(dest="command", metavar="<command>")
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

    if args.command is None:
        # No sub-command given: show help rather than doing nothing silently.
        parser.print_help()
        return EXIT_OK
    return EXIT_OK
