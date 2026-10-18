"""Allow ``python -m chainsentry ...`` as an alternative to the ``chainsentry`` command.

This is handy when the console script is not on PATH (e.g. a venv that is
not activated) and is the conventional entry point for Python CLI packages.
"""

from chainsentry.cli import main

# SystemExit carries main()'s return value out as the process exit code,
# which is what CI systems (Phase 6) look at.
raise SystemExit(main())
