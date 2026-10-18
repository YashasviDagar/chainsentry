"""ChainSentry - a dependency & supply-chain risk scanner.

ChainSentry reads a project's dependency manifests (``package.json``,
``package-lock.json``, ``requirements.txt``), then flags risky packages:
known vulnerabilities (OSV.dev), typosquatting look-alikes, and unhealthy
packages (abandoned, brand new, install scripts, ...).

Package layout (see PLAN.md for the full architecture)::

    chainsentry/
      models.py     shared dataclasses - the vocabulary every layer speaks
      config.py     tunable constants (limits, thresholds, weights)
      cli.py        command-line entry point
      parsers/      manifest files  -> Dependency objects   (no network)
      checks/       Dependency      -> Findings             (Phase 2-4)
      scoring/      Findings        -> 0-100 risk scores    (Phase 5)
      reporters/    results         -> table / JSON / SBOM  (Phase 5)
"""

# Single source of truth for the version: pyproject.toml reads it from here
# (via [tool.hatch.version]) and the CLI prints it for `--version`.
__version__ = "0.1.0"
