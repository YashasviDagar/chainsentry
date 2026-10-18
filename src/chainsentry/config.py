"""Central place for tunable constants.

Keeping magic numbers here (instead of scattered through the code) means:
  * they are documented in one spot,
  * tests can import and assert against them,
  * later phases add their own section (cache TTLs in Phase 2, typosquat
    thresholds in Phase 3, scoring weights in Phase 5) without hunting
    through modules.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Parsing (Phase 1)
# ---------------------------------------------------------------------------

# SECURITY: refuse to read manifest files larger than this. A real
# package-lock.json for a big monorepo is a few MB; anything near 50 MB is
# either broken or an attempt to exhaust memory (a "zip bomb"-style input).
MAX_MANIFEST_BYTES: int = 50 * 1024 * 1024

# SECURITY: maximum depth of nested `-r other.txt` includes in requirements
# files. Cycles are detected separately; this just bounds pathological chains.
MAX_REQUIREMENTS_INCLUDE_DEPTH: int = 10

# Directories never descended into when scanning recursively. They contain
# installed third-party code or build output, not the project's own
# manifests, and node_modules alone can hold tens of thousands of files.
SKIP_DIRS: frozenset[str] = frozenset(
    {
        "node_modules",
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        "site-packages",
        "dist",
        "build",
    }
)

# Hosts treated as "the official npm registry" when checking lockfile
# `resolved` URLs. registry.yarnpkg.com is a CNAME-style mirror of npmjs.
NPM_REGISTRY_HOSTS: frozenset[str] = frozenset({"registry.npmjs.org", "registry.yarnpkg.com"})
