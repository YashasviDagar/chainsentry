"""Central place for tunable constants.

Keeping magic numbers here (instead of scattered through the code) means:
  * they are documented in one spot,
  * tests can import and assert against them,
  * each phase adds its own section (network/cache in Phase 2, typosquat
    thresholds in Phase 3, health rules in Phase 4, scoring weights in
    Phase 5) without hunting through modules.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from chainsentry import __version__

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

# ---------------------------------------------------------------------------
# Network (Phase 2)
# ---------------------------------------------------------------------------

#: Sent with every request. Public APIs ask clients to identify themselves so
#: operators can contact them instead of simply blocking unknown traffic.
USER_AGENT: str = f"chainsentry/{__version__} (dependency risk scanner)"

#: Seconds. Every request has a timeout: a hung connection must never hang CI.
HTTP_CONNECT_TIMEOUT: float = 5.0
HTTP_READ_TIMEOUT: float = 30.0

#: Retries for transient failures (timeouts, HTTP 429 and 5xx).
HTTP_MAX_RETRIES: int = 3
#: Exponential backoff: wait BASE * 2**attempt seconds (plus jitter) between tries.
HTTP_BACKOFF_BASE: float = 0.5
#: Never wait longer than this for a server's Retry-After header.
HTTP_MAX_RETRY_AFTER: float = 30.0

#: SECURITY: refuse HTTP responses larger than this. Full npm metadata for a
#: very popular package can be tens of MB; anything far beyond is abnormal.
MAX_RESPONSE_BYTES: int = 150 * 1024 * 1024

#: Parallel requests for per-package lookups (vuln details, registry metadata).
#: Small enough to be polite to free public APIs.
MAX_WORKERS: int = 8

OSV_API_URL: str = "https://api.osv.dev/v1"
#: OSV's documented maximum number of queries per /v1/querybatch request.
OSV_BATCH_SIZE: int = 1000
NPM_REGISTRY_URL: str = "https://registry.npmjs.org"
PYPI_JSON_URL: str = "https://pypi.org/pypi"

# Cache lifetimes, in seconds. Vulnerability data changes daily at most, and
# package metadata (release dates, maintainers) changes rarely.
TTL_OSV_QUERY: int = 6 * 3600
TTL_OSV_VULN: int = 24 * 3600
TTL_REGISTRY: int = 24 * 3600
#: "Package not found" is cached briefly: a name could be registered at any time.
TTL_NOT_FOUND: int = 3600


def cache_dir() -> Path:
    """Where the on-disk HTTP cache lives.

    Order of precedence:
      1. ``CHAINSENTRY_CACHE_DIR`` environment variable (used by the GitHub Action)
      2. Windows: ``%LOCALAPPDATA%/chainsentry/cache``
      3. elsewhere: ``$XDG_CACHE_HOME/chainsentry`` or ``~/.cache/chainsentry``
    """
    override = os.environ.get("CHAINSENTRY_CACHE_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "chainsentry" / "cache"
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "chainsentry"


# ---------------------------------------------------------------------------
# Package health (Phase 4)
# ---------------------------------------------------------------------------

#: No release for this long -> "abandoned": security fixes are unlikely.
ABANDONED_DAYS: int = 730
#: Package first published less than this long ago -> "very new". Most
#: malicious packages are reported and removed within days of publication.
NEW_PACKAGE_DAYS: int = 30
#: The *installed version* was published less than this long ago. Hijacked
#: maintainer accounts push fresh malicious versions (ua-parser-js, 2021).
NEW_VERSION_DAYS: int = 7
#: npm packages with this many maintainers or fewer are flagged
#: (one compromised account = full control of the package).
SINGLE_MAINTAINER_MAX: int = 1

# ---------------------------------------------------------------------------
# Risk scoring (Phase 5) - explained with examples in docs/SCORING.md
# ---------------------------------------------------------------------------

#: Points for the *worst* known vulnerability of a package, by severity.
#: Chosen so a package's band is never lower than its worst vulnerability:
#: CRITICAL 75 lands in the CRITICAL band (75+), HIGH 50 in HIGH (50-74),
#: MEDIUM 25 in MEDIUM (20-49). UNKNOWN is treated like MEDIUM: a published
#: advisory without a rating is still a real advisory.
VULN_POINTS: dict[str, int] = {"CRITICAL": 75, "HIGH": 50, "MEDIUM": 25, "LOW": 5, "UNKNOWN": 25}
#: Each *additional* vulnerability adds a little, up to a cap - ten medium
#: bugs are worse than one, but not ten times worse.
EXTRA_VULN_POINTS: int = 2
EXTRA_VULN_CAP: int = 10

#: Points per finding code (from parsers, health and typosquat checks).
SIGNAL_POINTS: dict[str, int] = {
    "NOT_IN_REGISTRY": 40,
    "VERSION_NOT_IN_REGISTRY": 25,
    "NEW_PACKAGE": 20,
    "INSTALL_SCRIPT": 15,
    "NEW_VERSION": 10,
    "ABANDONED": 10,
    "DEPRECATED": 10,
    "YANKED": 10,
    "NON_REGISTRY_SOURCE": 10,
    "SINGLE_MAINTAINER": 5,
    "UNPINNED": 5,
    "NO_REPOSITORY": 5,
    "NPM_ALIAS": 5,
    "MISSING_INTEGRITY": 5,
}
#: Typosquat points depend on the detector's confidence.
TYPOSQUAT_POINTS: dict[str, int] = {"HIGH": 50, "MEDIUM": 30}

#: Score -> band thresholds, highest first.
BANDS: tuple[tuple[int, str], ...] = ((75, "CRITICAL"), (50, "HIGH"), (20, "MEDIUM"), (0, "LOW"))
#: Project score = worst package + this many points per other HIGH/CRITICAL package.
PROJECT_POINTS_PER_RISKY_PACKAGE: int = 2
