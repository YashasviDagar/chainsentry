"""Regenerate the popular-package lists used by the typosquatting check.

Usage::

    python scripts/update_popular_lists.py            # top 5,000 per ecosystem
    python scripts/update_popular_lists.py --limit 10000

Sources (both public, both ranked by downloads):

* PyPI - "Top PyPI Packages" by Hugo van Kemenade, built from the official
  PyPI BigQuery/ClickHouse download statistics (last 30 days).
  https://hugovk.github.io/top-pypi-packages/
* npm  - ``npm-high-impact`` by Titus Wormer (MIT), the most-downloaded npm
  packages. Pinned to a version so the snapshot is reproducible.
  https://github.com/wooorm/npm-high-impact

The output files are committed to the repo (``src/chainsentry/checks/data``)
so the typosquat check works offline and gives the same answer on every
machine. Each file starts with comment lines recording source and date.

SECURITY: the downloaded data is untrusted input. Every name is validated
(npm naming rules / PEP 503 normalisation) before being written, and the
JavaScript file is parsed with a regex - never executed.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx
from packaging.utils import canonicalize_name

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from chainsentry.parsers.npm_common import is_valid_npm_name  # noqa: E402

PYPI_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
NPM_HIGH_IMPACT_VERSION = "1.13.0"
NPM_URL = f"https://unpkg.com/npm-high-impact@{NPM_HIGH_IMPACT_VERSION}/lib/top-download.js"

DATA_DIR = Path(__file__).resolve().parents[1] / "src" / "chainsentry" / "checks" / "data"
_PYPI_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$")


def fetch_pypi(client: httpx.Client, limit: int) -> list[str]:
    rows = client.get(PYPI_URL).raise_for_status().json()["rows"]
    names: list[str] = []
    for row in rows:
        name = canonicalize_name(str(row.get("project", "")))
        if _PYPI_NAME_RE.match(name) and name not in names:
            names.append(name)
        if len(names) == limit:
            break
    return names


def fetch_npm(client: httpx.Client, limit: int) -> list[str]:
    source = client.get(NPM_URL).raise_for_status().text
    # The file is `export const topDownload = ['semver', 'minimatch', ...]`.
    names: list[str] = []
    for name in re.findall(r"'([^'\n]+)'", source):
        if is_valid_npm_name(name) and name not in names:
            names.append(name)
        if len(names) == limit:
            break
    return names


def write_list(path: Path, names: list[str], source: str) -> None:
    today = datetime.now(UTC).date().isoformat()
    header = [
        f"# Top {len(names)} packages by downloads, most popular first.",
        f"# Source: {source}",
        f"# Generated: {today} by scripts/update_popular_lists.py",
        "# One name per line; lines starting with '#' are comments.",
    ]
    path.write_text("\n".join(header + names) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {len(names):,} names to {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--limit", type=int, default=5000, help="names per ecosystem")
    args = parser.parse_args()

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        write_list(DATA_DIR / "top_pypi.txt", fetch_pypi(client, args.limit), PYPI_URL)
        write_list(DATA_DIR / "top_npm.txt", fetch_npm(client, args.limit), NPM_URL)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
