"""Batch mode: scan many public GitHub repositories and aggregate statistics.

Purpose: real numbers ("scanned 100 repositories, 63% had at least one known
vulnerability") instead of a single demo project.

How it works
------------
1. Pick repositories: from a text file (``owner/name`` per line) or a GitHub
   search query (``--search "language:python stars:>1000"``).
2. For each repository, list the **root directory** through the GitHub
   contents API and download only supported manifest files (no ``git clone``:
   much faster, far less data, and no untrusted code on disk).
3. Run the normal :func:`chainsentry.scanner.scan` on those files and save the
   JSON report per repository (``repos/<owner>__<name>.json``). Already
   scanned repositories are skipped, so an interrupted run can resume.
4. Aggregate every saved report into ``stats.json``, ``stats.csv`` and a
   human-readable ``SUMMARY.md``.

Ethics and limits
-----------------
* Only public data is read; nothing is written to any repository.
* Results are aggregate statistics. A typosquat hit is a *heuristic* and
  must be verified by hand before being called malicious.
* Only root-level manifests are scanned; monorepos and projects using
  Poetry/pnpm/yarn lockfiles are under-counted. Report the sample size and
  how repositories were chosen alongside any number you quote.
* Unauthenticated GitHub API access allows 60 requests/hour; set
  ``GITHUB_TOKEN`` (any classic or fine-grained token, no scopes needed for
  public repos) to get 5,000/hour.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import statistics
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from chainsentry import config
from chainsentry.net.client import HttpClient
from chainsentry.parsers import ParseError
from chainsentry.parsers.discovery import LOCKFILE_NAMES, PACKAGE_JSON, is_requirements_file
from chainsentry.reporters import json_report
from chainsentry.scanner import ScanOptions, open_cache, scan

GITHUB_API = "https://api.github.com"
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
#: Wait at most this long for a GitHub rate-limit reset before giving up.
MAX_RATE_LIMIT_WAIT = 15 * 60


class BatchError(Exception):
    """A repository could not be fetched."""


@dataclass
class RepoOutcome:
    repo: str
    status: str  # "scanned", "no-manifests", "error", "skipped"
    detail: str = ""


# ---------------------------------------------------------------------------
# GitHub access
# ---------------------------------------------------------------------------


class GitHubReader:
    """Minimal read-only GitHub REST client with rate-limit handling."""

    def __init__(
        self,
        token: str | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": config.USER_AGENT,
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(
            headers=headers, timeout=30, transport=transport, follow_redirects=True
        )
        self._sleep = sleep

    def close(self) -> None:
        self._client.close()

    def get(self, url: str, **params: Any) -> httpx.Response:
        """GET with one automatic wait-and-retry when the rate limit is hit."""
        for _ in range(2):
            response = self._client.get(url, params=params or None)
            if (
                response.status_code in (403, 429)
                and response.headers.get("X-RateLimit-Remaining") == "0"
            ):
                reset = float(response.headers.get("X-RateLimit-Reset", "0"))
                wait = max(0.0, reset - time.time()) + 1
                if wait > MAX_RATE_LIMIT_WAIT:
                    raise BatchError(
                        f"GitHub rate limit exhausted; resets in {wait / 60:.0f} min "
                        "(set GITHUB_TOKEN, then re-run: finished repos are skipped)"
                    )
                self._sleep(wait)
                continue
            return response
        return response

    def search(self, query: str, limit: int) -> list[str]:
        """Repository full names for a GitHub search query, most-starred first."""
        repos: list[str] = []
        page = 1
        while len(repos) < limit and page <= 10:  # the search API stops at 1,000 results
            response = self.get(
                f"{GITHUB_API}/search/repositories", q=query, sort="stars", per_page=100, page=page
            )
            if response.status_code != 200:
                raise BatchError(f"search failed with HTTP {response.status_code}")
            items = response.json().get("items", [])
            repos += [item["full_name"] for item in items]
            if len(items) < 100:
                break
            page += 1
        return repos[:limit]

    def download_manifests(self, repo: str, dest: Path) -> list[str]:
        """Save the supported root-level manifests of ``repo`` into ``dest``.

        Returns the file names saved (empty if the repository has none).
        """
        response = self.get(f"{GITHUB_API}/repos/{repo}/contents/")
        if response.status_code != 200:
            raise BatchError(f"listing failed with HTTP {response.status_code}")
        saved: list[str] = []
        for entry in response.json():
            name = str(entry.get("name", ""))
            # SECURITY: the name comes from the API. Only plain, known manifest
            # names are accepted, so it can never contain a path ("../x").
            if entry.get("type") != "file" or not _is_supported_name(name):
                continue
            if int(entry.get("size") or 0) > config.MAX_MANIFEST_BYTES:
                continue
            url = entry.get("download_url")
            if not url:
                continue
            raw = self._client.get(url)
            if raw.status_code != 200:
                raise BatchError(f"download of {name} failed with HTTP {raw.status_code}")
            (dest / name).write_bytes(raw.content)
            saved.append(name)
        return saved


def _is_supported_name(name: str) -> bool:
    if "/" in name or "\\" in name or name.startswith("."):
        return False
    return name in LOCKFILE_NAMES or name == PACKAGE_JSON or is_requirements_file(Path(name))


# ---------------------------------------------------------------------------
# Running the batch
# ---------------------------------------------------------------------------


def report_path(out_dir: Path, repo: str) -> Path:
    return out_dir / "repos" / (repo.replace("/", "__") + ".json")


def run_batch(
    repos: Iterable[str],
    out_dir: Path,
    *,
    reader: GitHubReader,
    options: ScanOptions,
    client: HttpClient,
    force: bool = False,
    log: Callable[[str], None] = print,
) -> list[RepoOutcome]:
    """Scan each repository and save its JSON report. Returns one outcome per repo."""
    outcomes: list[RepoOutcome] = []
    (out_dir / "repos").mkdir(parents=True, exist_ok=True)
    repos = list(repos)
    for index, repo in enumerate(repos, start=1):
        prefix = f"[{index}/{len(repos)}] {repo}"
        if not _REPO_RE.match(repo):
            outcomes.append(RepoOutcome(repo, "error", "not an owner/name"))
            continue
        target = report_path(out_dir, repo)
        if target.exists() and not force:
            outcomes.append(RepoOutcome(repo, "skipped", "already scanned"))
            log(f"{prefix}: already scanned")
            continue

        workdir = Path(tempfile.mkdtemp(prefix="chainsentry-batch-"))
        try:
            files = reader.download_manifests(repo, workdir)
            if not files:
                outcomes.append(RepoOutcome(repo, "no-manifests"))
                _write_marker(out_dir, repo, "no-manifests")
                log(f"{prefix}: no supported manifests")
                continue
            result = scan(workdir, options, client=client)
            result.target = repo
            data = json_report.to_dict(result)
            target.write_text(json.dumps(data, indent=1), encoding="utf-8", newline="\n")
            summary = data["summary"]
            outcomes.append(RepoOutcome(repo, "scanned"))
            log(
                f"{prefix}: {summary['packages']} packages, {summary['vulnerabilities']} vulns, "
                f"score {summary['project_score']}"
            )
        except (BatchError, ParseError, httpx.HTTPError) as exc:
            outcomes.append(RepoOutcome(repo, "error", str(exc)))
            log(f"{prefix}: ERROR {exc}")
            if "rate limit exhausted" in str(exc):
                break
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
    return outcomes


def _write_marker(out_dir: Path, repo: str, status: str) -> None:
    """Remember repositories without manifests so resumed runs skip them too."""
    report_path(out_dir, repo).write_text(
        json.dumps({"repo": repo, "status": status}), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def load_reports(out_dir: Path) -> tuple[list[dict[str, Any]], int]:
    """Return (scanned reports, number of repos without manifests)."""
    reports: list[dict[str, Any]] = []
    empty = 0
    for path in sorted((out_dir / "repos").glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("status") == "no-manifests":
            empty += 1
        elif "summary" in data:
            reports.append(data)
    return reports, empty


def aggregate(reports: list[dict[str, Any]], repos_without_manifests: int = 0) -> dict[str, Any]:
    """Compute dataset-level statistics from per-repository JSON reports."""
    n = len(reports)
    severities: Counter[str] = Counter()
    codes: Counter[str] = Counter()
    vulnerable_pkg_repos: Counter[str] = Counter()  # "eco:name" -> repos affected
    advisories: Counter[str] = Counter()
    bands: Counter[str] = Counter()
    unique: set[tuple[str, str, str | None]] = set()
    rows: list[dict[str, Any]] = []
    total_packages = total_vulnerable_packages = total_unchecked = 0

    for report in reports:
        summary = report["summary"]
        packages = report["packages"]
        bands[summary["project_band"]] += 1
        repo_severities: Counter[str] = Counter()
        repo_codes: Counter[str] = Counter()
        for pkg in packages:
            unique.add((pkg["ecosystem"], pkg["name"], pkg["version"]))
            if pkg["vulnerabilities"]:
                vulnerable_pkg_repos[f"{pkg['ecosystem']}:{pkg['name']}"] += 1
            for vuln in pkg["vulnerabilities"]:
                repo_severities[vuln["severity"]] += 1
                advisories[vuln["id"]] += 1
            for finding in pkg["findings"]:
                repo_codes[finding["code"]] += 1
        severities.update(repo_severities)
        codes.update(repo_codes)
        total_packages += summary["packages"]
        total_vulnerable_packages += summary["vulnerable_packages"]
        total_unchecked += summary["unchecked"]
        rows.append(
            {
                "repo": report["scan"]["target"],
                "files": " ".join(report["scan"]["files"]),
                "packages": summary["packages"],
                "direct": summary["direct"],
                "unchecked": summary["unchecked"],
                "vulnerable_packages": summary["vulnerable_packages"],
                "vulnerabilities": summary["vulnerabilities"],
                "critical": repo_severities["CRITICAL"],
                "high": repo_severities["HIGH"],
                "typosquat": repo_codes["TYPOSQUAT"],
                "install_scripts": repo_codes["INSTALL_SCRIPT"],
                "not_in_registry": repo_codes["NOT_IN_REGISTRY"],
                "project_score": summary["project_score"],
                "project_band": summary["project_band"],
            }
        )

    def pct(count: int) -> float:
        return round(100 * count / n, 1) if n else 0.0

    scores = [r["project_score"] for r in rows]
    return {
        "repositories_scanned": n,
        "repositories_without_supported_manifests": repos_without_manifests,
        "total_dependencies": total_packages,
        "unique_package_versions": len(unique),
        # Dependencies without an exact version could not be checked for CVEs;
        # always quote this next to vulnerability numbers.
        "unchecked_dependencies": total_unchecked,
        "vulnerable_dependencies": total_vulnerable_packages,
        "total_vulnerabilities": sum(severities.values()),
        "vulnerabilities_by_severity": dict(severities.most_common()),
        "repos_with_any_vulnerability": sum(1 for r in rows if r["vulnerabilities"]),
        "repos_with_any_vulnerability_pct": pct(sum(1 for r in rows if r["vulnerabilities"])),
        "repos_with_critical_pct": pct(sum(1 for r in rows if r["critical"])),
        "repos_with_install_scripts_pct": pct(sum(1 for r in rows if r["install_scripts"])),
        "repos_with_typosquat_suspects": sum(1 for r in rows if r["typosquat"]),
        "median_project_score": statistics.median(scores) if scores else 0,
        "project_bands": dict(bands.most_common()),
        "findings_by_code": dict(codes.most_common()),
        "most_common_vulnerable_packages": vulnerable_pkg_repos.most_common(15),
        "most_common_advisories": advisories.most_common(15),
        "rows": rows,
    }


def write_outputs(stats: dict[str, Any], out_dir: Path) -> list[Path]:
    """Write stats.json, stats.csv and SUMMARY.md."""
    rows = stats["rows"]
    stats_path = out_dir / "stats.json"
    stats_path.write_text(
        json.dumps({k: v for k, v in stats.items() if k != "rows"}, indent=2),
        encoding="utf-8",
        newline="\n",
    )
    csv_path = out_dir / "stats.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        if rows:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    md_path = out_dir / "SUMMARY.md"
    md_path.write_text(summary_markdown(stats), encoding="utf-8", newline="\n")
    return [stats_path, csv_path, md_path]


def summary_markdown(stats: dict[str, Any]) -> str:
    sev = stats["vulnerabilities_by_severity"]
    lines = [
        "# ChainSentry batch scan",
        "",
        f"* Repositories scanned: **{stats['repositories_scanned']}** "
        f"(+{stats['repositories_without_supported_manifests']} without supported root manifests)",
        f"* Dependencies analysed: **{stats['total_dependencies']:,}** "
        f"({stats['unique_package_versions']:,} unique package versions; "
        f"{stats['unchecked_dependencies']:,} had no exact version and were not checked "
        "for vulnerabilities)",
        f"* Vulnerable dependencies: **{stats['vulnerable_dependencies']:,}** with "
        f"**{stats['total_vulnerabilities']:,}** known vulnerabilities "
        f"({', '.join(f'{v} {k.lower()}' for k, v in sev.items()) or 'none'})",
        f"* Repositories with at least one known vulnerability: "
        f"**{stats['repos_with_any_vulnerability_pct']}%**",
        f"* Repositories with a CRITICAL vulnerability: **{stats['repos_with_critical_pct']}%**",
        f"* Repositories depending on packages with install scripts: "
        f"**{stats['repos_with_install_scripts_pct']}%**",
        f"* Repositories with typosquat suspects (unverified): "
        f"**{stats['repos_with_typosquat_suspects']}**",
        f"* Median project risk score: **{stats['median_project_score']}**",
        "",
        "## Most common vulnerable packages (repositories affected)",
        "",
        *[f"1. `{name}`: {count}" for name, count in stats["most_common_vulnerable_packages"]],
        "",
        "## Most common advisories",
        "",
        *[
            f"1. [{vid}](https://osv.dev/vulnerability/{vid}): {count}"
            for vid, count in stats["most_common_advisories"]
        ],
        "",
        "_Root-level manifests only; typosquat suspects are heuristic and need manual review._",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def read_repo_list(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="batch_scan", description="Scan many public GitHub repositories with ChainSentry."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--repos", type=Path, help="text file with one owner/name per line")
    source.add_argument("--search", help='GitHub search query, e.g. "language:python stars:>1000"')
    parser.add_argument("--limit", type=int, default=100, help="max repositories (default 100)")
    parser.add_argument("--out", type=Path, default=Path("batch-results"), help="output directory")
    parser.add_argument("--include-dev", action="store_true")
    parser.add_argument("--resolve", action="store_true", help="resolve unpinned ranges")
    parser.add_argument(
        "--skip-health", action="store_true", help="skip registry health checks (much faster)"
    )
    parser.add_argument("--force", action="store_true", help="re-scan repositories already done")
    parser.add_argument(
        "--aggregate-only", action="store_true", help="only rebuild stats from saved reports"
    )
    args = parser.parse_args(argv)

    if not args.aggregate_only:
        reader = GitHubReader(os.environ.get("GITHUB_TOKEN"))
        client = HttpClient(open_cache(True))
        try:
            repos = (
                read_repo_list(args.repos)[: args.limit]
                if args.repos
                else reader.search(args.search, args.limit)
            )
            options = ScanOptions(
                include_dev=args.include_dev,
                resolve=args.resolve,
                skip=frozenset({"health"}) if args.skip_health else frozenset(),
                # Direct-only keeps big lockfiles from costing thousands of lookups.
                health_direct_only=True,
            )
            outcomes = run_batch(
                repos, args.out, reader=reader, options=options, client=client, force=args.force
            )
            counts = Counter(o.status for o in outcomes)
            print("outcomes:", dict(counts))
        except BatchError as exc:
            print(f"error: {exc}")
            return 2
        finally:
            reader.close()
            client.close()

    reports, empty = load_reports(args.out)
    for path in write_outputs(aggregate(reports, empty), args.out):
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
