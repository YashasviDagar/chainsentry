"""Known-vulnerability lookup using the OSV.dev API.

OSV (Open Source Vulnerabilities, https://osv.dev) aggregates advisories from
GitHub (GHSA), the PyPI advisory DB (PYSEC), npm, OSS-Fuzz and more into one
schema: https://ossf.github.io/osv-schema/

How a lookup works
------------------
1. ``POST /v1/querybatch`` with up to 1,000 ``(ecosystem, name, version)``
   queries. The answer lists only vulnerability **IDs** per query.
   (If one package has very many vulns, OSV paginates with
   ``next_page_token``; we follow it with ``POST /v1/query``.)
2. ``GET /v1/vulns/{id}`` for each *unique* ID to get the full record:
   summary, severity, affected ranges, fixed versions, references.

Caching strategy
----------------
Each *package version's* ID list is cached separately
(``osv-query:PyPI:django:3.2.0``), not the whole batch. Adding one dependency
to a project then costs one query instead of invalidating the cache for all
of them. Vulnerability records are cached by ID.

De-duplication
--------------
The same flaw often appears twice: ``GHSA-xxxx`` and ``PYSEC-yyyy`` both
listing ``CVE-2023-1234`` as an alias. We keep the first record (GHSA
records are processed first because they carry severity data) and drop
any later record whose ID or aliases were already seen.
"""

from __future__ import annotations

from typing import Any

from packaging.utils import canonicalize_name

from chainsentry import config
from chainsentry.checks.base import chunked, parallel_map
from chainsentry.checks.cvss import base_score, severity_from_score
from chainsentry.models import Dependency, Ecosystem, PackageReport, Severity, Vulnerability
from chainsentry.net.cache import MISS
from chainsentry.net.client import HttpClient, HttpError, quote_segment

# GitHub advisories label severity "MODERATE" where CVSS says "MEDIUM".
_LABELS = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

_MAX_REFERENCES = 5


class OsvCheck:
    """Look up every exactly-versioned dependency in OSV.dev."""

    name = "osv"
    needs_network = True

    def __init__(self, client: HttpClient) -> None:
        self.client = client

    def run(self, packages: list[PackageReport]) -> list[str]:
        errors: list[str] = []

        # OSV needs an exact version; unpinned dependencies cannot be checked.
        queryable: dict[tuple, list[PackageReport]] = {}
        for report in packages:
            if report.dependency.version:
                queryable.setdefault(report.dependency.key, []).append(report)
        if not queryable:
            return errors

        deps = [reports[0].dependency for reports in queryable.values()]
        try:
            ids_by_key = self._query_ids(deps)
        except HttpError as exc:
            return [f"osv: vulnerability lookup failed ({exc})"]

        all_ids = sorted({i for ids in ids_by_key.values() for i in ids})
        records = dict(zip(all_ids, parallel_map(self._fetch_record, all_ids), strict=True))
        missing = [i for i, r in records.items() if r is None]
        if missing:
            errors.append(
                f"osv: could not fetch details for {len(missing)} vulnerability record(s)"
            )

        for key, reports in queryable.items():
            dep = reports[0].dependency
            vulns = _build_vulnerabilities(dep, [records[i] for i in ids_by_key.get(key, [])])
            for report in reports:
                report.vulnerabilities.extend(vulns)
        return errors

    # -- step 1: which vulnerability IDs affect each package version? --------

    def _query_ids(self, deps: list[Dependency]) -> dict[tuple, list[str]]:
        result: dict[tuple, list[str]] = {}
        uncached: list[Dependency] = []
        for dep in deps:
            cached = self.client.cache.get_json(_query_cache_key(dep))
            if cached is MISS:
                uncached.append(dep)
            else:
                result[dep.key] = cached

        for chunk in chunked(uncached, config.OSV_BATCH_SIZE):
            payload = {"queries": [_query(dep) for dep in chunk]}
            data = self.client.post_json(f"{config.OSV_API_URL}/querybatch", payload)
            answers = (data or {}).get("results", [])
            if len(answers) != len(chunk):
                raise HttpError("querybatch returned an unexpected number of results")
            for dep, answer in zip(chunk, answers, strict=True):
                ids = [v["id"] for v in answer.get("vulns") or [] if "id" in v]
                token = answer.get("next_page_token")
                while token:  # rare: >1,000 vulns for one package version
                    page = self.client.post_json(
                        f"{config.OSV_API_URL}/query", {**_query(dep), "page_token": token}
                    )
                    ids += [v["id"] for v in (page or {}).get("vulns") or [] if "id" in v]
                    token = (page or {}).get("next_page_token")
                result[dep.key] = ids
                self.client.cache.set_json(_query_cache_key(dep), ids, config.TTL_OSV_QUERY)
        return result

    # -- step 2: fetch the full record for each ID ----------------------------

    def _fetch_record(self, vuln_id: str) -> dict[str, Any] | None:
        try:
            return self.client.get_json(
                f"{config.OSV_API_URL}/vulns/{quote_segment(vuln_id)}",
                cache_key=f"osv-vuln:{vuln_id}",
                ttl=config.TTL_OSV_VULN,
            )
        except HttpError:
            return None


def _query(dep: Dependency) -> dict[str, Any]:
    return {
        "package": {"name": dep.name, "ecosystem": dep.ecosystem.value},
        "version": dep.version,
    }


def _query_cache_key(dep: Dependency) -> str:
    return f"osv-query:{dep.ecosystem.value}:{dep.name}:{dep.version}"


def _build_vulnerabilities(
    dep: Dependency, records: list[dict[str, Any] | None]
) -> list[Vulnerability]:
    """Turn OSV records into de-duplicated ``Vulnerability`` objects for ``dep``."""
    usable = [r for r in records if r and not r.get("withdrawn")]
    # GHSA first: those records carry CVSS vectors and severity labels.
    usable.sort(key=lambda r: (not str(r.get("id", "")).startswith("GHSA-"), r.get("id", "")))

    seen: set[str] = set()
    vulns: list[Vulnerability] = []
    for record in usable:
        ids = {record["id"], *record.get("aliases", [])}
        if ids & seen:
            continue
        seen |= ids
        vulns.append(parse_record(record, dep))
    return vulns


def parse_record(record: dict[str, Any], dep: Dependency) -> Vulnerability:
    """Convert one OSV JSON record into a :class:`Vulnerability` for ``dep``."""
    score, vector = _cvss(record)
    if score is not None:
        severity = severity_from_score(score)
    else:
        label = str((record.get("database_specific") or {}).get("severity", "")).upper()
        severity = _LABELS.get(label, Severity.UNKNOWN)
    if str(record.get("id", "")).startswith("MAL-"):
        # A known-malicious package is the worst possible finding.
        severity = Severity.CRITICAL

    ranges, fixed = _affected_ranges(record, dep)
    summary = record.get("summary") or (record.get("details") or "").strip().split("\n")[0]
    return Vulnerability(
        id=record["id"],
        aliases=list(record.get("aliases", [])),
        summary=summary[:300] or "(no summary)",
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        affected_ranges=ranges,
        fixed_versions=fixed,
        references=[r["url"] for r in record.get("references", []) if "url" in r][:_MAX_REFERENCES],
        published=record.get("published"),
    )


def _cvss(record: dict[str, Any]) -> tuple[float | None, str | None]:
    """Find a CVSS v3 vector (record-level, or per affected package) and score it."""
    candidates = list(record.get("severity") or [])
    for affected in record.get("affected") or []:
        candidates += affected.get("severity") or []
    for entry in candidates:
        if entry.get("type") == "CVSS_V3":
            try:
                return base_score(entry["score"]), entry["score"]
            except (ValueError, KeyError):
                continue
    return None, None


def _same_package(affected_pkg: dict[str, Any], dep: Dependency) -> bool:
    if affected_pkg.get("ecosystem") != dep.ecosystem.value:
        return False
    name = str(affected_pkg.get("name", ""))
    if dep.ecosystem is Ecosystem.PYPI:
        return canonicalize_name(name) == dep.name
    return name == dep.name


def _affected_ranges(record: dict[str, Any], dep: Dependency) -> tuple[list[str], list[str]]:
    """Describe the affected version ranges and fixed versions for *this* package.

    OSV ranges are event lists, read in order::

        [{"introduced": "0"}, {"fixed": "4.17.21"}]   ->  "<4.17.21"
        [{"introduced": "2.0"}, {"last_affected": "2.3"}] -> ">=2.0, <=2.3"
    """
    ranges: list[str] = []
    fixed: list[str] = []
    for affected in record.get("affected") or []:
        if not _same_package(affected.get("package") or {}, dep):
            continue
        for rng in affected.get("ranges") or []:
            if rng.get("type") == "GIT":
                continue  # commit hashes mean nothing to a package user
            lower: str | None = None
            for event in rng.get("events") or []:
                if "introduced" in event:
                    lower = event["introduced"]
                elif "fixed" in event or "last_affected" in event:
                    upper_op, upper = (
                        ("<", event["fixed"])
                        if "fixed" in event
                        else ("<=", event["last_affected"])
                    )
                    if "fixed" in event and upper not in fixed:
                        fixed.append(upper)
                    ranges.append(_describe(lower, f"{upper_op}{upper}"))
                    lower = None
            if lower is not None:  # introduced but never fixed
                ranges.append(_describe(lower, None))
    return ranges, fixed


def _describe(lower: str | None, upper: str | None) -> str:
    parts = []
    if lower and lower != "0":
        parts.append(f">={lower}")
    if upper:
        parts.append(upper)
    return ", ".join(parts) or "all versions"
