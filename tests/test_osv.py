"""Tests for the OSV.dev check (checks/osv.py), with the API mocked by respx."""

from __future__ import annotations

import httpx
import respx

from chainsentry import config
from chainsentry.checks.osv import OsvCheck, parse_record
from chainsentry.models import Dependency, Ecosystem, PackageReport, Severity
from chainsentry.net.cache import Cache
from chainsentry.net.client import HttpClient

BATCH = f"{config.OSV_API_URL}/querybatch"


def report(name: str, version: str | None, eco: Ecosystem = Ecosystem.NPM) -> PackageReport:
    return PackageReport(Dependency(name, version, None, eco, "x"))


def ghsa_record(vuln_id: str, name: str, eco: str = "npm", **extra) -> dict:
    """A minimal but realistic OSV record."""
    return {
        "id": vuln_id,
        "summary": f"Problem in {name}",
        "aliases": ["CVE-2021-23337"],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {
                "package": {"name": name, "ecosystem": eco},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}
                ],
            }
        ],
        "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/x"}],
        **extra,
    }


@respx.mock
def test_vulnerabilities_are_attached(client):
    respx.post(BATCH).mock(
        return_value=httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-1"}]}, {}]})
    )
    respx.get(f"{config.OSV_API_URL}/vulns/GHSA-1").mock(
        return_value=httpx.Response(200, json=ghsa_record("GHSA-1", "lodash"))
    )
    lodash, safe = report("lodash", "4.17.15"), report("left-pad", "1.3.0")

    assert OsvCheck(client).run([lodash, safe]) == []

    vuln = lodash.vulnerabilities[0]
    assert vuln.id == "GHSA-1"
    assert vuln.cve_ids == ["CVE-2021-23337"]
    assert vuln.cvss_score == 9.8 and vuln.severity is Severity.CRITICAL
    assert vuln.affected_ranges == ["<4.17.21"]
    assert vuln.fixed_versions == ["4.17.21"]
    assert safe.vulnerabilities == []


@respx.mock
def test_batch_payload_uses_osv_ecosystem_names(client):
    route = respx.post(BATCH).mock(return_value=httpx.Response(200, json={"results": [{}]}))
    OsvCheck(client).run([report("django", "3.2.0", Ecosystem.PYPI)])
    sent = route.calls[0].request.content
    assert b'"ecosystem":"PyPI"' in sent.replace(b" ", b"")


def test_unpinned_packages_are_not_queried(client):
    # No respx mock active: any HTTP request would fail the test.
    unpinned = report("lodash", None)
    assert OsvCheck(client).run([unpinned]) == []


@respx.mock
def test_aliased_duplicates_are_merged(client):
    respx.post(BATCH).mock(
        return_value=httpx.Response(
            200, json={"results": [{"vulns": [{"id": "PYSEC-1"}, {"id": "GHSA-2"}]}]}
        )
    )
    pysec = ghsa_record("PYSEC-1", "django", "PyPI", aliases=["CVE-2021-23337", "GHSA-2"])
    del pysec["severity"]
    respx.get(f"{config.OSV_API_URL}/vulns/PYSEC-1").mock(
        return_value=httpx.Response(200, json=pysec)
    )
    respx.get(f"{config.OSV_API_URL}/vulns/GHSA-2").mock(
        return_value=httpx.Response(200, json=ghsa_record("GHSA-2", "django", "PyPI"))
    )
    django = report("django", "3.2.0", Ecosystem.PYPI)
    OsvCheck(client).run([django])
    # Same CVE reported twice -> kept once, preferring the GHSA (it has CVSS).
    assert [v.id for v in django.vulnerabilities] == ["GHSA-2"]


@respx.mock
def test_pagination_is_followed(client):
    respx.post(BATCH).mock(
        return_value=httpx.Response(
            200, json={"results": [{"vulns": [{"id": "GHSA-1"}], "next_page_token": "t"}]}
        )
    )
    respx.post(f"{config.OSV_API_URL}/query").mock(
        return_value=httpx.Response(200, json={"vulns": [{"id": "GHSA-9"}]})
    )
    for vid in ("GHSA-1", "GHSA-9"):
        record = ghsa_record(vid, "lodash", aliases=[f"CVE-{vid}"])
        respx.get(f"{config.OSV_API_URL}/vulns/{vid}").mock(
            return_value=httpx.Response(200, json=record)
        )
    lodash = report("lodash", "4.17.15")
    OsvCheck(client).run([lodash])
    assert {v.id for v in lodash.vulnerabilities} == {"GHSA-1", "GHSA-9"}


@respx.mock
def test_api_failure_is_reported_not_raised(client):
    respx.post(BATCH).mock(return_value=httpx.Response(500))
    errors = OsvCheck(client).run([report("lodash", "4.17.15")])
    assert errors and "osv" in errors[0]


@respx.mock
def test_query_results_are_cached_per_package(tmp_path):
    client = HttpClient(Cache(tmp_path / "c.sqlite3"))
    route = respx.post(BATCH).mock(return_value=httpx.Response(200, json={"results": [{}]}))
    OsvCheck(client).run([report("lodash", "4.17.21")])
    OsvCheck(client).run([report("lodash", "4.17.21")])
    assert route.call_count == 1


class TestParseRecord:
    dep = Dependency("lodash", "4.17.15", None, Ecosystem.NPM, "x")

    def test_falls_back_to_advisory_label_without_cvss_v3(self):
        record = ghsa_record("GHSA-1", "lodash", database_specific={"severity": "MODERATE"})
        record["severity"] = [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/..."}]
        vuln = parse_record(record, self.dep)
        assert vuln.cvss_score is None
        assert vuln.severity is Severity.MEDIUM

    def test_unknown_severity(self):
        record = ghsa_record("GHSA-1", "lodash")
        del record["severity"]
        assert parse_record(record, self.dep).severity is Severity.UNKNOWN

    def test_malicious_package_is_critical(self):
        record = ghsa_record("MAL-2024-1", "lodash")
        del record["severity"]
        vuln = parse_record(record, self.dep)
        assert vuln.is_malicious and vuln.severity is Severity.CRITICAL

    def test_last_affected_and_open_ranges(self):
        record = ghsa_record("GHSA-1", "lodash")
        record["affected"][0]["ranges"] = [
            {"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"last_affected": "2.3.0"}]},
            {"type": "SEMVER", "events": [{"introduced": "3.0.0"}]},
        ]
        assert parse_record(record, self.dep).affected_ranges == [">=2.0.0, <=2.3.0", ">=3.0.0"]

    def test_ranges_of_other_packages_are_ignored(self):
        record = ghsa_record("GHSA-1", "underscore")
        assert parse_record(record, self.dep).affected_ranges == []

    def test_pypi_names_compared_normalised(self):
        dep = Dependency("python-dateutil", "2.8.0", None, Ecosystem.PYPI, "x")
        record = ghsa_record("GHSA-1", "Python_DateUtil", "PyPI")
        assert parse_record(record, dep).fixed_versions == ["4.17.21"]
