"""Tests for the reporters: JSON, CycloneDX SBOM, Markdown and terminal table."""

from __future__ import annotations

import json

import pytest
from rich.console import Console

from chainsentry.models import (
    Dependency,
    Ecosystem,
    Finding,
    PackageReport,
    ScanResult,
    Severity,
    Vulnerability,
)
from chainsentry.reporters import cyclonedx, json_report, markdown, table
from chainsentry.reporters.summary import summarise
from chainsentry.scoring import apply_scores


@pytest.fixture
def result() -> ScanResult:
    lodash = PackageReport(
        Dependency("lodash", "4.17.15", None, Ecosystem.NPM, "package-lock.json"),
        vulnerabilities=[
            Vulnerability(
                id="GHSA-35jh-r3h4-6jhm",
                aliases=["CVE-2021-23337"],
                summary="Command Injection in lodash",
                severity=Severity.HIGH,
                cvss_score=7.2,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                affected_ranges=["<4.17.21"],
                fixed_versions=["4.17.21"],
            )
        ],
    )
    scoped = PackageReport(
        Dependency("@babel/core", "7.24.0", None, Ecosystem.NPM, "package-lock.json", direct=False)
    )
    squat = PackageReport(
        Dependency("colourama", "0.1.6", None, Ecosystem.PYPI, "requirements.txt", dev=True),
        findings=[
            Finding(
                "typosquat",
                "TYPOSQUAT",
                Severity.MEDIUM,
                "looks like colorama",
                {"target": "colorama"},
            )
        ],
    )
    result = ScanResult(
        target="demo",
        packages=[lodash, scoped, squat],
        files=["package-lock.json", "requirements.txt"],
        warnings=["requirements.txt:5: --extra-index-url ... dependency confusion"],
        checks=["osv", "typosquat"],
        tool_version="0.1.0",
        scanned_at="2026-10-19T00:00:00+00:00",
    )
    apply_scores(result)
    return result


def test_summary(result):
    s = summarise(result)
    assert (s.packages, s.direct, s.vulnerabilities, s.vulnerable_packages) == (3, 2, 1, 1)
    assert s.vulnerabilities_by_severity == {"HIGH": 1}
    assert s.findings_by_code == {"TYPOSQUAT": 1}
    assert s.fixable_vulnerabilities == 1


class TestJson:
    def test_round_trips_through_json(self, result):
        data = json.loads(json_report.render(result))
        assert data["schema_version"] == json_report.SCHEMA_VERSION
        assert data["summary"]["project_score"] == result.project_score
        assert data["scan"]["checks"] == ["osv", "typosquat"]

    def test_packages_sorted_riskiest_first_with_details(self, result):
        packages = json_report.to_dict(result)["packages"]
        assert packages[0]["name"] == "lodash"
        assert packages[0]["purl"] == "pkg:npm/lodash@4.17.15"
        assert packages[0]["band"] == "HIGH"
        assert packages[0]["vulnerabilities"][0]["severity"] == "HIGH"
        assert packages[0]["score_breakdown"][0]["points"] == 50

    def test_write(self, result, tmp_path):
        path = json_report.write(result, tmp_path / "out" / "report.json")
        assert json.loads(path.read_text(encoding="utf-8"))["tool"]["name"] == "chainsentry"


class TestCycloneDx:
    def doc(self, result):
        return cyclonedx.to_dict(result, serial="urn:uuid:00000000-0000-0000-0000-000000000000")

    def test_required_top_level_fields(self, result):
        doc = self.doc(result)
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.5"
        assert doc["serialNumber"].startswith("urn:uuid:")
        assert doc["metadata"]["tools"]["components"][0]["name"] == "chainsentry"

    def test_components(self, result):
        components = {c["purl"]: c for c in self.doc(result)["components"]}
        babel = components["pkg:npm/%40babel/core@7.24.0"]
        assert (babel["group"], babel["name"], babel["version"]) == ("@babel", "core", "7.24.0")
        assert components["pkg:pypi/colourama@0.1.6"]["scope"] == "excluded"  # dev dependency
        assert all(c["bom-ref"] == c["purl"] for c in components.values())

    def test_direct_dependency_graph(self, result):
        deps = self.doc(result)["dependencies"][0]
        assert deps["ref"] == cyclonedx.ROOT_REF
        assert "pkg:npm/%40babel/core@7.24.0" not in deps["dependsOn"]  # transitive
        assert "pkg:npm/lodash@4.17.15" in deps["dependsOn"]

    def test_vulnerabilities_section(self, result):
        vuln = self.doc(result)["vulnerabilities"][0]
        assert vuln["id"] == "GHSA-35jh-r3h4-6jhm"
        assert vuln["affects"] == [{"ref": "pkg:npm/lodash@4.17.15"}]
        assert vuln["ratings"][0] == {
            "severity": "high",
            "score": 7.2,
            "method": "CVSSv31",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        }
        assert vuln["recommendation"] == "Upgrade to 4.17.21"
        assert vuln["references"][0]["id"] == "CVE-2021-23337"


class TestMarkdown:
    def test_has_marker_and_score(self, result):
        text = markdown.render(result)
        assert text.startswith(markdown.COMMENT_MARKER)
        assert f"**{result.project_score}/100**" in text
        assert "GHSA-35jh-r3h4-6jhm" in text

    def test_failure_banner(self, result):
        assert "Check failed" in markdown.render(result, failed_reasons=["too risky"])

    def test_no_risk_message(self):
        clean = ScanResult(target=".", packages=[], tool_version="0.1.0")
        assert "No risky dependencies" in markdown.render(clean)

    @pytest.mark.parametrize(
        ("text", "forbidden"),
        [
            ("a | b", " | "),  # would split the table cell
            ("<img src=x onerror=alert(1)>", "<img"),  # HTML injection
            ("ping @security-team", "@security"),  # unwanted @-mention
        ],
    )
    def test_md_escape(self, text, forbidden):
        assert forbidden not in markdown.md_escape(text)

    def test_md_code(self):
        assert markdown.md_code("a`b|c") == "`a'b\\|c`"


class TestTable:
    def render(self, result, **kwargs) -> str:
        console = Console(record=True, width=200, color_system=None)
        table.render(result, console, **kwargs)
        return console.export_text()

    def test_shows_score_and_packages(self, result):
        out = self.render(result)
        assert f"{result.project_score}/100" in out
        assert "lodash" in out and "colourama" in out
        assert "1 other package(s) have no known issues" in out

    def test_details_lists_finding_messages(self, result):
        assert "looks like colorama" in self.render(result, details=True)

    def test_untrusted_markup_is_escaped(self, result):
        result.packages[0].vulnerabilities[0].summary = "[bold red]FAKE[/] [link=http://x]y[/link]"
        out = self.render(result)
        assert "[bold red]FAKE[/]" in out  # printed literally, not interpreted
