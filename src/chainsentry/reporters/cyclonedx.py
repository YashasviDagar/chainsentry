"""CycloneDX 1.5 JSON SBOM (Software Bill of Materials).

An SBOM is an inventory of every third-party component in a piece of
software - the "ingredients list". After Log4Shell, the US Executive Order
14028 (2021) made SBOMs a requirement for software sold to the US
government, and they are now common in procurement and audits.

CycloneDX (OWASP) and SPDX (Linux Foundation) are the two standard formats.
We produce CycloneDX because it also has a first-class ``vulnerabilities``
section, so one file carries both the inventory and the known issues.

Spec: https://cyclonedx.org/docs/1.5/json/

What we emit
------------
* ``metadata``    - when, which tool, and the project being described
* ``components``  - one ``library`` per dependency, identified by its purl
* ``dependencies``- the project -> direct dependencies edges
* ``vulnerabilities`` - OSV findings with CVSS ratings and fix advice

The document is written by hand (plain dicts -> JSON) rather than with the
``cyclonedx-python-lib`` package: it is short, and building it ourselves
shows exactly what the standard contains. Validate the output with the
official CLI if needed: ``cyclonedx validate --input-file sbom.cdx.json``.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from chainsentry.models import Ecosystem, PackageReport, ScanResult, Vulnerability

SPEC_VERSION = "1.5"
ROOT_REF = "project-root"


def to_dict(result: ScanResult, *, serial: str | None = None) -> dict[str, Any]:
    """Build the CycloneDX document for ``result``.

    Args:
        serial: Fixed serial number (tests use this for stable output); a
            random ``urn:uuid`` is generated otherwise, as the spec requires a
            unique serial per BOM.
    """
    project_name = Path(result.target).resolve().name or "project"
    components = [_component(p) for p in result.packages]
    direct_refs = [p.dependency.purl for p in result.packages if p.dependency.direct]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": result.scanned_at,
            "tools": {
                "components": [
                    {"type": "application", "name": "chainsentry", "version": result.tool_version}
                ]
            },
            "component": {"type": "application", "name": project_name, "bom-ref": ROOT_REF},
            "properties": [
                {"name": "chainsentry:project-score", "value": str(result.project_score)},
                {"name": "chainsentry:project-band", "value": result.project_band.value},
            ],
        },
        "components": components,
        "dependencies": [{"ref": ROOT_REF, "dependsOn": direct_refs}],
        "vulnerabilities": [
            _vulnerability(vuln, report)
            for report in result.packages
            for vuln in report.vulnerabilities
        ],
    }


def _component(report: PackageReport) -> dict[str, Any]:
    dep = report.dependency
    component: dict[str, Any] = {"type": "library", "bom-ref": dep.purl}
    if dep.ecosystem is Ecosystem.NPM and dep.name.startswith("@") and "/" in dep.name:
        # CycloneDX models an npm scope as the component's "group".
        group, name = dep.name.split("/", 1)
        component["group"] = group
        component["name"] = name
    else:
        component["name"] = dep.name
    if dep.version:
        component["version"] = dep.version
    component["purl"] = dep.purl
    # "required" = shipped/used at runtime; dev-only packages are "excluded".
    component["scope"] = "excluded" if dep.dev else "required"
    properties = [
        {"name": "chainsentry:risk-score", "value": str(report.score)},
        {"name": "chainsentry:risk-band", "value": report.band.value},
        {"name": "chainsentry:direct", "value": str(dep.direct).lower()},
        {"name": "chainsentry:source-file", "value": dep.source_file},
    ]
    properties += [{"name": "chainsentry:finding", "value": f.code} for f in report.findings]
    if report.resolved:
        properties.append({"name": "chainsentry:version-resolved", "value": "true"})
    component["properties"] = properties
    return component


def _vulnerability(vuln: Vulnerability, report: PackageReport) -> dict[str, Any]:
    purl = report.dependency.purl
    entry: dict[str, Any] = {
        # bom-ref must be unique; the same advisory can affect two components.
        "bom-ref": f"{vuln.id}@{purl}",
        "id": vuln.id,
        "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vuln.id}"},
        "description": vuln.summary,
        "affects": [{"ref": purl}],
    }
    if vuln.aliases:
        entry["references"] = [
            {"id": alias, "source": _alias_source(alias)} for alias in vuln.aliases
        ]
    rating: dict[str, Any] = {"severity": vuln.severity.value.lower()}
    if vuln.cvss_score is not None and vuln.cvss_vector:
        rating["score"] = vuln.cvss_score
        rating["method"] = "CVSSv31" if vuln.cvss_vector.startswith("CVSS:3.1") else "CVSSv3"
        rating["vector"] = vuln.cvss_vector
    entry["ratings"] = [rating]
    if vuln.fixed_versions:
        entry["recommendation"] = f"Upgrade to {' or '.join(vuln.fixed_versions)}"
    if vuln.published:
        entry["published"] = vuln.published
    return entry


def _alias_source(alias: str) -> dict[str, str]:
    if alias.startswith("CVE-"):
        return {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{alias}"}
    if alias.startswith("GHSA-"):
        return {"name": "GitHub", "url": f"https://github.com/advisories/{alias}"}
    return {"name": "OSV", "url": f"https://osv.dev/vulnerability/{alias}"}


def render(result: ScanResult) -> str:
    return json.dumps(to_dict(result), indent=2, ensure_ascii=False) + "\n"


def write(result: ScanResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(result), encoding="utf-8")
    return path
