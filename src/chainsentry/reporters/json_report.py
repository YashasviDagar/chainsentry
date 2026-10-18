"""Machine-readable JSON report.

This is ChainSentry's stable output format: the dashboard (Phase 7), the
batch scanner and the GitHub Action all read it. ``schema_version`` is bumped
whenever a field is renamed or removed, so consumers can detect changes.

Shape (abridged)::

    {
      "schema_version": "1.0",
      "tool": {"name": "chainsentry", "version": "0.1.0"},
      "scan": {"target", "scanned_at", "duration_seconds", "files", "checks",
               "errors", "warnings"},
      "summary": {"project_score", "project_band", "packages", "vulnerabilities",
                  "vulnerabilities_by_severity", "packages_by_band", ...},
      "packages": [{"name", "version", "ecosystem", "purl", "direct", "dev",
                    "score", "band", "score_breakdown", "vulnerabilities",
                    "findings", ...}]
    }
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from chainsentry.models import PackageReport, ScanResult
from chainsentry.reporters.summary import summarise

SCHEMA_VERSION = "1.0"


def to_dict(result: ScanResult) -> dict[str, Any]:
    """Convert a ScanResult into plain JSON-compatible data."""
    summary = asdict(summarise(result))
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "chainsentry", "version": result.tool_version},
        "scan": {
            "target": result.target,
            "scanned_at": result.scanned_at,
            "duration_seconds": result.duration_seconds,
            "files": result.files,
            "checks": result.checks,
            "errors": result.errors,
            "warnings": result.warnings,
        },
        "summary": {
            "project_score": result.project_score,
            "project_band": result.project_band.value,
            **summary,
        },
        # Riskiest first: the order a human (or the dashboard) wants to read.
        "packages": [
            _package(p)
            for p in sorted(result.packages, key=lambda p: (-p.score, p.dependency.name))
        ],
    }


def _package(report: PackageReport) -> dict[str, Any]:
    dep = report.dependency
    return {
        "name": dep.name,
        "version": dep.version,
        "spec": dep.spec,
        "ecosystem": dep.ecosystem.value,
        "purl": dep.purl,
        "direct": dep.direct,
        "dev": dep.dev,
        "source_file": dep.source_file,
        "resolved": report.resolved,
        "score": report.score,
        "band": report.band.value,
        "score_breakdown": [asdict(c) for c in report.score_breakdown],
        # asdict() turns enums into themselves; StrEnum values serialise as
        # plain strings via json.dumps, so no custom encoder is needed.
        "vulnerabilities": [asdict(v) for v in report.vulnerabilities],
        "findings": [asdict(f) for f in report.findings],
    }


def render(result: ScanResult) -> str:
    """The report as pretty-printed JSON text."""
    return json.dumps(to_dict(result), indent=2, ensure_ascii=False) + "\n"


def write(result: ScanResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(result), encoding="utf-8")
    return path
