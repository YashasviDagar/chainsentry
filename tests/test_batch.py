"""Tests for batch mode (batch.py): GitHub fetching, resumable runs and aggregation."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from chainsentry.batch import (
    GITHUB_API,
    BatchError,
    GitHubReader,
    aggregate,
    load_reports,
    report_path,
    run_batch,
    write_outputs,
)
from chainsentry.scanner import ScanOptions

OFFLINE = ScanOptions(offline=True, use_cache=False)
LOCKFILE = {
    "lockfileVersion": 3,
    "packages": {
        "": {"dependencies": {"crossenv": "1"}},
        "node_modules/crossenv": {"version": "6.1.1"},
    },
}


def listing(*names: str, size: int = 10) -> list[dict]:
    return [
        {"name": n, "type": "file", "size": size, "download_url": f"https://raw.example/{n}"}
        for n in names
    ]


@pytest.fixture
def reader():
    r = GitHubReader(token=None, sleep=lambda _s: None)
    yield r
    r.close()


@respx.mock
def test_downloads_only_supported_manifest_names(reader, tmp_path):
    respx.get(f"{GITHUB_API}/repos/o/r/contents/").mock(
        return_value=httpx.Response(
            200,
            json=listing("package-lock.json", "README.md", "requirements-dev.txt", "../evil.txt")
            + [{"name": "src", "type": "dir"}],
        )
    )
    respx.get("https://raw.example/package-lock.json").mock(
        return_value=httpx.Response(200, content=b"{}")
    )
    respx.get("https://raw.example/requirements-dev.txt").mock(
        return_value=httpx.Response(200, content=b"")
    )
    saved = reader.download_manifests("o/r", tmp_path)
    assert sorted(saved) == ["package-lock.json", "requirements-dev.txt"]
    assert not (tmp_path.parent / "evil.txt").exists()


@respx.mock
def test_oversized_files_are_skipped(reader, tmp_path):
    respx.get(f"{GITHUB_API}/repos/o/r/contents/").mock(
        return_value=httpx.Response(200, json=listing("package.json", size=10**9))
    )
    assert reader.download_manifests("o/r", tmp_path) == []


@respx.mock
def test_rate_limit_waits_then_retries():
    waits: list[float] = []
    reader = GitHubReader(sleep=waits.append)
    url = f"{GITHUB_API}/repos/o/r/contents/"
    import time

    respx.get(url).mock(
        side_effect=[
            httpx.Response(
                403,
                headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(time.time() + 5)},
            ),
            httpx.Response(200, json=[]),
        ]
    )
    assert reader.get(url).status_code == 200
    assert len(waits) == 1


@respx.mock
def test_long_rate_limit_wait_aborts(reader):
    import time

    url = f"{GITHUB_API}/repos/o/r/contents/"
    respx.get(url).mock(
        return_value=httpx.Response(
            403,
            headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(time.time() + 7200)},
        )
    )
    with pytest.raises(BatchError, match="rate limit"):
        reader.get(url)


@respx.mock
def test_search_paginates(reader):
    respx.get(f"{GITHUB_API}/search/repositories").mock(
        return_value=httpx.Response(
            200, json={"items": [{"full_name": "a/b"}, {"full_name": "c/d"}]}
        )
    )
    assert reader.search("language:python", limit=1) == ["a/b"]


@respx.mock
def test_run_batch_scans_saves_and_resumes(reader, tmp_path, client):
    respx.get(f"{GITHUB_API}/repos/o/app/contents/").mock(
        return_value=httpx.Response(200, json=listing("package-lock.json"))
    )
    respx.get("https://raw.example/package-lock.json").mock(
        return_value=httpx.Response(200, json=LOCKFILE)
    )
    respx.get(f"{GITHUB_API}/repos/o/empty/contents/").mock(
        return_value=httpx.Response(200, json=listing("README.md"))
    )
    respx.get(f"{GITHUB_API}/repos/o/gone/contents/").mock(return_value=httpx.Response(404))

    repos = ["o/app", "o/empty", "o/gone", "not a repo"]
    outcomes = run_batch(
        repos, tmp_path, reader=reader, options=OFFLINE, client=client, log=lambda _m: None
    )
    assert [o.status for o in outcomes] == ["scanned", "no-manifests", "error", "error"]

    saved = json.loads(report_path(tmp_path, "o/app").read_text(encoding="utf-8"))
    assert saved["scan"]["target"] == "o/app"
    assert saved["packages"][0]["findings"][0]["code"] == "TYPOSQUAT"

    # Second run: finished repos are skipped, no new requests needed for them.
    again = run_batch(
        ["o/app", "o/empty"],
        tmp_path,
        reader=reader,
        options=OFFLINE,
        client=client,
        log=lambda _m: None,
    )
    assert [o.status for o in again] == ["skipped", "skipped"]


def fake_report(repo: str, *, vulns: list[str], codes: list[str], unchecked: int = 0) -> dict:
    return {
        "scan": {"target": repo, "files": ["package-lock.json"]},
        "summary": {
            "project_score": 80 if vulns else 0,
            "project_band": "CRITICAL" if vulns else "LOW",
            "packages": 2,
            "direct": 1,
            "unchecked": unchecked,
            "vulnerable_packages": 1 if vulns else 0,
            "vulnerabilities": len(vulns),
        },
        "packages": [
            {
                "ecosystem": "npm",
                "name": "lodash",
                "version": "4.17.15",
                "vulnerabilities": [
                    {"id": f"GHSA-{i}", "severity": s} for i, s in enumerate(vulns)
                ],
                "findings": [{"code": c} for c in codes],
            },
            {
                "ecosystem": "npm",
                "name": "ok",
                "version": "1.0.0",
                "vulnerabilities": [],
                "findings": [],
            },
        ],
    }


def test_aggregate_statistics():
    reports = [
        fake_report("a/1", vulns=["CRITICAL", "HIGH"], codes=["INSTALL_SCRIPT"]),
        fake_report("a/2", vulns=["HIGH"], codes=[]),
        fake_report("a/3", vulns=[], codes=["TYPOSQUAT"], unchecked=2),
        fake_report("a/4", vulns=[], codes=[]),
    ]
    stats = aggregate(reports, repos_without_manifests=3)
    assert stats["repositories_scanned"] == 4
    assert stats["repositories_without_supported_manifests"] == 3
    assert stats["total_dependencies"] == 8
    assert stats["unique_package_versions"] == 2
    assert stats["unchecked_dependencies"] == 2
    assert stats["total_vulnerabilities"] == 3
    assert stats["vulnerabilities_by_severity"] == {"HIGH": 2, "CRITICAL": 1}
    assert stats["repos_with_any_vulnerability_pct"] == 50.0
    assert stats["repos_with_critical_pct"] == 25.0
    assert stats["repos_with_install_scripts_pct"] == 25.0
    assert stats["repos_with_typosquat_suspects"] == 1
    assert stats["most_common_vulnerable_packages"][0] == ("npm:lodash", 2)


def test_aggregate_empty_dataset():
    stats = aggregate([])
    assert stats["repositories_scanned"] == 0 and stats["repos_with_any_vulnerability_pct"] == 0.0


def test_outputs_round_trip(tmp_path):
    (tmp_path / "repos").mkdir()
    report_path(tmp_path, "a/1").write_text(json.dumps(fake_report("a/1", vulns=["LOW"], codes=[])))
    report_path(tmp_path, "a/2").write_text(json.dumps({"repo": "a/2", "status": "no-manifests"}))
    reports, empty = load_reports(tmp_path)
    assert (len(reports), empty) == (1, 1)
    paths = write_outputs(aggregate(reports, empty), tmp_path)
    assert {p.name for p in paths} == {"stats.json", "stats.csv", "SUMMARY.md"}
    assert "Repositories scanned: **1**" in (tmp_path / "SUMMARY.md").read_text(encoding="utf-8")
    assert "a/1" in (tmp_path / "stats.csv").read_text(encoding="utf-8")
