"""Tests for the PR-comment integration (github.py) with the GitHub API mocked."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from chainsentry import github
from chainsentry.cli import EXIT_OK, main
from chainsentry.reporters.markdown import COMMENT_MARKER

API = "https://api.github.com"
COMMENTS = f"{API}/repos/octo/app/issues/7/comments"
CTX = github.PullRequestContext(token="t0ken", repository="octo/app", number=7)


def comment(cid: int, login: str, body: str) -> dict:
    return {"id": cid, "user": {"login": login}, "body": body}


@respx.mock
def test_creates_comment_when_none_exists():
    respx.get(COMMENTS).mock(return_value=httpx.Response(200, json=[]))
    create = respx.post(COMMENTS).mock(return_value=httpx.Response(201, json={"id": 1}))
    assert github.upsert_comment(CTX, f"{COMMENT_MARKER}\nreport") == "created"
    request = create.calls[0].request
    assert request.headers["Authorization"] == "Bearer t0ken"
    assert json.loads(request.content)["body"].startswith(COMMENT_MARKER)


@respx.mock
def test_updates_own_previous_comment():
    respx.get(COMMENTS).mock(
        return_value=httpx.Response(
            200, json=[comment(5, "github-actions[bot]", f"{COMMENT_MARKER} old report")]
        )
    )
    update = respx.patch(f"{API}/repos/octo/app/issues/comments/5").mock(
        return_value=httpx.Response(200, json={})
    )
    assert github.upsert_comment(CTX, "new report") == "updated"
    assert update.called


@respx.mock
def test_never_edits_a_human_comment_containing_the_marker():
    # SECURITY: anyone can paste the marker; only the bot's comment is ours.
    respx.get(COMMENTS).mock(
        return_value=httpx.Response(200, json=[comment(9, "mallory", f"{COMMENT_MARKER} hi")])
    )
    create = respx.post(COMMENTS).mock(return_value=httpx.Response(201, json={}))
    assert github.upsert_comment(CTX, "report") == "created"
    assert create.called


@respx.mock
def test_follows_pagination():
    page1 = [comment(i, "someone", "chatter") for i in range(100)]
    page2 = [comment(500, "github-actions[bot]", COMMENT_MARKER)]
    respx.get(COMMENTS, params={"page": "1"}).mock(return_value=httpx.Response(200, json=page1))
    respx.get(COMMENTS, params={"page": "2"}).mock(return_value=httpx.Response(200, json=page2))
    respx.patch(f"{API}/repos/octo/app/issues/comments/500").mock(return_value=httpx.Response(200))
    assert github.upsert_comment(CTX, "report") == "updated"


@respx.mock
def test_long_reports_are_truncated():
    respx.get(COMMENTS).mock(return_value=httpx.Response(200, json=[]))
    create = respx.post(COMMENTS).mock(return_value=httpx.Response(201))
    github.upsert_comment(CTX, COMMENT_MARKER + "x" * 100_000)
    assert len(json.loads(create.calls[0].request.content)["body"]) < 66_000


@respx.mock
def test_forbidden_gives_helpful_error():
    respx.get(COMMENTS).mock(return_value=httpx.Response(403))
    with pytest.raises(github.GitHubError, match="read-only token"):
        github.upsert_comment(CTX, "report")


class TestContextFromEnv:
    def test_reads_pull_request_number(self, tmp_path):
        event = tmp_path / "event.json"
        event.write_text(json.dumps({"pull_request": {"number": 42}}), encoding="utf-8")
        ctx = github.context_from_env(
            {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "o/r", "GITHUB_EVENT_PATH": str(event)}
        )
        assert (ctx.repository, ctx.number, ctx.api_url) == ("o/r", 42, API)

    def test_not_a_pull_request(self, tmp_path):
        event = tmp_path / "event.json"
        event.write_text(json.dumps({"push": {}}), encoding="utf-8")
        env = {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "o/r", "GITHUB_EVENT_PATH": str(event)}
        with pytest.raises(github.GitHubError, match="not for a pull request"):
            github.context_from_env(env)

    def test_missing_variables(self):
        with pytest.raises(github.GitHubError, match="must be set"):
            github.context_from_env({})


def test_cli_command_never_fails_the_build(tmp_path, monkeypatch, capsys):
    # Outside Actions (no env vars) the command warns and still exits 0.
    for var in ("GITHUB_TOKEN", "GITHUB_REPOSITORY", "GITHUB_EVENT_PATH"):
        monkeypatch.delenv(var, raising=False)
    report = tmp_path / "report.md"
    report.write_text("hi", encoding="utf-8")
    assert main(["github-comment", "--report", str(report)]) == EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("::warning")
    assert "t0ken" not in out
