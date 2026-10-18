"""Post (or update) ChainSentry's pull-request comment through the GitHub REST API.

Used by the GitHub Action via ``chainsentry github-comment``. Behaviour:

* Finds an existing comment that contains the hidden marker
  ``<!-- chainsentry-report -->`` **and was written by the bot account**,
  then edits it. Otherwise it creates a new comment. Re-running the
  workflow on every push therefore keeps *one* up-to-date comment instead of
  spamming the PR.
* Reads its inputs from the standard Actions environment
  (``GITHUB_TOKEN``, ``GITHUB_REPOSITORY``, ``GITHUB_EVENT_PATH``,
  ``GITHUB_API_URL``).

Security notes
--------------
* SECURITY: only comments authored by ``bot_login`` are edited. Anyone can
  paste the marker into their own comment; without the author check we
  would try to overwrite a human's comment.
* SECURITY: the token is sent only in the ``Authorization`` header and is
  never printed. Error messages include the HTTP status, not the request.
* On pull requests from forks GitHub gives the workflow a read-only token,
  so posting fails with 403. That is expected and reported as a warning,
  not a failed build. The job summary still shows the report.

API reference: https://docs.github.com/en/rest/issues/comments
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

import httpx

from chainsentry import config
from chainsentry.reporters.markdown import COMMENT_MARKER

#: GitHub rejects comment bodies longer than 65,536 characters.
MAX_COMMENT_CHARS = 65_000
DEFAULT_BOT_LOGIN = "github-actions[bot]"


class GitHubError(Exception):
    """The GitHub API call failed."""


@dataclass(frozen=True)
class PullRequestContext:
    token: str
    repository: str  # "owner/name"
    number: int
    api_url: str = "https://api.github.com"


def context_from_env(env: dict[str, str] | None = None) -> PullRequestContext:
    """Build the context from GitHub Actions environment variables.

    Raises:
        GitHubError: if not running for a pull request or a variable is missing.
    """
    env = dict(os.environ if env is None else env)
    token = env.get("GITHUB_TOKEN", "")
    repository = env.get("GITHUB_REPOSITORY", "")
    event_path = env.get("GITHUB_EVENT_PATH", "")
    if not token or not repository or not event_path:
        raise GitHubError("GITHUB_TOKEN, GITHUB_REPOSITORY and GITHUB_EVENT_PATH must be set")
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GitHubError(f"cannot read the event payload ({exc.__class__.__name__})") from exc
    number = (event.get("pull_request") or {}).get("number")
    if not isinstance(number, int):
        raise GitHubError("this workflow run is not for a pull request")
    return PullRequestContext(
        token=token,
        repository=repository,
        number=number,
        api_url=env.get("GITHUB_API_URL", "https://api.github.com").rstrip("/"),
    )


def upsert_comment(
    ctx: PullRequestContext,
    body: str,
    *,
    bot_login: str = DEFAULT_BOT_LOGIN,
    transport: httpx.BaseTransport | None = None,
) -> str:
    """Create or update the ChainSentry comment. Returns ``"created"`` or ``"updated"``.

    Raises:
        GitHubError: on any non-success response.
    """
    if COMMENT_MARKER not in body:
        body = f"{COMMENT_MARKER}\n{body}"
    if len(body) > MAX_COMMENT_CHARS:
        body = body[:MAX_COMMENT_CHARS] + "\n\n_…report truncated; see the workflow artifacts._\n"

    headers = {
        "Authorization": f"Bearer {ctx.token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": config.USER_AGENT,
    }
    base = f"{ctx.api_url}/repos/{ctx.repository}/issues"
    with httpx.Client(headers=headers, timeout=30, transport=transport) as client:
        existing = _find_existing(client, f"{base}/{ctx.number}/comments", bot_login)
        if existing is not None:
            _check(
                client.patch(f"{base}/comments/{existing}", json={"body": body}), "update comment"
            )
            return "updated"
        _check(client.post(f"{base}/{ctx.number}/comments", json={"body": body}), "create comment")
        return "created"


def _find_existing(client: httpx.Client, url: str, bot_login: str) -> int | None:
    """Return the id of our previous comment, following pagination (100 per page)."""
    page = 1
    while True:
        response = client.get(url, params={"per_page": 100, "page": page})
        _check(response, "list comments")
        comments = response.json()
        for comment in comments:
            author = (comment.get("user") or {}).get("login")
            if author == bot_login and COMMENT_MARKER in (comment.get("body") or ""):
                return int(comment["id"])
        if len(comments) < 100 or page >= 50:  # page cap: never loop forever
            return None
        page += 1


def _check(response: httpx.Response, action: str) -> None:
    if response.status_code >= 400:
        hint = ""
        if response.status_code in (403, 404):
            hint = " (fork PRs get a read-only token; check 'permissions: pull-requests: write')"
        raise GitHubError(f"GitHub API: {action} failed with HTTP {response.status_code}{hint}")
