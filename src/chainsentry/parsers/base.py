"""Shared building blocks for every parser.

Each concrete parser (requirements.txt, package.json, package-lock.json) is a
plain function ``parse_xxx(path, ...) -> ParseResult``.

Design decisions
----------------
* **Functions, not a class hierarchy.** Parsers hold no state between calls,
  so a ``Parser`` base class would add ceremony without adding behaviour
  (YAGNI). Dispatch on file name lives in ``discovery.py``.
* **Parsers never raise for a single bad line/entry.** One odd line should
  not hide the other 300 dependencies, so problems become ``warnings``.
  ``ParseError`` is raised only when the *whole file* is unusable
  (unreadable, too big, not JSON, wrong top-level type).
* **Parsers also report risk signals** they can see from the file alone
  (an unpinned version, a git URL instead of the registry, ...). Those are
  ``Finding`` objects, attached to the dependency they concern.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from chainsentry.config import MAX_MANIFEST_BYTES
from chainsentry.models import Dependency, Ecosystem, Finding, Severity

# ---------------------------------------------------------------------------
# Finding codes produced by parsers. They are constants (not bare strings
# typed in many places) so a typo is an import error, and scoring (Phase 5)
# can import the same names.
# ---------------------------------------------------------------------------

#: Version is a range / missing, so the exact installed version is unknown.
UNPINNED = "UNPINNED"
#: Package comes from a git repo, tarball URL, etc. instead of the registry.
NON_REGISTRY_SOURCE = "NON_REGISTRY_SOURCE"
#: npm alias: the name in the manifest differs from the real package installed.
NPM_ALIAS = "NPM_ALIAS"
#: Lockfile entry has no integrity hash, so tampering would go unnoticed.
MISSING_INTEGRITY = "MISSING_INTEGRITY"

DependencyKey = tuple[Ecosystem, str, str | None]


class ParseError(Exception):
    """The manifest as a whole could not be parsed."""

    def __init__(self, path: Path | str, reason: str) -> None:
        self.path = str(path)
        self.reason = reason
        super().__init__(f"{self.path}: {reason}")


@dataclass
class ParseResult:
    """Everything a parser (or a whole project scan) found.

    Dependencies are stored by ``Dependency.key`` so the same package version
    declared twice (e.g. in ``requirements.txt`` and an included
    ``base.txt``) is reported once.

    Attributes:
        findings: Risk signals, keyed by the dependency's ``key``.
        warnings: Human-readable notes about lines/entries that were skipped
            or settings that deserve attention, formatted ``file:line: text``.
        files: Manifest files that contributed to this result.
    """

    _deps: dict[DependencyKey, Dependency] = field(default_factory=dict)
    findings: dict[DependencyKey, list[Finding]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)

    @property
    def dependencies(self) -> list[Dependency]:
        """All unique dependencies, in the order they were first seen."""
        return list(self._deps.values())

    def add_dependency(self, dep: Dependency) -> Dependency:
        """Add ``dep``, merging it with an existing entry for the same package version.

        Merge rule when the same name@version is seen twice:
          * ``direct`` -> True if *either* copy is direct (the project asked for it).
          * ``dev``    -> True only if *both* are dev (if production needs it
            anywhere, it ships to production).

        Returns:
            The dependency actually stored (possibly the merged one).
        """
        existing = self._deps.get(dep.key)
        if existing is None:
            self._deps[dep.key] = dep
            return dep
        merged = replace(
            existing,
            direct=existing.direct or dep.direct,
            dev=existing.dev and dep.dev,
        )
        self._deps[dep.key] = merged
        return merged

    def add_finding(self, dep: Dependency, finding: Finding) -> None:
        """Attach ``finding`` to ``dep``; identical findings are stored once."""
        bucket = self.findings.setdefault(dep.key, [])
        if not any(f.code == finding.code and f.message == finding.message for f in bucket):
            bucket.append(finding)

    def findings_for(self, dep: Dependency) -> list[Finding]:
        """Findings attached to ``dep`` (empty list if none)."""
        return self.findings.get(dep.key, [])

    def warn(self, path: Path | str, message: str, line: int | None = None) -> None:
        """Record a non-fatal problem, prefixed with its location."""
        location = f"{path}:{line}" if line is not None else str(path)
        self._add_warning(f"{location}: {message}")

    def _add_warning(self, text: str) -> None:
        # The same file can be read twice (e.g. requirements.txt directly and
        # again via "-r" from requirements-dev.txt); report each warning once.
        if text not in self.warnings:
            self.warnings.append(text)

    def extend(self, other: ParseResult) -> None:
        """Merge another result (e.g. from a second manifest) into this one."""
        for dep in other.dependencies:
            stored = self.add_dependency(dep)
            for finding in other.findings_for(dep):
                self.add_finding(stored, finding)
        for warning in other.warnings:
            self._add_warning(warning)
        for f in other.files:
            if f not in self.files:
                self.files.append(f)


def parser_finding(code: str, severity: Severity, message: str, **details: Any) -> Finding:
    """Shorthand for a ``Finding`` whose ``check`` is ``"parser"``."""
    return Finding(check="parser", code=code, severity=severity, message=message, details=details)


def display_path(path: Path, root: Path | None) -> str:
    """Path shown in reports: relative to the scan root, with forward slashes.

    ``sub/requirements.txt`` reads better than
    ``D:\\work\\proj\\sub\\requirements.txt`` and is identical on every OS,
    which keeps JSON reports comparable between Windows and Linux CI.
    """
    if root is not None:
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            pass  # not under root - fall back to the path as given
    return path.as_posix()


def redact_url(url: str) -> str:
    """Remove credentials from a URL before it is shown or stored.

    SECURITY: private index URLs are often written as
    ``https://user:TOKEN@pypi.company.com/simple``. Reports end up in CI logs
    and PR comments, so the secret must never be echoed back.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if parts.username is None and parts.password is None:
        return url
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, f"***@{host}", parts.path, parts.query, parts.fragment))


def read_text(path: Path) -> str:
    """Read a manifest as text, safely.

    Raises:
        ParseError: if the file is missing, too large or not valid UTF-8.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ParseError(path, f"cannot read file ({exc.strerror})") from exc

    # SECURITY: check the size *before* reading so a huge file is never
    # loaded into memory.
    if size > MAX_MANIFEST_BYTES:
        raise ParseError(path, f"file is {size:,} bytes; limit is {MAX_MANIFEST_BYTES:,}")

    try:
        # "utf-8-sig" transparently drops the byte-order mark that some
        # Windows editors (Notepad, PowerShell's Out-File) put at the start.
        return path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ParseError(path, "file is not valid UTF-8 text") from exc
    except OSError as exc:
        raise ParseError(path, f"cannot read file ({exc.strerror})") from exc


def load_json_object(path: Path) -> dict[str, Any]:
    """Read ``path`` and parse it as a JSON object (``{...}``).

    SECURITY: ``json.loads`` only builds dicts/lists/strings/numbers - it can
    never execute code, unlike ``eval`` or ``pickle``. Manifests come from
    untrusted repositories, so this matters.

    Raises:
        ParseError: on invalid JSON or if the top level is not an object.
    """
    text = read_text(path)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError(path, f"invalid JSON at line {exc.lineno}, column {exc.colno}") from exc
    except RecursionError as exc:
        # SECURITY: "[[[[[...]]]]]" nested 100k deep exhausts the parser's
        # recursion budget. Turn that into a normal error instead of a crash.
        raise ParseError(path, "JSON nested too deeply") from exc
    if not isinstance(data, dict):
        raise ParseError(path, f"expected a JSON object at top level, got {type(data).__name__}")
    return data
