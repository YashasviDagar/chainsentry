"""Parser for pip requirements files (``requirements.txt`` and friends).

Format reference: https://pip.pypa.io/en/stable/reference/requirements-file-format/

A requirements file is *not* just "one package per line". This parser handles:

* comments (``# ...``) and blank lines
* line continuations (a trailing ``\\``)
* PEP 508 requirement lines: extras ``pkg[security]``, environment markers
  ``; python_version < "3.12"``, direct references ``pkg @ https://...``
* per-requirement options such as ``--hash=sha256:...``
* global options: ``-r`` / ``-c`` includes, ``-e`` editables, index options

Design decisions
----------------
* **``packaging.requirements.Requirement`` does the hard parsing.** It is the
  same PEP 508 implementation pip uses; writing our own regex would get
  extras/markers/URLs subtly wrong.
* **Only ``==X`` (without ``*``) and ``===X`` count as exact pins.**
  ``>=2.0`` could install 2.0 today and 9.0 tomorrow, so we cannot say
  which version - and therefore which CVEs - you actually have.
* **Names are normalised per PEP 503** (``Flask_Login`` -> ``flask-login``)
  because PyPI and OSV treat those as the same project.
* **Index options are security-relevant, so they produce warnings**:
  ``--extra-index-url`` is the classic *dependency confusion* setup.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from chainsentry.config import MAX_REQUIREMENTS_INCLUDE_DEPTH
from chainsentry.models import Dependency, Ecosystem, Severity
from chainsentry.parsers.base import (
    NON_REGISTRY_SOURCE,
    UNPINNED,
    ParseResult,
    display_path,
    parser_finding,
    read_text,
    redact_url,
)

# pip treats '#' as a comment only at line start or after whitespace, so
# "pkg @ https://host/x.whl#sha256=..." keeps its URL fragment.
_COMMENT_RE = re.compile(r"(^|\s+)#.*$")

# File-name words that mark a requirements file as development-only,
# e.g. requirements-dev.txt, dev-requirements.txt, requirements/test.txt.
_DEV_TOKENS = frozenset({"dev", "develop", "test", "tests", "testing", "lint", "docs", "doc", "ci"})

# Hosts that make up the official Python Package Index.
_PYPI_HOSTS = frozenset({"pypi.org", "pypi.python.org", "files.pythonhosted.org"})

# Global options that only tune *how* pip installs and carry no risk signal.
_HARMLESS_OPTIONS = frozenset(
    {
        "--pre",
        "--prefer-binary",
        "--require-hashes",
        "--only-binary",
        "--no-binary",
        "--use-feature",
        "--progress-bar",
        "--no-index",
    }
)


def parse_requirements(path: Path, *, root: Path | None = None) -> ParseResult:
    """Parse a requirements file and everything it includes with ``-r``.

    Args:
        path: The requirements file.
        root: Project directory. Included files must live inside it
            (defaults to the file's own directory).

    Returns:
        A ``ParseResult`` with one ``Dependency`` per requirement.

    Raises:
        ParseError: if the top-level file cannot be read.
    """
    path = path.resolve()
    root = (root or path.parent).resolve()
    result = ParseResult()
    _parse_file(path, root, result, visited=set(), depth=0, dev=is_dev_requirements_file(path))
    return result


def _parse_file(
    path: Path,
    root: Path,
    result: ParseResult,
    *,
    visited: set[Path],
    depth: int,
    dev: bool,
) -> None:
    """Parse one file into ``result``, recursing into ``-r`` includes."""
    visited.add(path)
    shown = display_path(path, root)
    result.files.append(shown)
    text = read_text(path)

    for lineno, line in _logical_lines(text):
        line = _COMMENT_RE.sub("", line).strip()
        if not line:
            continue

        if line.startswith("-"):
            _handle_option(line, lineno, path, shown, root, result, visited, depth, dev)
        else:
            _handle_requirement(line, lineno, shown, result, dev)


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash-continued lines, keeping the *starting* line number.

    ``"requests==2.31.0 \\\\\\n    --hash=sha256:abc"`` becomes one logical line,
    exactly as pip does it, so per-requirement options stay attached.
    """
    lines: list[tuple[int, str]] = []
    buffer: list[str] = []
    start = 0
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if not buffer:
            start = lineno
        if raw.endswith("\\"):
            buffer.append(raw[:-1])
            continue
        buffer.append(raw)
        lines.append((start, "".join(buffer)))
        buffer = []
    if buffer:  # file ended with a dangling backslash - keep what we have
        lines.append((start, "".join(buffer)))
    return lines


def _split_option(line: str) -> tuple[str, str]:
    """Split an option line into (option, value).

    Handles ``-r base.txt``, ``-rbase.txt`` and ``--requirement=base.txt``.
    """
    if line.startswith("--"):
        match = re.match(r"(--[\w-]+)\s*=?\s*(.*)", line)
        if match:
            return match.group(1), match.group(2).strip()
        return line, ""
    # Short options may be glued to their value: "-rbase.txt".
    return line[:2], line[2:].lstrip(" =").strip()


def _handle_option(
    line: str,
    lineno: int,
    path: Path,
    shown: str,
    root: Path,
    result: ParseResult,
    visited: set[Path],
    depth: int,
    dev: bool,
) -> None:
    """React to a global option line (anything starting with ``-``)."""
    option, value = _split_option(line)

    if option in ("-r", "--requirement"):
        _include(value, lineno, path, shown, root, result, visited, depth, dev)
    elif option in ("-c", "--constraint"):
        # LIMITATION: constraint files pin versions without adding packages.
        # Applying them correctly needs pip's resolver, so they are ignored.
        result.warn(shown, f"constraints file '{value}' ignored (not supported)", lineno)
    elif option in ("-e", "--editable"):
        result.warn(
            shown,
            f"editable requirement '{redact_url(value)}' skipped: local/VCS code is not on an "
            "index and cannot be checked",
            lineno,
        )
    elif option in ("-i", "--index-url"):
        if not _is_pypi(value):
            result.warn(
                shown,
                f"custom package index {redact_url(value)}: packages are not fetched from PyPI",
                lineno,
            )
    elif option == "--extra-index-url":
        # SECURITY: with an extra index pip picks the *highest version from
        # any index*. If an internal package name is not also registered on
        # public PyPI, an attacker can publish it there with a huge version
        # number and pip will install theirs (dependency confusion, 2021).
        result.warn(
            shown,
            f"--extra-index-url {redact_url(value)} enables dependency confusion: pip will "
            "install whichever index offers the highest version",
            lineno,
        )
    elif option == "--trusted-host":
        # SECURITY: disables TLS certificate checks for that host -> MITM risk.
        result.warn(shown, f"--trusted-host {value} disables TLS verification", lineno)
    elif option in ("-f", "--find-links"):
        result.warn(
            shown,
            f"--find-links {redact_url(value)}: packages may come from outside any index",
            lineno,
        )
    elif option not in _HARMLESS_OPTIONS:
        result.warn(shown, f"unrecognised option '{option}' ignored", lineno)


def _include(
    target: str,
    lineno: int,
    path: Path,
    shown: str,
    root: Path,
    result: ParseResult,
    visited: set[Path],
    depth: int,
    dev: bool,
) -> None:
    """Follow ``-r other.txt`` safely."""
    if not target:
        result.warn(shown, "'-r' without a file name", lineno)
        return
    if "://" in target:
        # SECURITY: never download and parse a remote file on the user's behalf.
        result.warn(shown, f"remote include '{redact_url(target)}' not followed", lineno)
        return

    included = (path.parent / target).resolve()

    # SECURITY: a malicious repo could write "-r ../../../../etc/passwd" or
    # "-r C:\\Users\\you\\secrets.txt". We only read files inside the project.
    if not included.is_relative_to(root):
        result.warn(shown, f"include '{target}' points outside the project; not followed", lineno)
        return
    if included in visited:
        result.warn(shown, f"'{target}' already parsed (duplicate or circular include)", lineno)
        return
    if depth + 1 > MAX_REQUIREMENTS_INCLUDE_DEPTH:
        result.warn(shown, f"include depth limit reached at '{target}'", lineno)
        return
    if not included.is_file():
        result.warn(shown, f"included file '{target}' not found", lineno)
        return

    _parse_file(
        included,
        root,
        result,
        visited=visited,
        depth=depth + 1,
        # An included file is dev-only if its parent is, or its own name says so.
        dev=dev or is_dev_requirements_file(included),
    )


def _handle_requirement(line: str, lineno: int, shown: str, result: ParseResult, dev: bool) -> None:
    """Turn one requirement line into a ``Dependency`` (+ findings)."""
    # Per-requirement options ("--hash=...", "--config-settings=...") follow the
    # requirement after whitespace. They don't affect *which* package it is.
    requirement_text = re.split(r"\s+--?[A-Za-z]", line, maxsplit=1)[0].strip()

    try:
        req = Requirement(requirement_text)
    except InvalidRequirement:
        if _looks_like_location(requirement_text):
            result.warn(
                shown,
                f"'{redact_url(requirement_text)}' installs from a path/URL, not an index; skipped",
                lineno,
            )
        else:
            result.warn(shown, f"invalid requirement '{requirement_text}' skipped", lineno)
        return

    name = canonicalize_name(req.name)

    # LIMITATION: environment markers (e.g. `; sys_platform == "win32"`) are
    # NOT evaluated. The machine running the scan is usually not the machine
    # the app is deployed on, so we report every dependency that *could* apply.

    if req.url:
        # "name @ https://..." / "name @ git+https://...": bypasses the index.
        url = redact_url(req.url)
        dep = result.add_dependency(
            Dependency(
                name=name,
                version=None,
                spec=url,
                ecosystem=Ecosystem.PYPI,
                source_file=shown,
                direct=True,
                dev=dev,
            )
        )
        result.add_finding(
            dep,
            parser_finding(
                NON_REGISTRY_SOURCE,
                Severity.MEDIUM,
                f"installed from {url} instead of PyPI; registry integrity checks do not apply",
                url=url,
            ),
        )
        return

    spec_text = str(req.specifier) or None
    version = exact_version(req.specifier)
    dep = result.add_dependency(
        Dependency(
            name=name,
            version=version,
            spec=spec_text,
            ecosystem=Ecosystem.PYPI,
            source_file=shown,
            # LIMITATION: a requirements file is assumed to list direct
            # dependencies. A `pip freeze` dump also contains transitive ones
            # and there is no way to tell them apart from the file alone.
            direct=True,
            dev=dev,
        )
    )
    if version is None:
        reason = f"range '{spec_text}'" if spec_text else "no version constraint"
        result.add_finding(
            dep,
            parser_finding(
                UNPINNED,
                Severity.LOW,
                f"not pinned to an exact version ({reason}); the installed version can change "
                "without any code change",
                spec=spec_text,
            ),
        )


def exact_version(specifier: SpecifierSet) -> str | None:
    """Return the pinned version if ``specifier`` allows exactly one version.

    >>> exact_version(SpecifierSet("==2.31.0"))
    '2.31.0'
    >>> exact_version(SpecifierSet(">=2.0")) is None
    True
    """
    specs = list(specifier)
    if len(specs) != 1:
        return None
    spec = specs[0]
    if spec.operator == "===":
        # "Arbitrary equality": compare as plain strings, no normalisation.
        return spec.version
    if spec.operator == "==" and not spec.version.endswith(".*"):
        try:
            # Normalise e.g. "2.31.00" -> "2.31.0" so it matches OSV's data.
            return str(Version(spec.version))
        except InvalidVersion:
            return spec.version
    return None


def is_dev_requirements_file(path: Path) -> bool:
    """Guess from the file name whether it lists development-only packages.

    LIMITATION: a heuristic. ``requirements-dev.txt`` is dev,
    ``requirements.txt`` is not; anything unusual is treated as production
    (the safer assumption for a security tool).
    """
    tokens = set(re.split(r"[-_.\s]+", path.stem.lower()))
    return bool(tokens & _DEV_TOKENS)


def _is_pypi(url: str) -> bool:
    """True if ``url`` points at the official PyPI."""
    try:
        return (urlsplit(url).hostname or "") in _PYPI_HOSTS
    except ValueError:
        return False


def _looks_like_location(text: str) -> bool:
    """True for bare URLs / VCS refs / local paths (``./pkg``, ``git+https://...``, ``x.whl``)."""
    return (
        "://" in text
        or text.startswith((".", "/", "\\", "~"))
        or text.endswith((".whl", ".zip", ".tar.gz"))
        or bool(re.match(r"^[A-Za-z]:[\\/]", text))  # Windows drive path
    )
