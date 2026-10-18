"""Find manifest files in a project and send each one to the right parser.

Rules
-----
* **A file path** is parsed as exactly that file.
* **A directory** is searched for supported manifests (only the top level by
  default; ``recursive=True`` walks sub-folders but never enters
  ``node_modules``, virtualenvs, ``.git`` etc. - see ``config.SKIP_DIRS``).
* **Per folder, the npm lockfile wins over package.json.** The lockfile has
  exact versions *and* the transitive tree; ``package.json`` only has
  ranges. Precedence: ``npm-shrinkwrap.json`` > ``package-lock.json`` >
  ``package.json`` (the same order npm itself uses).
* **Requirements files** are any ``*requirements*.txt``
  (``requirements.txt``, ``requirements-dev.txt``, ``dev-requirements.txt``)
  plus every ``.txt`` inside a folder named ``requirements/``.
"""

from __future__ import annotations

import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from chainsentry.config import SKIP_DIRS
from chainsentry.parsers.base import ParseError, ParseResult, display_path, load_json_object
from chainsentry.parsers.npm_lockfile import parse_npm_lockfile
from chainsentry.parsers.npm_package_json import parse_package_json
from chainsentry.parsers.pip_requirements import is_dev_requirements_file, parse_requirements

PACKAGE_JSON = "package.json"
# Highest precedence first.
LOCKFILE_NAMES: tuple[str, ...] = ("npm-shrinkwrap.json", "package-lock.json")

_REQUIREMENTS_RE = re.compile(r"^(?:.*[-_.])?requirements(?:[-_.].*)?\.txt$", re.IGNORECASE)


def is_requirements_file(path: Path) -> bool:
    """True for ``requirements.txt``-style names and ``requirements/*.txt``."""
    if _REQUIREMENTS_RE.match(path.name):
        return True
    return path.suffix.lower() == ".txt" and path.parent.name.lower() == "requirements"


def _is_manifest(path: Path) -> bool:
    return path.name in LOCKFILE_NAMES or path.name == PACKAGE_JSON or is_requirements_file(path)


def find_manifests(root: Path, *, recursive: bool = False) -> list[Path]:
    """List supported manifest files under ``root``, sorted for stable output.

    SECURITY: ``os.walk`` does not follow symlinked directories by default,
    so a symlink loop (or a link to ``C:\\``) in a scanned repo cannot make
    us wander the whole disk.
    """
    found: list[Path] = []
    if not recursive:
        found = [p for p in root.iterdir() if p.is_file() and _is_manifest(p)]
        return sorted(found)

    for dirpath, dirnames, filenames in os.walk(root):
        # Editing dirnames in place is how os.walk lets you prune sub-trees.
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for filename in filenames:
            candidate = Path(dirpath) / filename
            if _is_manifest(candidate):
                found.append(candidate)
    return sorted(found)


def parse_project(target: Path | str, *, recursive: bool = False) -> ParseResult:
    """Parse a single manifest file, or every manifest in a project directory.

    Args:
        target: A manifest file or a project directory.
        recursive: For directories, also search sub-folders.

    Returns:
        One merged ``ParseResult`` for the whole project.

    Raises:
        ParseError: if ``target`` does not exist, is an unsupported file, or a
            manifest is unreadable / invalid JSON.
    """
    target = Path(target)
    if not target.exists():
        raise ParseError(target, "no such file or directory")

    if target.is_file():
        return parse_file(target, root=target.resolve().parent)

    root = target.resolve()
    result = ParseResult()
    manifests = find_manifests(root, recursive=recursive)
    if not manifests:
        result.warn(display_path(root, None), "no supported manifest files found")
        return result

    # Group by folder: each folder is its own npm project / Python project.
    by_folder: dict[Path, dict[str, Path]] = defaultdict(dict)
    for manifest in manifests:
        by_folder[manifest.parent][manifest.name] = manifest

    for folder in sorted(by_folder):
        files = by_folder[folder]
        _parse_npm_folder(files, root, result)

        # Production files first, dev files last. Order matters: if
        # requirements-dev.txt ran first, its "-r requirements.txt" would
        # mark every production package as dev-only. Parsed in this order,
        # the merge rule (dev only if *every* occurrence is dev) gets it right.
        requirement_files = sorted(
            (p for p in files.values() if is_requirements_file(p)),
            key=lambda p: (is_dev_requirements_file(p), p.name),
        )
        for path in requirement_files:
            # A file already pulled in through another file's "-r" is skipped.
            if display_path(path, root) not in result.files:
                result.extend(parse_requirements(path, root=root))
    return result


def parse_file(path: Path, *, root: Path) -> ParseResult:
    """Parse one explicitly named manifest file."""
    if path.name in LOCKFILE_NAMES:
        return parse_npm_lockfile(
            path, root=root, package_json=_load_sibling_package_json(path, root)
        )

    if path.name == PACKAGE_JSON:
        result = parse_package_json(path, root=root)
        if any((path.parent / name).is_file() for name in LOCKFILE_NAMES):
            result.warn(
                display_path(path, root),
                "a lockfile exists next to this file; scan the folder or the lockfile to get "
                "exact versions",
            )
        return result

    # Any explicitly named .txt / .in file is treated as a requirements file
    # (e.g. "deps/prod.txt", or pip-tools' "requirements.in").
    if path.suffix.lower() in (".txt", ".in"):
        return parse_requirements(path, root=root)

    raise ParseError(
        path,
        "unsupported file type (expected package.json, package-lock.json, "
        "npm-shrinkwrap.json or a requirements .txt file)",
    )


def _parse_npm_folder(files: dict[str, Path], root: Path, result: ParseResult) -> None:
    """Parse the npm manifests of one folder, preferring the lockfile."""
    lockfile = next((files[n] for n in LOCKFILE_NAMES if n in files), None)
    package_json = files.get(PACKAGE_JSON)

    if lockfile is not None:
        result.extend(
            parse_npm_lockfile(
                lockfile, root=root, package_json=_load_sibling_package_json(lockfile, root)
            )
        )
    elif package_json is not None:
        parsed = parse_package_json(package_json, root=root)
        parsed.warn(
            display_path(package_json, root),
            "no package-lock.json found; only direct dependencies with version ranges can be "
            "listed (run `npm install --package-lock-only` to create one)",
        )
        result.extend(parsed)


def _load_sibling_package_json(lockfile: Path, root: Path) -> dict[str, Any] | None:
    """Load the package.json next to a lockfile, or ``None`` if absent/broken.

    A broken package.json should not stop us from reading a valid lockfile,
    so errors are downgraded to ``None`` here (the lockfile parser then
    warns that direct dependencies cannot be identified).
    """
    candidate = lockfile.parent / PACKAGE_JSON
    if not candidate.is_file():
        return None
    try:
        return load_json_object(candidate)
    except ParseError:
        return None
