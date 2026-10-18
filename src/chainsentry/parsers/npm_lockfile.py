"""Parser for ``package-lock.json`` and ``npm-shrinkwrap.json``.

The lockfile records the *exact* version of every package npm installed,
including transitive ones, which is exactly what vulnerability lookups need.

Lockfile formats (https://docs.npmjs.com/cli/configuring-npm/package-lock-json)
--------------------------------------------------------------------------------
**v1** (npm 5-6): a nested tree under ``"dependencies"``::

    "dependencies": {
      "express": { "version": "4.18.2", "resolved": "...", "integrity": "...",
                   "dependencies": { "debug": { "version": "2.6.9", ... } } }
    }

**v2** (npm 7-8): a flat map under ``"packages"`` keyed by install path,
plus the old ``"dependencies"`` tree for backwards compatibility.
**v3** (npm 9+): only ``"packages"``::

    "packages": {
      "":                                   { "dependencies": {"express": "^4.18.2"} },
      "node_modules/express":               { "version": "4.18.2", ... },
      "node_modules/express/node_modules/debug": { "version": "2.6.9", ... }
    }

Design decisions
----------------
* **Prefer ``packages`` when present.** It is flat, complete and records
  ``dev`` flags precisely; ``dependencies`` is only read for v1 files.
* **The same package can appear at several versions** (two nested copies).
  Each version is a separate ``Dependency`` because each can have different
  vulnerabilities.
* **Walk the v1 tree with an explicit stack, not recursion.** A crafted,
  deeply nested lockfile cannot crash the scanner with ``RecursionError``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from chainsentry.models import Dependency, Ecosystem, Severity
from chainsentry.parsers.base import (
    MISSING_INTEGRITY,
    NON_REGISTRY_SOURCE,
    NPM_ALIAS,
    ParseResult,
    display_path,
    load_json_object,
    parser_finding,
    redact_url,
)
from chainsentry.parsers.npm_common import (
    SpecKind,
    classify_spec,
    exact_npm_version,
    is_official_registry_url,
    is_valid_npm_name,
)
from chainsentry.parsers.npm_package_json import declared_names

_NODE_MODULES = "node_modules/"


def parse_npm_lockfile(
    path: Path,
    *,
    root: Path | None = None,
    package_json: dict[str, Any] | None = None,
) -> ParseResult:
    """Parse an npm lockfile (v1, v2 or v3).

    Args:
        path: ``package-lock.json`` or ``npm-shrinkwrap.json``.
        root: Scan root, used to display relative paths.
        package_json: The parsed sibling ``package.json``, if available.
            v2/v3 lockfiles contain the root manifest themselves; v1 files
            do not, so without it we cannot tell direct from transitive.

    Raises:
        ParseError: if the file is not a readable JSON object.
    """
    data = load_json_object(path)
    shown = display_path(path, root)
    result = ParseResult(files=[shown])

    lock_version = data.get("lockfileVersion", 1)
    packages = data.get("packages")

    if isinstance(packages, dict) and isinstance(lock_version, int) and lock_version >= 2:
        _parse_packages_map(packages, package_json, shown, result)
    elif isinstance(data.get("dependencies"), dict):
        _parse_v1_tree(data["dependencies"], package_json, shown, result)
    elif packages is None and data.get("dependencies") is None:
        pass  # a project with no dependencies at all - nothing to do
    else:
        result.warn(shown, f"unrecognised lockfile layout (lockfileVersion={lock_version!r})")
    return result


def _parse_packages_map(
    packages: dict[str, Any],
    package_json: dict[str, Any] | None,
    shown: str,
    result: ParseResult,
) -> None:
    """Handle the flat ``packages`` map of lockfile v2/v3."""
    # The "" key is the project itself; its dependency lists tell us which
    # packages are direct. Fall back to package.json if it is missing.
    root_entry = packages.get("")
    if isinstance(root_entry, dict):
        direct_names = declared_names(root_entry)
    else:
        direct_names = declared_names(package_json or {})

    for install_path, entry in packages.items():
        if install_path == "":
            continue
        if not isinstance(entry, dict):
            result.warn(shown, f"packages['{install_path}'] is not an object; skipped")
            continue
        # Keys without "node_modules/" are workspace source folders (the
        # project's own code, e.g. "packages/app"), not downloaded packages.
        if _NODE_MODULES not in install_path:
            continue
        # A "link" entry is a symlink to a workspace folder; skip it, the
        # folder's real dependencies are listed under their own keys.
        if entry.get("link"):
            continue

        # "node_modules/a/node_modules/@scope/b" -> "@scope/b"
        install_name = install_path.rsplit(_NODE_MODULES, 1)[1]
        # For aliases ("my-lodash": "npm:lodash@4"), "name" holds the real package.
        real_name = entry.get("name") if isinstance(entry.get("name"), str) else install_name

        # Only a top-level copy (directly under ./node_modules) can be the one
        # the project asked for; a nested copy with the same name is transitive.
        is_top_level = install_path == f"{_NODE_MODULES}{install_name}"

        _add_locked_package(
            result,
            shown,
            install_name=install_name,
            real_name=real_name,
            version=entry.get("version"),
            resolved=entry.get("resolved"),
            integrity=entry.get("integrity"),
            direct=is_top_level and install_name in direct_names,
            # "devOptional" packages may also be installed in production (as
            # optional deps of a prod package), so only a plain "dev" counts.
            dev=bool(entry.get("dev")),
        )


def _parse_v1_tree(
    dependencies: dict[str, Any],
    package_json: dict[str, Any] | None,
    shown: str,
    result: ParseResult,
) -> None:
    """Handle the nested ``dependencies`` tree of lockfile v1."""
    if package_json is None:
        result.warn(
            shown,
            "lockfile v1 without a package.json next to it: cannot tell direct from "
            "transitive dependencies (all reported as transitive)",
        )
    direct_names = declared_names(package_json or {})

    # Stack of (subtree, is_top_level). Using a list as a stack instead of
    # recursion keeps memory use flat however deep the tree is.
    stack: list[tuple[dict[str, Any], bool]] = [(dependencies, True)]
    while stack:
        tree, top_level = stack.pop()
        for install_name, entry in tree.items():
            if not isinstance(entry, dict):
                result.warn(shown, f"dependencies['{install_name}'] is not an object; skipped")
                continue

            real_name, version = install_name, entry.get("version")
            # v1 records aliases inside "version": "npm:lodash@4.17.21".
            if isinstance(version, str) and version.startswith("npm:"):
                parsed = classify_spec(version)
                real_name = parsed.alias_name or install_name
                version = parsed.alias_spec

            _add_locked_package(
                result,
                shown,
                install_name=install_name,
                real_name=real_name,
                version=version,
                resolved=entry.get("resolved"),
                integrity=entry.get("integrity"),
                direct=top_level and install_name in direct_names,
                dev=bool(entry.get("dev")),
            )

            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                stack.append((nested, False))


def _add_locked_package(
    result: ParseResult,
    shown: str,
    *,
    install_name: str,
    real_name: str,
    version: Any,
    resolved: Any,
    integrity: Any,
    direct: bool,
    dev: bool,
) -> None:
    """Validate one lockfile entry and add it, with findings, to ``result``."""
    if not is_valid_npm_name(real_name):
        result.warn(shown, f"'{real_name}' is not a valid npm package name; skipped")
        return
    if not isinstance(version, str) or not version:
        result.warn(shown, f"'{install_name}' has no version; skipped")
        return

    findings = []
    exact = exact_npm_version(version)
    resolved_url = redact_url(resolved) if isinstance(resolved, str) else None

    if exact is None:
        # v1 stores git/URL deps as their spec ("github:user/repo#abc123").
        kind = classify_spec(version).kind
        if kind is SpecKind.LOCAL:
            result.warn(shown, f"'{install_name}' is a local path dependency; skipped")
            return
        findings.append(
            parser_finding(
                NON_REGISTRY_SOURCE,
                Severity.MEDIUM,
                f"locked to non-registry source '{redact_url(version)}'",
                source=redact_url(version),
            )
        )
    elif resolved_url and not is_official_registry_url(resolved_url):
        findings.append(
            parser_finding(
                NON_REGISTRY_SOURCE,
                Severity.MEDIUM,
                f"downloaded from {resolved_url} instead of the official npm registry over HTTPS",
                resolved=resolved_url,
            )
        )
    elif resolved_url and not integrity:
        # SECURITY: "integrity" is the SHA-512 of the tarball. npm refuses a
        # download whose hash differs - without it, a tampered tarball would
        # be installed silently.
        findings.append(
            parser_finding(
                MISSING_INTEGRITY,
                Severity.LOW,
                "lockfile entry has no integrity hash; tampering would go undetected",
            )
        )

    if real_name != install_name:
        findings.append(
            parser_finding(
                NPM_ALIAS,
                Severity.LOW,
                f"'{install_name}' is an alias for the package '{real_name}'",
                alias=install_name,
            )
        )

    dep = result.add_dependency(
        Dependency(
            name=real_name,
            version=exact,
            spec=version,
            ecosystem=Ecosystem.NPM,
            source_file=shown,
            direct=direct,
            dev=dev,
            resolved_url=resolved_url,
        )
    )
    for finding in findings:
        result.add_finding(dep, finding)
