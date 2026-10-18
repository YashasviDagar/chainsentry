"""Parser for npm's ``package.json``.

``package.json`` lists what the project *asks for* (usually ranges like
``^4.17.0``), not what is actually installed. The exact versions live in
``package-lock.json``; ``discovery.py`` prefers the lockfile whenever it
exists and uses this parser only as a fallback.

Sections read
-------------
* ``dependencies``          -> production
* ``optionalDependencies``  -> production (installed when possible)
* ``devDependencies``       -> dev only
* ``peerDependencies`` are **not** listed: they are installed by the
  *consumer* of a library, so they already appear in that consumer's own
  manifest. They still count as "declared" for :func:`declared_names`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from chainsentry.models import Dependency, Ecosystem, Severity
from chainsentry.parsers.base import (
    NON_REGISTRY_SOURCE,
    NPM_ALIAS,
    UNPINNED,
    ParseResult,
    display_path,
    load_json_object,
    parser_finding,
)
from chainsentry.parsers.npm_common import SpecKind, classify_spec, is_valid_npm_name

# (section name, is_dev). Order matters: if a package appears in two sections
# the first one wins, matching how npm treats a production dependency.
_SECTIONS: tuple[tuple[str, bool], ...] = (
    ("dependencies", False),
    ("optionalDependencies", False),
    ("devDependencies", True),
)


def parse_package_json(path: Path, *, root: Path | None = None) -> ParseResult:
    """Parse ``package.json`` into direct dependencies.

    Raises:
        ParseError: if the file is not a readable JSON object.
    """
    data = load_json_object(path)
    shown = display_path(path, root)
    result = ParseResult(files=[shown])

    seen: set[str] = set()
    for section, dev in _SECTIONS:
        block = data.get(section)
        if block is None:
            continue
        if not isinstance(block, dict):
            result.warn(shown, f"'{section}' should be an object; ignored")
            continue
        for name, spec in block.items():
            if name in seen:
                continue
            seen.add(name)
            if not isinstance(spec, str):
                result.warn(shown, f"{section}.{name}: version spec is not a string; skipped")
                continue
            add_spec_dependency(result, name, spec, dev=dev, direct=True, source=shown)
    return result


def add_spec_dependency(
    result: ParseResult,
    name: str,
    spec: str,
    *,
    dev: bool,
    direct: bool,
    source: str,
) -> None:
    """Classify ``name: spec`` and add the resulting dependency + findings to ``result``."""
    if not is_valid_npm_name(name):
        result.warn(source, f"'{name}' is not a valid npm package name; skipped")
        return

    parsed = classify_spec(spec)
    findings = []

    if parsed.kind is SpecKind.ALIAS:
        # "my-lodash": "npm:lodash@^4" installs *lodash* under the folder
        # name "my-lodash". Vulnerabilities belong to the real package, so we
        # look that one up. Aliases also make malicious swaps harder to spot
        # in code review, which is why they are flagged.
        real = parsed.alias_name or ""
        if not is_valid_npm_name(real):
            result.warn(source, f"alias '{name}' -> '{real}' is not a valid package name; skipped")
            return
        findings.append(
            parser_finding(
                NPM_ALIAS,
                Severity.LOW,
                f"'{name}' is an alias for the package '{real}'",
                alias=name,
            )
        )
        name, spec = real, parsed.alias_spec or "*"
        parsed = classify_spec(spec)

    if parsed.kind is SpecKind.LOCAL:
        result.warn(source, f"'{name}' is a local path dependency ({spec}); skipped")
        return

    version = parsed.version if parsed.kind is SpecKind.EXACT else None
    dep = result.add_dependency(
        Dependency(
            name=name,
            version=version,
            spec=spec,
            ecosystem=Ecosystem.NPM,
            source_file=source,
            direct=direct,
            dev=dev,
        )
    )

    if parsed.kind in (SpecKind.GIT, SpecKind.URL):
        findings.append(
            parser_finding(
                NON_REGISTRY_SOURCE,
                Severity.MEDIUM,
                f"installed from {parsed.kind.value} source '{spec}' instead of the npm registry",
                spec=spec,
            )
        )
    elif version is None:
        findings.append(
            parser_finding(
                UNPINNED,
                Severity.LOW,
                f"version '{spec}' is a range; without a lockfile the installed version is unknown",
                spec=spec,
            )
        )

    for finding in findings:
        result.add_finding(dep, finding)


def declared_names(data: dict[str, Any]) -> set[str]:
    """All package names the project declares itself (used to mark lockfile entries as direct)."""
    names: set[str] = set()
    for section in (
        "dependencies",
        "optionalDependencies",
        "devDependencies",
        "peerDependencies",
    ):
        block = data.get(section)
        if isinstance(block, dict):
            names.update(block)
    return names
