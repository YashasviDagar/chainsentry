"""Parsers: manifest files -> ``Dependency`` objects (no network access).

Public API - most callers only need :func:`parse_project`::

    from chainsentry.parsers import parse_project
    result = parse_project("path/to/project")
    for dep in result.dependencies:
        print(dep.display, result.findings_for(dep))

Modules:
    base               ParseResult, ParseError, safe file reading, finding codes
    discovery          finds manifests in a folder and dispatches to parsers
    pip_requirements   requirements.txt (PEP 508 / pip format)
    npm_package_json   package.json (declared ranges)
    npm_lockfile       package-lock.json / npm-shrinkwrap.json v1-v3 (exact versions)
    npm_common         npm spec classification and name validation
"""

from chainsentry.parsers.base import ParseError, ParseResult
from chainsentry.parsers.discovery import find_manifests, parse_file, parse_project

__all__ = ["ParseError", "ParseResult", "find_manifests", "parse_file", "parse_project"]
