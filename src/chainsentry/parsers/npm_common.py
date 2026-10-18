"""Helpers shared by the ``package.json`` and ``package-lock.json`` parsers.

npm version specs come in many shapes - only some of them point at the
public registry. This module classifies a spec string so both parsers apply
the same rules.

Reference: https://docs.npmjs.com/cli/configuring-npm/package-json#dependencies
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import NamedTuple
from urllib.parse import urlsplit

from chainsentry.config import NPM_REGISTRY_HOSTS

# Exact semver version: 1.2.3, 1.2.3-beta.1, 1.2.3+build. npm also accepts a
# leading "v" or "=" ("=1.2.3") as the same exact version.
_EXACT_SEMVER_RE = re.compile(
    r"^[=v]?(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$"
)

# Valid npm package names (https://github.com/npm/validate-npm-package-name).
# Uppercase letters are allowed because legacy packages such as "JSONStream"
# still exist; new packages must be lowercase.
_NPM_NAME_RE = re.compile(r"^(?:@[a-z0-9~-][a-z0-9._~-]*/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$")
_NPM_NAME_MAX_LEN = 214

# "user/repo" or "user/repo#ref" - npm's shorthand for a GitHub repository.
_GITHUB_SHORTHAND_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:#.*)?$")

# A dist-tag such as "latest", "next", "beta" (starts with a letter).
_DIST_TAG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]*$")


class SpecKind(StrEnum):
    """What an npm dependency spec points at."""

    EXACT = "exact"  # "1.2.3"           -> one specific registry version
    RANGE = "range"  # "^1.2.3", "~1.2"  -> some registry version, decided at install time
    ANY = "any"  # "*", "", "latest" -> whatever is newest at install time
    ALIAS = "alias"  # "npm:other@1.0.0" -> a *different* package under this name
    GIT = "git"  # "github:u/r", "git+https://..." -> code straight from a repo
    URL = "url"  # "https://host/pkg.tgz" -> arbitrary tarball
    LOCAL = "local"  # "file:../lib", "workspace:*" -> code inside this repo


class NpmSpec(NamedTuple):
    """Result of :func:`classify_spec`."""

    kind: SpecKind
    version: str | None = None  # set for EXACT
    alias_name: str | None = None  # set for ALIAS: the real package name
    alias_spec: str | None = None  # set for ALIAS: the version spec of the real package


def is_valid_npm_name(name: str) -> bool:
    """Check ``name`` against npm's naming rules.

    SECURITY: names flow into registry URLs in later phases. Rejecting
    anything that is not a legal npm name (e.g. ``"../../admin"``) here is a
    first line of defence; URL-encoding in the HTTP layer is the second.
    """
    return 0 < len(name) <= _NPM_NAME_MAX_LEN and bool(_NPM_NAME_RE.match(name))


def exact_npm_version(text: str) -> str | None:
    """Return the version if ``text`` is one exact semver version, else ``None``."""
    match = _EXACT_SEMVER_RE.match(text.strip())
    return match.group("version") if match else None


def classify_spec(spec: str) -> NpmSpec:
    """Classify a dependency spec from ``package.json`` (or a v1 lockfile ``version``).

    Examples::

        "4.17.21"              -> EXACT, version="4.17.21"
        "^4.17.0"              -> RANGE
        "*"                    -> ANY
        "npm:lodash@^4"        -> ALIAS, alias_name="lodash", alias_spec="^4"
        "github:user/repo"     -> GIT
        "https://x.com/p.tgz"  -> URL
        "file:../shared"       -> LOCAL
    """
    spec = spec.strip()

    if spec in ("", "*", "x", "X"):
        return NpmSpec(SpecKind.ANY)

    if spec.startswith("npm:"):
        name, _, sub_spec = _split_alias(spec[4:])
        return NpmSpec(SpecKind.ALIAS, alias_name=name, alias_spec=sub_spec or "*")

    if spec.startswith(("file:", "link:", "workspace:", "portal:", "./", "../", "/", "~/")):
        return NpmSpec(SpecKind.LOCAL)

    if spec.startswith(("git+", "git:", "git@", "github:", "gitlab:", "bitbucket:", "gist:")):
        return NpmSpec(SpecKind.GIT)

    if spec.startswith(("http://", "https://")):
        return NpmSpec(SpecKind.URL)

    # Version ranges never contain "/", so "user/repo" is the GitHub shorthand.
    if _GITHUB_SHORTHAND_RE.match(spec):
        return NpmSpec(SpecKind.GIT)

    version = exact_npm_version(spec)
    if version:
        return NpmSpec(SpecKind.EXACT, version=version)

    if _DIST_TAG_RE.match(spec):
        # "latest", "next": a moving pointer, effectively "any version".
        return NpmSpec(SpecKind.ANY)

    return NpmSpec(SpecKind.RANGE)


def _split_alias(rest: str) -> tuple[str, str, str]:
    """Split ``"@scope/name@^1.0"`` into ``("@scope/name", "@", "^1.0")``.

    The first "@" of a scoped name is part of the name, so we search for the
    separator starting at index 1.
    """
    at = rest.find("@", 1)
    if at == -1:
        return rest, "", ""
    return rest[:at], "@", rest[at + 1 :]


def is_official_registry_url(url: str) -> bool:
    """True if a lockfile ``resolved`` URL is HTTPS on the public npm registry.

    LIMITATION: companies often use a private mirror (Artifactory, Verdaccio).
    Those URLs are reported as non-registry sources; a configurable list of
    trusted registries is future work.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    # SECURITY: plain "http://" counts as non-registry too - without TLS a
    # network attacker can swap the tarball (the integrity hash still helps).
    return parts.scheme == "https" and (parts.hostname or "") in NPM_REGISTRY_HOSTS
