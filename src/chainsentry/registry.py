"""Fetch and summarise package metadata from the npm registry and PyPI.

Two features need registry metadata:

* ``--resolve`` (Phase 2) needs the list of published versions.
* Health checks (Phase 4) need release dates, maintainers, install scripts,
  deprecation and yanking information.

Both go through :class:`RegistryClient`, so each package is downloaded at
most once per run (and once per day thanks to the cache).

Design decision: cache a *summary*, not the raw response
----------------------------------------------------------
npm's full metadata document ("packument") for a popular package can be
several megabytes - it contains every version's ``package.json``. We extract
the few fields we need into a :class:`PackageInfo` (a few KB) and cache
that instead. Smaller cache, faster reads.

Endpoints
---------
* npm:  ``GET https://registry.npmjs.org/<name>`` (scoped: ``@scope%2Fname``)
  https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md
* PyPI: ``GET https://pypi.org/pypi/<name>/json``
  https://docs.pypi.org/api/json/
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from chainsentry import config
from chainsentry.models import Ecosystem
from chainsentry.net.cache import MISS
from chainsentry.net.client import HttpClient, quote_segment

#: npm lifecycle scripts that run automatically during ``npm install``.
INSTALL_SCRIPT_NAMES: tuple[str, ...] = ("preinstall", "install", "postinstall")

_REPO_HOST_RE = re.compile(r"(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|sr\.ht)", re.I)
_INACTIVE_CLASSIFIER = "Development Status :: 7 - Inactive"


@dataclass
class PackageInfo:
    """The registry facts ChainSentry uses about one package (all versions).

    Every field is JSON-serialisable so the object can be cached as-is.
    """

    ecosystem: str
    name: str
    #: Published versions that can still be installed (yanked ones excluded).
    versions: list[str] = field(default_factory=list)
    #: The registry's "latest" version.
    latest: str | None = None
    #: version -> ISO-8601 upload time.
    release_times: dict[str, str] = field(default_factory=dict)
    #: When the package (its first version) was published.
    created: str | None = None
    #: Number of maintainers; ``None`` when the registry does not say (PyPI).
    maintainers: int | None = None
    #: version -> install-time scripts it defines (only versions that have some).
    install_scripts: dict[str, list[str]] = field(default_factory=dict)
    #: version -> deprecation message. Key "*" = the whole project is deprecated.
    deprecated: dict[str, str] = field(default_factory=dict)
    #: Versions withdrawn by their author (PyPI "yanked").
    yanked: list[str] = field(default_factory=list)
    #: Source repository URL, if the metadata links one.
    repository: str | None = None
    #: npm: the package was unpublished (all versions removed).
    unpublished: bool = False

    @property
    def last_release(self) -> str | None:
        """ISO time of the most recent upload (string max works for ISO-8601 UTC)."""
        return max(self.release_times.values(), default=None)

    def deprecation_for(self, version: str | None) -> str | None:
        if "*" in self.deprecated:
            return self.deprecated["*"]
        return self.deprecated.get(version or "")


class RegistryClient:
    """Look up :class:`PackageInfo` for npm and PyPI packages."""

    def __init__(self, client: HttpClient) -> None:
        self.client = client
        # In-memory memo on top of the disk cache: --resolve and the health
        # check both ask for the same packages, even when caching is off.
        self._memo: dict[tuple[Ecosystem, str], PackageInfo | None] = {}

    def info(self, ecosystem: Ecosystem, name: str) -> PackageInfo | None:
        """Return metadata, or ``None`` if the package does not exist on the public registry.

        Raises:
            HttpError: if the registry could not be reached.
        """
        if (ecosystem, name) in self._memo:
            return self._memo[(ecosystem, name)]
        info = self._lookup(ecosystem, name)
        self._memo[(ecosystem, name)] = info
        return info

    def _lookup(self, ecosystem: Ecosystem, name: str) -> PackageInfo | None:
        key = f"registry:{ecosystem.value}:{name}"
        cached = self.client.cache.get_json(key)
        if cached is not MISS:
            return PackageInfo(**cached) if cached is not None else None

        if ecosystem is Ecosystem.NPM:
            # "@" stays literal, "/" is encoded: "@types%2Fnode" is what npm expects.
            url = f"{config.NPM_REGISTRY_URL}/{quote_segment(name, safe='@')}"
            doc = self.client.get_json(url, not_found_ok=True)
            info = summarise_npm(name, doc) if doc else None
        else:
            url = f"{config.PYPI_JSON_URL}/{quote_segment(name)}/json"
            doc = self.client.get_json(url, not_found_ok=True)
            info = summarise_pypi(name, doc) if doc else None

        if info is None:
            self.client.cache.set_json(key, None, config.TTL_NOT_FOUND)
        else:
            self.client.cache.set_json(key, asdict(info), config.TTL_REGISTRY)
        return info


def summarise_npm(name: str, doc: dict[str, Any]) -> PackageInfo:
    """Extract a :class:`PackageInfo` from an npm packument."""
    times: dict[str, Any] = doc.get("time") or {}
    versions: dict[str, Any] = doc.get("versions") or {}
    info = PackageInfo(ecosystem=Ecosystem.NPM.value, name=name)
    info.versions = list(versions)
    info.latest = (doc.get("dist-tags") or {}).get("latest")
    # "time" also holds bookkeeping keys that are not versions.
    info.release_times = {
        v: t
        for v, t in times.items()
        if v not in ("created", "modified", "unpublished") and isinstance(t, str)
    }
    info.created = times.get("created") if isinstance(times.get("created"), str) else None
    info.unpublished = "unpublished" in times and not versions
    maintainers = doc.get("maintainers")
    info.maintainers = len(maintainers) if isinstance(maintainers, list) else None
    info.repository = _repo_url(doc.get("repository"))

    for version, manifest in versions.items():
        if not isinstance(manifest, dict):
            continue
        scripts = manifest.get("scripts") if isinstance(manifest.get("scripts"), dict) else {}
        found = [s for s in INSTALL_SCRIPT_NAMES if s in scripts]
        # A binding.gyp file makes npm run "node-gyp rebuild" even without an
        # explicit install script; the registry marks that with gypfile.
        if manifest.get("gypfile") and "install" not in found:
            found.append("install (node-gyp)")
        if found:
            info.install_scripts[version] = found
        if isinstance(manifest.get("deprecated"), str) and manifest["deprecated"]:
            info.deprecated[version] = manifest["deprecated"]
        if info.repository is None:
            info.repository = _repo_url(manifest.get("repository"))
    return info


def summarise_pypi(name: str, doc: dict[str, Any]) -> PackageInfo:
    """Extract a :class:`PackageInfo` from PyPI's JSON API response.

    LIMITATION: PyPI's JSON API does not list maintainers/owners, so
    ``maintainers`` stays ``None`` ("unknown") rather than being guessed from
    the free-text author fields.
    """
    meta: dict[str, Any] = doc.get("info") or {}
    releases: dict[str, Any] = doc.get("releases") or {}
    info = PackageInfo(ecosystem=Ecosystem.PYPI.value, name=name, latest=meta.get("version"))

    for version, files in releases.items():
        if not isinstance(files, list) or not files:
            continue  # a version with no uploaded files cannot be installed
        times = [f.get("upload_time_iso_8601") for f in files if isinstance(f, dict)]
        times = [t for t in times if isinstance(t, str)]
        if times:
            info.release_times[version] = min(times)
        if all(isinstance(f, dict) and f.get("yanked") for f in files):
            info.yanked.append(version)
        else:
            info.versions.append(version)

    info.created = min(info.release_times.values(), default=None)
    if _INACTIVE_CLASSIFIER in (meta.get("classifiers") or []):
        info.deprecated["*"] = "project is marked 'Development Status :: 7 - Inactive'"

    urls = list((meta.get("project_urls") or {}).values()) + [meta.get("home_page")]
    info.repository = next(
        (u for u in urls if isinstance(u, str) and _REPO_HOST_RE.search(u)), None
    )
    return info


def _repo_url(value: Any) -> str | None:
    """npm "repository" may be a string or ``{"type": "git", "url": "..."}``."""
    if isinstance(value, dict):
        value = value.get("url")
    return value if isinstance(value, str) and value.strip() else None
