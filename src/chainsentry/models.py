"""Shared data model - the vocabulary every ChainSentry layer speaks.

Design decisions
----------------
* **Plain dataclasses, no ORM / pydantic.** The data is small and
  in-memory; dataclasses are stdlib, typed, and easy to explain.
* **``Dependency`` is frozen (immutable + hashable).** A dependency read
  from a file is a *fact*; nothing downstream should mutate it. Being
  hashable also lets us put it in sets and use it as a dict key.
* **Enums for closed sets of values** (ecosystems, severities) so a typo
  such as ``"pypi"`` vs ``"PyPI"`` is caught immediately instead of
  silently producing zero OSV results.
* **The model grew with the phases.** ``Vulnerability``,
  ``PackageReport`` and ``ScanResult`` arrived in Phase 2 with the scanner;
  risk scores (``ScoreComponent`` and the score fields) in Phase 5.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from urllib.parse import quote


class Ecosystem(StrEnum):
    """Package ecosystems ChainSentry understands.

    The *values* are exactly the ecosystem names used by the OSV.dev API
    (https://ossf.github.io/osv-schema/#affectedpackage-field), so they can
    be sent to OSV without any translation table.
    """

    NPM = "npm"
    PYPI = "PyPI"


class Severity(StrEnum):
    """How serious a finding is, from UNKNOWN (lowest) to CRITICAL.

    Uses the same labels as CVSS qualitative ratings
    (Low / Medium / High / Critical) so vulnerability severities and our own
    heuristic findings can be compared on one scale.
    """

    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Numeric order for comparisons, e.g. ``sev.rank >= Severity.HIGH.rank``.

        StrEnum members compare as strings ("HIGH" < "LOW" alphabetically),
        which is wrong for severities, so we expose an explicit rank instead.
        """
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.UNKNOWN: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class Dependency:
    """One package (at one version) that the project depends on.

    Attributes:
        name: Package name as the registry knows it. PyPI names are
            normalised per PEP 503 (``Flask_Login`` -> ``flask-login``).
            npm names are kept *exactly* as written because npm still hosts
            legacy mixed-case packages (e.g. ``JSONStream``) and OSV matches
            names case-sensitively.
        version: The exact version if it is known (from a lockfile or an
            ``==`` pin), otherwise ``None``. Vulnerability lookups need an
            exact version.
        spec: The original version constraint text, e.g. ``"^4.17.0"`` or
            ``">=2.0,<3"``. Kept for display and for later resolution.
        ecosystem: npm or PyPI.
        source_file: The manifest this dependency was read from.
        direct: ``True`` if the project declares it itself; ``False`` if it
            was pulled in by another package (transitive).
        dev: ``True`` for development-only dependencies (tests, linters...).
        resolved_url: Where a lockfile says the package was downloaded from.
            A non-registry URL here is a supply-chain signal.
    """

    name: str
    version: str | None
    spec: str | None
    ecosystem: Ecosystem
    source_file: str
    direct: bool = True
    dev: bool = False
    resolved_url: str | None = None

    @property
    def key(self) -> tuple[Ecosystem, str, str | None]:
        """Identity of the *package version*, ignoring where it was declared.

        Two files that both depend on ``requests==2.31.0`` produce two
        ``Dependency`` objects with the same key; the scanner uses this key to
        de-duplicate them and to attach findings.
        """
        return (self.ecosystem, self.name, self.version)

    @property
    def display(self) -> str:
        """Human-friendly ``name@version`` (or ``name (spec)`` when unpinned)."""
        if self.version:
            return f"{self.name}@{self.version}"
        return f"{self.name} ({self.spec or 'any version'})"

    @property
    def purl(self) -> str:
        """Package URL (purl) - the standard ID used in SBOMs.

        Spec: https://github.com/package-url/purl-spec

        Examples::

            pkg:npm/lodash@4.17.21
            pkg:npm/%40babel/core@7.24.0     (the '@' of a scope is encoded)
            pkg:pypi/requests@2.31.0
        """
        # quote(..., safe="") percent-encodes everything that is not a plain
        # URL character, as the purl spec requires for each path segment.
        if self.ecosystem is Ecosystem.NPM:
            if self.name.startswith("@") and "/" in self.name:
                scope, bare = self.name.split("/", 1)
                path = f"{quote(scope, safe='')}/{quote(bare, safe='')}"
            else:
                path = quote(self.name, safe="")
            base = f"pkg:npm/{path}"
        else:
            # purl's pypi type wants lowercase names with '-' instead of '_';
            # our PyPI names are already PEP 503-normalised, which satisfies that.
            base = f"pkg:pypi/{quote(self.name, safe='')}"
        return f"{base}@{quote(self.version, safe='')}" if self.version else base


@dataclass
class Finding:
    """A single risk signal about a dependency (anything except a known CVE).

    Attributes:
        check: Which component produced it: ``"parser"``, ``"typosquat"``,
            ``"health"``.
        code: Stable machine-readable identifier, e.g. ``"UNPINNED"`` or
            ``"INSTALL_SCRIPT"``. Scoring (Phase 5) keys its weights on this.
        severity: How bad it is.
        message: One human-readable sentence.
        details: Extra structured data for JSON reports (free-form).
    """

    check: str
    code: str
    severity: Severity
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Vulnerability:
    """A known vulnerability affecting one dependency (from OSV.dev).

    Attributes:
        id: OSV identifier - ``GHSA-...`` (GitHub advisory), ``PYSEC-...``
            (PyPI advisory DB), ``CVE-...``, ``MAL-...`` (malicious package).
        aliases: Other IDs for the same issue, e.g. ``["CVE-2021-23337"]``.
        summary: One-line description.
        severity: Qualitative rating (from the CVSS score when available).
        cvss_score: CVSS v3 base score 0.0-10.0, if a v3 vector was published.
        cvss_vector: The raw vector string, e.g. ``CVSS:3.1/AV:N/AC:L/...``.
        affected_ranges: Human-readable ranges, e.g. ``[">=4.0.0, <4.17.21"]``.
        fixed_versions: Versions that contain the fix (upgrade targets).
        references: Advisory / patch URLs.
        published: ISO-8601 publication date, if known.
    """

    id: str
    summary: str
    severity: Severity
    aliases: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str | None = None
    affected_ranges: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    published: str | None = None

    @property
    def cve_ids(self) -> list[str]:
        """The CVE identifiers among ``id`` and ``aliases``."""
        return [i for i in [self.id, *self.aliases] if i.startswith("CVE-")]

    @property
    def is_malicious(self) -> bool:
        """OSV ``MAL-`` entries describe packages that are malware, not bugs."""
        return self.id.startswith("MAL-") or any(a.startswith("MAL-") for a in self.aliases)


@dataclass(frozen=True)
class ScoreComponent:
    """One line of a score explanation, e.g. ("worst vulnerability: CRITICAL", 60)."""

    reason: str
    points: int


@dataclass
class PackageReport:
    """Everything ChainSentry learned about one dependency.

    Checks *add* to ``findings`` / ``vulnerabilities``; the scorer then sets
    ``score``, ``band`` and ``score_breakdown`` (which explains the score).
    """

    dependency: Dependency
    findings: list[Finding] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    #: True when the version was resolved from a range by ``--resolve``
    #: (i.e. "what would be installed today", not what is locked).
    resolved: bool = False
    #: Risk score 0-100 (see scoring/risk.py and docs/SCORING.md).
    score: int = 0
    band: Severity = Severity.LOW
    score_breakdown: list[ScoreComponent] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        """Append ``finding`` unless an identical one (same code+message) exists."""
        if not any(f.code == finding.code and f.message == finding.message for f in self.findings):
            self.findings.append(finding)


@dataclass
class ScanResult:
    """The outcome of scanning one project - the input to every reporter."""

    target: str
    packages: list[PackageReport]
    files: list[str] = field(default_factory=list)
    #: Non-fatal notes from parsing (skipped lines, risky pip options...).
    warnings: list[str] = field(default_factory=list)
    #: Problems that made a check incomplete (e.g. "osv: HTTP 503").
    errors: list[str] = field(default_factory=list)
    #: Names of the checks that ran, e.g. ["osv", "typosquat", "health"].
    checks: list[str] = field(default_factory=list)
    tool_version: str = ""
    #: ISO-8601 UTC timestamp of when the scan started.
    scanned_at: str = ""
    duration_seconds: float = 0.0
    #: Overall project risk 0-100 and its band.
    project_score: int = 0
    project_band: Severity = Severity.LOW
