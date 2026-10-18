"""Typosquatting detection: is this dependency a look-alike of a popular package?

The attack
----------
An attacker publishes ``reqeusts`` or ``crossenv`` (instead of ``requests`` /
``cross-env``) with malware in its install script, then waits for someone
to mistype a name. Real examples: ``crossenv`` (npm, 2017, stole env vars),
``jeIlyfish`` with a capital I (PyPI, 2019, stole SSH/GPG keys),
``python3-dateutil`` (PyPI, 2019).

How we detect it
----------------
For each dependency that is *not itself popular*, compare it with the top
~5,000 packages of its ecosystem (``checks/data/top_*.txt``) using several
targeted techniques, strongest first:

==========================  =======================  ==========================
technique                   example                  how it is detected
==========================  =======================  ==========================
unicode homoglyph           ``rеquests`` (Cyrillic е)  NFKC + confusables map
visual homoglyph            ``jeIlyfish``, ``rn``->m   "skeleton" comparison
separator confusion         ``crossenv``             compare without ``- _ .``
combosquatting (affix)      ``requests-py``          strip known prefixes/suffixes
edit distance (typo)        ``reqeusts``, ``lodahs``  Damerau-Levenshtein <= 1-2
==========================  =======================  ==========================

Precision vs recall
-------------------
Short names produce many accidental near-matches (``six``/``sip``), so
edit-distance matching only applies to names of 5+ characters, the allowed
distance grows with length, and a dependency that is itself on the popular
list is never flagged. Known false positives go in ``data/allowlist.txt``.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files

from packaging.utils import canonicalize_name

from chainsentry.models import Ecosystem, Finding, PackageReport, Severity

TYPOSQUAT = "TYPOSQUAT"

# Non-Latin letters that render (almost) identically to Latin ones. A real
# implementation could use the full Unicode confusables table (UTS #39);
# this covers the characters seen in actual package-registry attacks.
_CONFUSABLES = str.maketrans(
    {
        # Cyrillic
        "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
        "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
        "ӏ": "l",
        # Greek
        "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
        "υ": "u", "χ": "x",
    }
)  # fmt: skip

# ASCII sequences that look alike in many fonts. Order matters: multi-letter
# pairs are collapsed before single characters are mapped.
_VISUAL_PAIRS = (("rn", "m"), ("vv", "w"), ("cl", "d"))
_VISUAL_CHARS = str.maketrans({"0": "o", "1": "l", "i": "l", "|": "l", "5": "s"})

# Words commonly glued onto a popular name to make a plausible fake.
_PREFIXES = ("python-", "python3-", "py-", "py", "node-", "js-", "npm-", "the-", "real-")
_SUFFIXES = ("-js", ".js", "js", "-py", "py", "-python", "-node", "-dev", "-lib", "-cli", "2", "3")

_SEPARATORS_RE = re.compile(r"[-_.]")

#: Distance-2 matches only count for targets at or above this popularity rank.
_TWO_EDIT_MAX_RANK = 1000

# Techniques that are strong evidence on their own: legitimate packages
# almost never differ from a popular one only by look-alike letters or by
# separators (crossenv vs cross-env was exactly this).
_STRONG = frozenset({"unicode homoglyph", "visual homoglyph", "separator confusion"})
# Classic typo shapes: strong when the target is very popular.
_CLASSIC = frozenset({"transposition", "repeated character", "omission"})


@dataclass(frozen=True)
class TyposquatMatch:
    """A suspicious resemblance between a dependency and a popular package."""

    name: str
    target: str  # the popular package it resembles
    target_rank: int  # 1 = most downloaded
    technique: str
    distance: int  # edit distance (0 for homoglyph/separator matches)
    confidence: Severity  # HIGH or MEDIUM


def damerau_levenshtein(a: str, b: str, max_distance: int | None = None) -> int:
    """Edit distance counting insert, delete, substitute and *adjacent swap* as 1 each.

    This is the "optimal string alignment" variant: plain Levenshtein would
    count ``reqeusts`` -> ``requests`` (one swapped pair) as 2 edits; typos
    are very often swaps, so we count it as 1.

    If ``max_distance`` is given, the function stops early and returns
    ``max_distance + 1`` once the answer is known to exceed it - most
    comparisons are against obviously different names, so this matters for
    speed when comparing against 5,000 names.

    >>> damerau_levenshtein("reqeusts", "requests")
    1
    """
    if abs(len(a) - len(b)) > (max_distance if max_distance is not None else len(a) + len(b)):
        return (max_distance or 0) + 1
    # prev2/prev/curr are three rows of the classic dynamic-programming table.
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        curr = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(
                prev[j] + 1,  # deletion
                curr[j - 1] + 1,  # insertion
                prev[j - 1] + cost,  # substitution
            )
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                curr[j] = min(curr[j], prev2[j - 2] + 1)  # transposition
        if max_distance is not None and min(curr) > max_distance:
            return max_distance + 1
        prev2, prev = prev, curr
    return prev[-1]


def classify_edit(name: str, target: str) -> str:
    """Describe a single-edit difference in human terms."""
    if len(name) == len(target):
        diffs = [i for i, (x, y) in enumerate(zip(name, target, strict=True)) if x != y]
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
            return "transposition"
        return "substitution"
    if len(name) > len(target):
        # Which character was added? A doubled letter ("requestss") is common.
        added_at = [i for i in range(len(name)) if name[:i] + name[i + 1 :] == target]
        if any(i > 0 and name[i - 1] == name[i] for i in added_at):
            return "repeated character"
        return "insertion"
    return "omission"


def normalise(name: str, ecosystem: Ecosystem) -> str:
    """Lowercase, apply Unicode NFKC and map confusable letters to ASCII."""
    text = unicodedata.normalize("NFKC", name).lower().translate(_CONFUSABLES)
    return canonicalize_name(text) if ecosystem is Ecosystem.PYPI else text


def skeleton(name: str) -> str:
    """Collapse visually similar characters so look-alikes compare equal."""
    for pair, single in _VISUAL_PAIRS:
        name = name.replace(pair, single)
    return name.translate(_VISUAL_CHARS)


def collapse(name: str) -> str:
    """Remove separators: ``cross-env`` -> ``crossenv``."""
    return _SEPARATORS_RE.sub("", name)


class TyposquatDetector:
    """Compares names against a ranked list of popular packages.

    Args:
        popular: ecosystem -> names, most popular first.
        allowlist: ``"npm:name"`` / ``"pypi:name"`` entries never to flag.
    """

    def __init__(
        self, popular: dict[Ecosystem, list[str]], allowlist: set[str] | None = None
    ) -> None:
        self.allowlist = allowlist or set()
        self._rank: dict[Ecosystem, dict[str, int]] = {}
        self._by_length: dict[Ecosystem, dict[int, list[str]]] = {}
        self._by_collapsed: dict[Ecosystem, dict[str, str]] = {}
        self._by_skeleton: dict[Ecosystem, dict[str, str]] = {}
        for eco, names in popular.items():
            ranks: dict[str, int] = {}
            for name in names:
                ranks.setdefault(normalise(name, eco), len(ranks) + 1)
            self._rank[eco] = ranks
            by_len: dict[int, list[str]] = {}
            collapsed: dict[str, str] = {}
            skeletons: dict[str, str] = {}
            for name in ranks:  # dicts keep insertion order = popularity order
                by_len.setdefault(len(name), []).append(name)
                collapsed.setdefault(collapse(name), name)
                skeletons.setdefault(skeleton(name), name)
            self._by_length[eco] = by_len
            self._by_collapsed[eco] = collapsed
            self._by_skeleton[eco] = skeletons

    def is_popular(self, name: str, ecosystem: Ecosystem) -> bool:
        lowered = name.lower() if ecosystem is Ecosystem.NPM else canonicalize_name(name)
        return lowered in self._rank.get(ecosystem, {})

    def check(self, name: str, ecosystem: Ecosystem) -> TyposquatMatch | None:
        """Return the most convincing match for ``name``, or ``None`` if it looks fine."""
        ranks = self._rank.get(ecosystem)
        if not ranks or f"{_eco_prefix(ecosystem)}:{name.lower()}" in self.allowlist:
            return None
        if self.is_popular(name, ecosystem):
            return None  # it *is* the popular package

        norm = normalise(name, ecosystem)

        # 1. Non-ASCII letters that normalise to a popular name: almost never innocent.
        if norm in ranks:
            return self._match(name, norm, "unicode homoglyph", 0, ecosystem)

        # 2. Separator games: crossenv / cross_env vs cross-env.
        target = self._by_collapsed[ecosystem].get(collapse(norm))
        if target:
            return self._match(name, target, "separator confusion", 0, ecosystem)

        # 3. Visual look-alikes: jeIlyfish (capital i) vs jellyfish, rn vs m.
        target = self._by_skeleton[ecosystem].get(skeleton(norm))
        if target:
            return self._match(name, target, "visual homoglyph", 0, ecosystem)

        # 4. Edit distance: the classic typo. Short names are skipped (too noisy).
        best = self._closest(norm, ecosystem)
        if best:
            target, technique, distance = best
            return self._match(name, target, technique, distance, ecosystem)

        # 5. Popular name plus a plausible prefix/suffix.
        target = self._affix_target(norm, ranks)
        if target:
            return self._match(name, target, "combosquatting", 0, ecosystem)
        return None

    def _closest(self, norm: str, ecosystem: Ecosystem) -> tuple[str, str, int] | None:
        if len(norm) < 5:
            return None
        limit = 1 if len(norm) <= 8 else 2
        by_len = self._by_length[ecosystem]
        best: tuple[int, int, str] | None = None  # (distance, rank, target)
        ranks = self._rank[ecosystem]
        for length in range(len(norm) - limit, len(norm) + limit + 1):
            for target in by_len.get(length, ()):
                distance = damerau_levenshtein(norm, target, limit)
                # Two edits away is weak evidence; only count it against the
                # top 1,000 names, where squatting pays off for attackers.
                if distance <= limit and (distance == 1 or ranks[target] <= _TWO_EDIT_MAX_RANK):
                    candidate = (distance, ranks[target], target)
                    if best is None or candidate < best:
                        best = candidate
        if best is None:
            return None
        distance, _, target = best
        technique = classify_edit(norm, target) if distance == 1 else "multiple edits"
        return target, technique, distance

    def _affix_target(self, norm: str, ranks: dict[str, int]) -> str | None:
        for prefix in _PREFIXES:
            rest = norm[len(prefix) :]
            if norm.startswith(prefix) and len(rest) >= 4 and rest in ranks:
                return rest
        for suffix in _SUFFIXES:
            rest = norm[: -len(suffix)]
            if norm.endswith(suffix) and len(rest) >= 4 and rest in ranks:
                return rest
        return None

    def _match(
        self, name: str, target: str, technique: str, distance: int, ecosystem: Ecosystem
    ) -> TyposquatMatch:
        rank = self._rank[ecosystem][target]
        high = (
            technique in _STRONG
            or (technique in _CLASSIC and rank <= 1000)
            # Any one-character slip on a top-100 package is worth a hard look.
            or (distance == 1 and rank <= 100)
        )
        return TyposquatMatch(
            name=name,
            target=target,
            target_rank=rank,
            technique=technique,
            distance=distance,
            confidence=Severity.HIGH if high else Severity.MEDIUM,
        )


def _eco_prefix(ecosystem: Ecosystem) -> str:
    return "npm" if ecosystem is Ecosystem.NPM else "pypi"


def _read_lines(filename: str) -> list[str]:
    text = files("chainsentry.checks").joinpath("data", filename).read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


@lru_cache(maxsize=1)
def default_detector() -> TyposquatDetector:
    """Detector built from the bundled lists (loaded once per process)."""
    return TyposquatDetector(
        {Ecosystem.NPM: _read_lines("top_npm.txt"), Ecosystem.PYPI: _read_lines("top_pypi.txt")},
        allowlist={line.lower() for line in _read_lines("allowlist.txt")},
    )


class TyposquatCheck:
    """Flag dependencies whose names imitate popular packages. Works offline."""

    name = "typosquat"
    needs_network = False

    def __init__(self, detector: TyposquatDetector | None = None) -> None:
        self.detector = detector or default_detector()

    def run(self, packages: list[PackageReport]) -> list[str]:
        for report in packages:
            dep = report.dependency
            match = self.detector.check(dep.name, dep.ecosystem)
            if match is None:
                continue
            report.add_finding(
                Finding(
                    check=self.name,
                    code=TYPOSQUAT,
                    severity=match.confidence,
                    message=(
                        f"'{dep.name}' resembles the popular package '{match.target}' "
                        f"(#{match.target_rank} by downloads; {match.technique}). "
                        "Make sure this is the package you meant."
                    ),
                    details={
                        "target": match.target,
                        "target_rank": match.target_rank,
                        "technique": match.technique,
                        "distance": match.distance,
                    },
                )
            )
        return []
