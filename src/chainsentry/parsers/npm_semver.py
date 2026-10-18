"""A small, well-tested implementation of npm's version-range rules.

Used by ``--resolve`` to answer "which version would ``^4.17.0`` install
today?" from the list of versions on the registry.

Reference: https://github.com/npm/node-semver#ranges

How it works
------------
Every range is *desugared* into primitive comparators (``>=``, ``>``,
``<``, ``<=``, ``=``) on full versions, then a version satisfies the range if
it satisfies **all** comparators of **any** ``||``-separated set::

    ^1.2.3          ->  >=1.2.3 <2.0.0-0
    ~1.2            ->  >=1.2.0 <1.3.0-0
    1.x             ->  >=1.0.0 <2.0.0-0
    1.2.3 - 2.3     ->  >=1.2.3 <2.4.0-0
    >=1 <2 || ^3    ->  two sets

(``-0`` is the lowest possible prerelease, so ``<2.0.0-0`` excludes
``2.0.0-beta`` as well as ``2.0.0``.)

Prerelease rule (npm's): ``1.3.0-beta`` only satisfies a range if some
comparator in the same set mentions a prerelease of ``1.3.0`` itself. This
stops ``^1.2.0`` from picking an unstable ``1.3.0-beta``.

Anything unusual raises :class:`UnsupportedRange`; we never *guess* a version.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import total_ordering


class UnsupportedRange(ValueError):
    """The range uses syntax this matcher does not understand."""


_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
# A partial version inside a range: "1", "1.2", "1.2.3", "1.x", "*", "1.2.3-beta".
_PARTIAL_RE = re.compile(
    r"^v?(?P<major>\d+|[xX*])(?:\.(?P<minor>\d+|[xX*]))?(?:\.(?P<patch>\d+|[xX*]))?"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)
_COMPARATOR_RE = re.compile(r"^(?P<op><=|>=|<|>|=|\^|~>|~)?\s*(?P<ver>.+)$")


@total_ordering
@dataclass(frozen=True)
class SemVer:
    """A full semantic version, comparable with ``<`` / ``==``."""

    major: int
    minor: int
    patch: int
    prerelease: tuple[int | str, ...] = ()

    @classmethod
    def parse(cls, text: str) -> SemVer:
        match = _VERSION_RE.match(text.strip())
        if not match:
            raise ValueError(f"not a semantic version: {text!r}")
        major, minor, patch, pre = match.groups()
        return cls(int(major), int(minor), int(patch), _parse_pre(pre))

    def __lt__(self, other: SemVer) -> bool:
        if (self.major, self.minor, self.patch) != (other.major, other.minor, other.patch):
            return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)
        # A release is *greater* than any of its prereleases: 1.0.0 > 1.0.0-rc.1
        if not self.prerelease or not other.prerelease:
            return bool(self.prerelease) and not other.prerelease
        return _pre_key(self.prerelease) < _pre_key(other.prerelease)

    @property
    def core(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)


def _parse_pre(pre: str | None) -> tuple[int | str, ...]:
    if not pre:
        return ()
    return tuple(int(p) if p.isdigit() else p for p in pre.split("."))


def _pre_key(pre: tuple[int | str, ...]) -> tuple:
    # Numeric identifiers sort before alphanumeric ones (semver §11.4.3).
    return tuple((0, p, "") if isinstance(p, int) else (1, 0, p) for p in pre)


@dataclass(frozen=True)
class _Comparator:
    op: str  # one of ">=", ">", "<", "<=", "="
    version: SemVer

    def test(self, v: SemVer) -> bool:
        if self.op == "=":
            return v == self.version
        if self.op == ">=":
            return v >= self.version
        if self.op == ">":
            return v > self.version
        if self.op == "<":
            return v < self.version
        return v <= self.version


def _zero_pre() -> tuple[int, ...]:
    return (0,)


def _expand(op: str, text: str) -> list[_Comparator]:
    """Desugar one comparator such as ``^1.2`` into primitive comparators."""
    match = _PARTIAL_RE.match(text)
    if not match:
        raise UnsupportedRange(f"cannot parse version {text!r}")

    def num(group: str) -> int | None:
        value = match.group(group)
        return None if value is None or value in "xX*" else int(value)

    major, minor, patch = num("major"), num("minor"), num("patch")
    pre = _parse_pre(match.group("pre"))
    # Normalise "1.x.3" style nonsense: anything after a wildcard is a wildcard.
    if major is None:
        minor = patch = None
    elif minor is None:
        patch = None

    def v(ma: int, mi: int, pa: int, pr: tuple = ()) -> SemVer:
        return SemVer(ma, mi, pa, pr)

    if major is None:  # "*", "x"
        return (
            []
            if op in ("", "=", ">=", "<=", "^", "~", "~>")
            else [_Comparator("<", v(0, 0, 0, _zero_pre()))]
        )

    if op == "^":
        low = v(major, minor or 0, patch or 0, pre)
        if major > 0 or minor is None:
            high = v(major + 1, 0, 0, _zero_pre())
        elif minor > 0 or patch is None:
            high = v(0, minor + 1, 0, _zero_pre())
        else:
            high = v(0, 0, patch + 1, _zero_pre())
        return [_Comparator(">=", low), _Comparator("<", high)]

    if op in ("~", "~>"):
        low = v(major, minor or 0, patch or 0, pre)
        high = (
            v(major + 1, 0, 0, _zero_pre())
            if minor is None
            else v(major, minor + 1, 0, _zero_pre())
        )
        return [_Comparator(">=", low), _Comparator("<", high)]

    if minor is None or patch is None:  # partial version with a plain operator
        low = v(major, minor or 0, 0)
        high = (
            v(major + 1, 0, 0, _zero_pre())
            if minor is None
            else v(major, minor + 1, 0, _zero_pre())
        )
        if op in ("", "="):
            return [_Comparator(">=", low), _Comparator("<", high)]
        if op == ">=":
            return [_Comparator(">=", low)]
        if op == ">":
            # ">1.2" means "1.3.0 or later"; no "-0" here, or 1.3.0-beta would sneak in.
            return [_Comparator(">=", v(high.major, high.minor, 0))]
        if op == "<":
            return [_Comparator("<", v(low.major, low.minor, 0, _zero_pre()))]
        return [_Comparator("<", high)]  # "<="

    full = v(major, minor, patch, pre)
    return [_Comparator(op or "=", full)]


def _parse_set(text: str) -> list[_Comparator]:
    """Parse one ``||``-free comparator set (may be a hyphen range)."""
    text = text.strip()
    hyphen = re.fullmatch(r"(\S+)\s+-\s+(\S+)", text)
    if hyphen:
        low_text, high_text = hyphen.groups()
        lows = _expand(">=", low_text)
        high_match = _PARTIAL_RE.match(high_text)
        if not high_match:
            raise UnsupportedRange(f"cannot parse version {high_text!r}")
        # A partial upper bound includes everything that starts with it:
        # "1.2.3 - 2.3" means "<2.4.0-0".
        highs = _expand("<=", high_text)
        return lows + highs

    # Allow "> = 1.2" style spacing by gluing operators to their versions.
    tokens = re.sub(r"(<=|>=|<|>|=|\^|~>|~)\s+", r"\1", text).split()
    comparators: list[_Comparator] = []
    for token in tokens:
        m = _COMPARATOR_RE.match(token)
        if not m:
            raise UnsupportedRange(f"cannot parse comparator {token!r}")
        comparators += _expand(m.group("op") or "", m.group("ver"))
    return comparators


def parse_range(text: str) -> list[list[_Comparator]]:
    """Parse a full range into a list of comparator sets (joined by ``||``)."""
    text = text.strip()
    if text in ("", "*", "x", "X", "latest"):
        return [[]]
    return [_parse_set(part) for part in text.split("||")]


def _set_allows(comparators: list[_Comparator], v: SemVer) -> bool:
    if not all(c.test(v) for c in comparators):
        return False
    if v.prerelease:
        # npm's prerelease rule (see module docstring).
        return any(c.version.prerelease and c.version.core == v.core for c in comparators)
    return True


def satisfies(version: str, range_text: str) -> bool:
    """True if ``version`` is inside ``range_text``.

    >>> satisfies("4.17.21", "^4.17.0")
    True
    >>> satisfies("5.0.0", "^4.17.0")
    False
    """
    try:
        v = SemVer.parse(version)
    except ValueError:
        return False
    return any(_set_allows(s, v) for s in parse_range(range_text))


def max_satisfying(versions: Iterable[str], range_text: str) -> str | None:
    """Highest version in ``versions`` that satisfies ``range_text`` (or ``None``).

    Raises:
        UnsupportedRange: if ``range_text`` cannot be parsed.
    """
    sets = parse_range(range_text)
    best: tuple[SemVer, str] | None = None
    for text in versions:
        try:
            v = SemVer.parse(text)
        except ValueError:
            continue
        if any(_set_allows(s, v) for s in sets) and (best is None or v > best[0]):
            best = (v, text)
    return best[1] if best else None
