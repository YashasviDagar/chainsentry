"""CVSS v3.x base-score calculator.

OSV records publish severity as a CVSS *vector string*, not a number::

    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H   ->  9.8 (CRITICAL)

so we compute the score ourselves, following the formulas in the official
specification: https://www.first.org/cvss/v3.1/specification-document (§7).

Metric cheat-sheet (worth memorising for interviews)
----------------------------------------------------
Exploitability - *how hard is it to attack?*
    AV  Attack Vector        N(etwork) A(djacent) L(ocal) P(hysical)
    AC  Attack Complexity    L(ow) H(igh)
    PR  Privileges Required  N(one) L(ow) H(igh)
    UI  User Interaction     N(one) R(equired)
Scope
    S   U(nchanged) / C(hanged) - can the attack break out of the vulnerable
        component (e.g. sandbox escape)?
Impact - *what happens if it succeeds?* (CIA triad)
    C / I / A  Confidentiality, Integrity, Availability: H(igh) L(ow) N(one)

LIMITATION: only the *base* score is computed. Temporal (exploit maturity)
and environmental (your deployment) metrics can lower or raise real risk.
CVSS v4 vectors use a lookup-table algorithm and are not computed here;
the OSV check falls back to the advisory's own severity label for those.
"""

from __future__ import annotations

import math

from chainsentry.models import Severity

# Numeric weights from the CVSS v3.1 specification, table 16.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
# Privileges matter less when the attack escapes its scope.
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse_vector(vector: str) -> dict[str, str]:
    """Split ``"CVSS:3.1/AV:N/..."`` into ``{"AV": "N", ...}``.

    Raises:
        ValueError: if it is not a complete CVSS v3.0/v3.1 vector.
    """
    parts = vector.strip().split("/")
    if not parts or parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        raise ValueError(f"not a CVSS v3 vector: {vector!r}")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        if not sep:
            raise ValueError(f"malformed metric {part!r} in {vector!r}")
        metrics[key] = value
    missing = [m for m in _REQUIRED if m not in metrics]
    if missing:
        raise ValueError(f"vector {vector!r} is missing {', '.join(missing)}")
    return metrics


def roundup(value: float) -> float:
    """Round *up* to one decimal, as defined in CVSS v3.1 Appendix A.

    The spec works on integers to avoid floating-point surprises such as
    ``math.ceil(4.0000000001 * 10)`` turning 4.0 into 4.1.
    """
    as_int = round(value * 100_000)
    if as_int % 10_000 == 0:
        return as_int / 100_000.0
    return (math.floor(as_int / 10_000) + 1) / 10.0


def base_score(vector: str) -> float:
    """Compute the CVSS v3.x base score (0.0-10.0) for ``vector``.

    >>> base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    9.8

    Raises:
        ValueError: on an invalid vector or unknown metric value.
    """
    m = parse_vector(vector)
    try:
        changed = m["S"] == "C"
        if m["S"] not in ("U", "C"):
            raise KeyError("S")
        av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError as exc:
        raise ValueError(f"invalid metric value in {vector!r}") from exc

    # Impact Sub-Score: 1 minus the chance that *nothing* is impacted.
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def severity_from_score(score: float) -> Severity:
    """Map a 0-10 score to the CVSS qualitative rating scale.

    0.1-3.9 LOW · 4.0-6.9 MEDIUM · 7.0-8.9 HIGH · 9.0-10.0 CRITICAL.
    (CVSS calls 0.0 "None"; we report it as LOW since a vulnerability was
    still published.)
    """
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW
