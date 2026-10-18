"""Tests for typosquatting detection (checks/typosquat.py)."""

from __future__ import annotations

import pytest

from chainsentry.checks.typosquat import (
    TYPOSQUAT,
    TyposquatCheck,
    TyposquatDetector,
    classify_edit,
    collapse,
    damerau_levenshtein,
    default_detector,
    skeleton,
)
from chainsentry.models import Dependency, Ecosystem, PackageReport, Severity

NPM, PYPI = Ecosystem.NPM, Ecosystem.PYPI


@pytest.fixture
def detector() -> TyposquatDetector:
    """A tiny, predictable popularity list (rank = position)."""
    return TyposquatDetector(
        {
            NPM: ["lodash", "express", "cross-env", "@types/node", "react"],
            PYPI: ["requests", "python-dateutil", "jellyfish", "colorama", "six", "numpy"],
        },
        allowlist={"pypi:request"},
    )


class TestDamerauLevenshtein:
    @pytest.mark.parametrize(
        ("a", "b", "distance"),
        [
            ("requests", "requests", 0),
            ("reqeusts", "requests", 1),  # swap counts as ONE edit
            ("requets", "requests", 1),  # omission
            ("requestss", "requests", 1),  # insertion
            ("requesta", "requests", 1),  # substitution
            ("kitten", "sitting", 3),
            ("", "abc", 3),
        ],
    )
    def test_distances(self, a, b, distance):
        assert damerau_levenshtein(a, b) == distance

    def test_early_exit_caps_result(self):
        assert damerau_levenshtein("completely", "different", max_distance=1) == 2


@pytest.mark.parametrize(
    ("name", "target", "kind"),
    [
        ("reqeusts", "requests", "transposition"),
        ("requesta", "requests", "substitution"),
        ("requets", "requests", "omission"),
        ("requestss", "requests", "repeated character"),
        ("requesxts", "requests", "insertion"),
    ],
)
def test_classify_edit(name, target, kind):
    assert classify_edit(name, target) == kind


def test_skeleton_and_collapse():
    assert skeleton("jeilyfish") == skeleton("jellyfish")
    assert skeleton("rnodule") == skeleton("module")
    assert collapse("cross-env") == collapse("cross_env") == "crossenv"


class TestDetector:
    @pytest.mark.parametrize(
        ("name", "eco", "target", "technique"),
        [
            ("crossenv", NPM, "cross-env", "separator confusion"),
            ("jeIlyfish", PYPI, "jellyfish", "visual homoglyph"),  # capital I, 2019 attack
            ("rеquests", PYPI, "requests", "unicode homoglyph"),  # Cyrillic 'е'
            ("reqeusts", PYPI, "requests", "transposition"),
            ("lodahs", NPM, "lodash", "transposition"),
            ("python3-dateutil", PYPI, "python-dateutil", "insertion"),  # 2019 attack
            ("colourama", PYPI, "colorama", "insertion"),  # 2018 attack
            ("@typess/node", NPM, "@types/node", "repeated character"),
            ("requests-py", PYPI, "requests", "combosquatting"),
        ],
    )
    def test_known_attack_shapes_are_flagged(self, detector, name, eco, target, technique):
        match = detector.check(name, eco)
        assert match is not None
        assert (match.target, match.technique) == (target, technique)

    @pytest.mark.parametrize(
        ("name", "eco"),
        [
            ("requests", PYPI),  # the popular package itself
            ("Requests", PYPI),  # same project after normalisation
            ("python_dateutil", PYPI),  # PEP 503: identical project on PyPI
            ("lodash", NPM),
            ("my-company-utils", NPM),  # unrelated name
            ("sip", PYPI),  # 1 edit from "six" but too short to judge
            ("request", PYPI),  # allowlisted
        ],
    )
    def test_legitimate_names_are_not_flagged(self, detector, name, eco):
        assert detector.check(name, eco) is None

    def test_ecosystems_are_separate(self, detector):
        # "reqeusts" resembles a *PyPI* package; on npm there is no such target.
        assert detector.check("reqeusts", NPM) is None

    def test_strong_techniques_are_high_confidence(self, detector):
        assert detector.check("jeIlyfish", PYPI).confidence is Severity.HIGH

    def test_affix_is_medium_confidence(self, detector):
        assert detector.check("requests-py", PYPI).confidence is Severity.MEDIUM

    def test_most_popular_target_wins(self):
        detector = TyposquatDetector({NPM: ["react", "reach"]})
        assert detector.check("reacth", NPM).target == "react"


class TestBundledLists:
    """The shipped top-5,000 lists catch real historical attacks."""

    @pytest.mark.parametrize(
        ("name", "eco"),
        [("crossenv", NPM), ("jeIlyfish", PYPI), ("python3-dateutil", PYPI), ("colourama", PYPI)],
    )
    def test_real_incidents(self, name, eco):
        assert default_detector().check(name, eco) is not None

    @pytest.mark.parametrize(
        ("name", "eco"),
        [("react", NPM), ("express", NPM), ("django", PYPI), ("numpy", PYPI), ("flask", PYPI)],
    )
    def test_popular_packages_are_clean(self, name, eco):
        assert default_detector().check(name, eco) is None


def test_check_adds_findings(detector):
    bad = PackageReport(Dependency("crossenv", "6.1.1", None, NPM, "package-lock.json"))
    good = PackageReport(Dependency("lodash", "4.17.21", None, NPM, "package-lock.json"))
    assert TyposquatCheck(detector).run([bad, good]) == []
    assert [f.code for f in bad.findings] == [TYPOSQUAT]
    assert bad.findings[0].details["target"] == "cross-env"
    assert good.findings == []
