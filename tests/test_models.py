"""Tests for the shared data model (models.py)."""

from chainsentry.models import Dependency, Ecosystem, Severity


def _dep(name: str, version: str | None, eco: Ecosystem = Ecosystem.NPM) -> Dependency:
    """Small factory so each test only states what it cares about."""
    return Dependency(name=name, version=version, spec=None, ecosystem=eco, source_file="x")


class TestPurl:
    def test_plain_npm_package(self):
        assert _dep("lodash", "4.17.21").purl == "pkg:npm/lodash@4.17.21"

    def test_scoped_npm_package_encodes_at_sign(self):
        # The purl spec requires the '@' of an npm scope to be percent-encoded.
        assert _dep("@babel/core", "7.24.0").purl == "pkg:npm/%40babel/core@7.24.0"

    def test_pypi_package(self):
        assert _dep("requests", "2.31.0", Ecosystem.PYPI).purl == "pkg:pypi/requests@2.31.0"

    def test_without_version_omits_at(self):
        assert _dep("requests", None, Ecosystem.PYPI).purl == "pkg:pypi/requests"

    def test_prerelease_plus_sign_is_encoded(self):
        # '+' (semver build metadata) is not a safe purl character.
        assert _dep("pkg", "1.0.0+build.1").purl == "pkg:npm/pkg@1.0.0%2Bbuild.1"


class TestSeverity:
    def test_rank_orders_by_seriousness_not_alphabet(self):
        ordered = sorted(Severity, key=lambda s: s.rank)
        assert ordered == [
            Severity.UNKNOWN,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]

    def test_values_are_plain_strings(self):
        # StrEnum members serialise to JSON as their value without extra work.
        assert Severity.HIGH == "HIGH"


class TestEcosystem:
    def test_values_match_osv_names(self):
        # OSV is case-sensitive: it expects exactly "npm" and "PyPI".
        assert Ecosystem.NPM.value == "npm"
        assert Ecosystem.PYPI.value == "PyPI"


def test_dependency_is_hashable_and_immutable():
    dep = _dep("lodash", "4.17.21")
    assert {dep, dep} == {dep}  # usable in sets
    try:
        dep.name = "other"  # type: ignore[misc]
    except AttributeError:
        pass
    else:  # pragma: no cover - would mean frozen=True was removed
        raise AssertionError("Dependency should be frozen")
