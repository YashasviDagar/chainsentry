"""Tests for manifest discovery and project-level parsing (parsers/discovery.py)."""

from __future__ import annotations

import pytest

from chainsentry.parsers import ParseError, find_manifests, parse_project
from chainsentry.parsers.base import NON_REGISTRY_SOURCE, NPM_ALIAS, UNPINNED


def names(result):
    return {d.name for d in result.dependencies}


class TestFindManifests:
    def test_top_level_only_by_default(self, write, tmp_path):
        write("requirements.txt", "")
        write("sub/package.json", "{}")
        assert [p.name for p in find_manifests(tmp_path)] == ["requirements.txt"]

    def test_recursive_skips_node_modules_and_venvs(self, write, tmp_path):
        write("package.json", "{}")
        write("web/package.json", "{}")
        write("node_modules/lodash/package.json", "{}")
        write(".venv/lib/requirements.txt", "")
        found = {
            p.relative_to(tmp_path).as_posix() for p in find_manifests(tmp_path, recursive=True)
        }
        assert found == {"package.json", "web/package.json"}

    def test_requirements_folder_is_recognised(self, write, tmp_path):
        write("requirements/base.txt", "")
        write("notes.txt", "")  # an unrelated .txt file must not be picked up
        found = {p.name for p in find_manifests(tmp_path, recursive=True)}
        assert found == {"base.txt"}


class TestParseProject:
    def test_lockfile_wins_over_package_json(self, write_json, tmp_path):
        write_json("package.json", {"dependencies": {"lodash": "^4.17.0"}})
        write_json(
            "package-lock.json",
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"lodash": "^4.17.0"}},
                    "node_modules/lodash": {"version": "4.17.21"},
                },
            },
        )
        result = parse_project(tmp_path)
        assert [(d.name, d.version) for d in result.dependencies] == [("lodash", "4.17.21")]
        assert result.files == ["package-lock.json"]

    def test_package_json_alone_warns_about_missing_lockfile(self, write_json, tmp_path):
        write_json("package.json", {"dependencies": {"lodash": "^4.17.0"}})
        result = parse_project(tmp_path)
        assert "no package-lock.json" in result.warnings[0]

    def test_shrinkwrap_takes_precedence(self, write_json, tmp_path):
        lock = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"version": "1.0.0"}}}
        shrink = {
            "lockfileVersion": 3,
            "packages": {"": {}, "node_modules/a": {"version": "2.0.0"}},
        }
        write_json("package-lock.json", lock)
        write_json("npm-shrinkwrap.json", shrink)
        assert parse_project(tmp_path).dependencies[0].version == "2.0.0"

    def test_prod_requirements_stay_prod_when_dev_file_includes_them(self, write, tmp_path):
        # Regression test: requirements-dev.txt sorts before requirements.txt,
        # and including the prod file must not mark prod packages as dev.
        write("requirements.txt", "django==4.2.0\n")
        write("requirements-dev.txt", "-r requirements.txt\npytest==8.0.0\n")
        deps = {d.name: d for d in parse_project(tmp_path).dependencies}
        assert deps["django"].dev is False
        assert deps["pytest"].dev is True

    def test_duplicate_warnings_are_reported_once(self, write, tmp_path):
        write("requirements.txt", "--trusted-host example.com\n")
        write("requirements-dev.txt", "-r requirements.txt\n")
        result = parse_project(tmp_path)
        assert len([w for w in result.warnings if "trusted-host" in w]) == 1

    def test_single_file_target(self, write, tmp_path):
        path = write("deps/prod.txt", "flask==3.0.0\n")
        assert names(parse_project(path)) == {"flask"}

    def test_explicit_package_json_warns_if_lockfile_exists(self, write_json, tmp_path):
        path = write_json("package.json", {"dependencies": {"a": "1.0.0"}})
        write_json("package-lock.json", {"lockfileVersion": 3})
        assert "lockfile exists" in parse_project(path).warnings[0]

    def test_empty_directory_warns(self, tmp_path):
        result = parse_project(tmp_path)
        assert result.dependencies == []
        assert "no supported manifest" in result.warnings[0]

    def test_missing_path_raises(self, tmp_path):
        with pytest.raises(ParseError, match="no such file"):
            parse_project(tmp_path / "missing")

    def test_unsupported_file_raises(self, write):
        with pytest.raises(ParseError, match="unsupported file type"):
            parse_project(write("Cargo.lock", ""))

    def test_broken_package_json_does_not_block_lockfile(self, write, write_json, tmp_path):
        write("package.json", "{ broken")
        write_json(
            "package-lock.json",
            {"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"version": "1.0.0"}}},
        )
        assert names(parse_project(tmp_path)) == {"a"}


def test_demo_project_end_to_end(demo_dir):
    """The demo fixture exercises every parser feature at once."""
    result = parse_project(demo_dir)
    deps = {d.name: d for d in result.dependencies}

    # npm side (from the lockfile)
    assert deps["lodash"].version == "4.17.15"
    assert not deps["debug"].direct  # transitive, nested under express
    assert deps["minimist"].dev
    assert NPM_ALIAS in [f.code for f in result.findings_for(deps["left-pad"])]
    assert NON_REGISTRY_SOURCE in [f.code for f in result.findings_for(deps["internal-lib"])]

    # PyPI side (requirements.txt + requirements-dev.txt)
    assert deps["django"].version == "3.2.0" and not deps["django"].dev
    assert deps["pytest"].dev
    assert "python-dateutil" in deps  # PEP 503-normalised from python_dateutil
    assert UNPINNED in [f.code for f in result.findings_for(deps["requests"])]

    # The extra index URL is flagged, with its credentials redacted.
    assert any("dependency confusion" in w for w in result.warnings)
    assert not any("s3cr3t" in w for w in result.warnings)
