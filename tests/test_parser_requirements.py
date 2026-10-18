"""Tests for the requirements.txt parser (parsers/pip_requirements.py)."""

from __future__ import annotations

import pytest
from packaging.specifiers import SpecifierSet

from chainsentry.models import Ecosystem
from chainsentry.parsers.base import NON_REGISTRY_SOURCE, UNPINNED, ParseError
from chainsentry.parsers.pip_requirements import (
    exact_version,
    is_dev_requirements_file,
    parse_requirements,
)


def by_name(result):
    """Index a ParseResult's dependencies by name for easy assertions."""
    return {d.name: d for d in result.dependencies}


class TestBasicLines:
    def test_pinned_requirement(self, write):
        result = parse_requirements(write("requirements.txt", "requests==2.31.0\n"))
        dep = by_name(result)["requests"]
        assert dep.version == "2.31.0"
        assert dep.ecosystem is Ecosystem.PYPI
        assert dep.direct and not dep.dev
        assert result.findings_for(dep) == []

    def test_comments_and_blank_lines_are_ignored(self, write):
        path = write(
            "requirements.txt",
            """
            # a full-line comment

            flask==3.0.0   # trailing comment
            """,
        )
        assert list(by_name(parse_requirements(path))) == ["flask"]

    def test_name_is_pep503_normalised(self, write):
        path = write("requirements.txt", "Flask_Login==0.6.3\n")
        assert "flask-login" in by_name(parse_requirements(path))

    def test_extras_and_markers_are_understood(self, write):
        path = write("requirements.txt", 'urllib3[socks]==1.26.4 ; python_version >= "3.6"\n')
        assert by_name(parse_requirements(path))["urllib3"].version == "1.26.4"

    def test_line_continuation_with_hash(self, write):
        path = write(
            "requirements.txt",
            """
            pyyaml==6.0.1 \\
                --hash=sha256:abc123
            """,
        )
        result = parse_requirements(path)
        assert by_name(result)["pyyaml"].version == "6.0.1"
        assert result.warnings == []

    def test_version_is_normalised(self, write):
        path = write("requirements.txt", "django==3.2.00\n")
        assert by_name(parse_requirements(path))["django"].version == "3.2.0"


class TestPinning:
    @pytest.mark.parametrize(
        ("spec", "expected"),
        [
            ("==2.31.0", "2.31.0"),
            ("===2.31.0-custom", "2.31.0-custom"),
            ("==2.*", None),  # wildcard = many versions
            (">=2.0", None),
            ("~=2.31", None),
            (">=2.0,<3", None),
            ("", None),
        ],
    )
    def test_exact_version(self, spec, expected):
        assert exact_version(SpecifierSet(spec)) == expected

    def test_range_produces_unpinned_finding(self, write):
        result = parse_requirements(write("requirements.txt", "requests>=2.0\n"))
        dep = by_name(result)["requests"]
        assert dep.version is None
        assert dep.spec == ">=2.0"
        assert [f.code for f in result.findings_for(dep)] == [UNPINNED]

    def test_no_version_at_all_is_unpinned(self, write):
        result = parse_requirements(write("requirements.txt", "requests\n"))
        assert [f.code for f in result.findings_for(by_name(result)["requests"])] == [UNPINNED]


class TestNonIndexSources:
    def test_direct_url_reference_is_flagged(self, write):
        path = write("requirements.txt", "mylib @ git+https://github.com/org/mylib@v1\n")
        result = parse_requirements(path)
        dep = by_name(result)["mylib"]
        assert dep.version is None
        assert [f.code for f in result.findings_for(dep)] == [NON_REGISTRY_SOURCE]

    def test_bare_url_line_is_skipped_with_warning(self, write):
        path = write("requirements.txt", "https://example.com/pkg-1.0.whl\n")
        result = parse_requirements(path)
        assert result.dependencies == []
        assert "installs from a path/URL" in result.warnings[0]

    def test_editable_is_skipped_with_warning(self, write):
        result = parse_requirements(write("requirements.txt", "-e .\n"))
        assert result.dependencies == []
        assert "editable" in result.warnings[0]

    def test_invalid_line_is_a_warning_not_a_crash(self, write):
        result = parse_requirements(write("requirements.txt", "this is not valid!!\nflask==3.0\n"))
        assert list(by_name(result)) == ["flask"]
        assert "invalid requirement" in result.warnings[0]


class TestSecurityOptions:
    def test_extra_index_url_warns_about_dependency_confusion(self, write):
        result = parse_requirements(
            write("requirements.txt", "--extra-index-url https://pypi.corp.example/simple\n")
        )
        assert "dependency confusion" in result.warnings[0]

    def test_credentials_in_index_url_are_redacted(self, write):
        result = parse_requirements(
            write(
                "requirements.txt",
                "--extra-index-url https://user:SuperSecret@pypi.corp.example/simple\n",
            )
        )
        assert "SuperSecret" not in result.warnings[0]
        assert "***@pypi.corp.example" in result.warnings[0]

    def test_trusted_host_warns(self, write):
        result = parse_requirements(write("requirements.txt", "--trusted-host pypi.corp.example\n"))
        assert "TLS" in result.warnings[0]

    def test_official_index_url_does_not_warn(self, write):
        result = parse_requirements(write("requirements.txt", "-i https://pypi.org/simple\n"))
        assert result.warnings == []


class TestIncludes:
    def test_dash_r_include_is_followed(self, write):
        write("base.txt", "requests==2.31.0\n")
        main = write("requirements.txt", "-r base.txt\nflask==3.0.0\n")
        result = parse_requirements(main)
        assert set(by_name(result)) == {"requests", "flask"}
        assert result.files == ["requirements.txt", "base.txt"]

    def test_glued_short_option(self, write):
        write("base.txt", "requests==2.31.0\n")
        main = write("requirements.txt", "-rbase.txt\n")
        assert "requests" in by_name(parse_requirements(main))

    def test_circular_include_terminates(self, write):
        write("a.txt", "-r b.txt\nflask==3.0.0\n")
        write("b.txt", "-r a.txt\nrequests==2.31.0\n")
        result = parse_requirements(write("requirements.txt", "-r a.txt\n"))
        assert set(by_name(result)) == {"flask", "requests"}
        assert any("circular" in w for w in result.warnings)

    def test_include_outside_project_is_refused(self, write, tmp_path):
        # SECURITY: a manifest must not make us read arbitrary files.
        project = tmp_path / "project"
        write("secret.txt", "leaked==1.0\n")
        main = write("project/requirements.txt", "-r ../secret.txt\n")
        result = parse_requirements(main, root=project)
        assert result.dependencies == []
        assert "outside the project" in result.warnings[0]

    def test_remote_include_is_not_downloaded(self, write):
        result = parse_requirements(write("requirements.txt", "-r https://evil.example/reqs.txt\n"))
        assert "not followed" in result.warnings[0]

    def test_missing_include_warns(self, write):
        result = parse_requirements(write("requirements.txt", "-r nope.txt\n"))
        assert "not found" in result.warnings[0]

    def test_dev_flag_inherited_by_included_file(self, write):
        write("common.txt", "requests==2.31.0\n")
        result = parse_requirements(write("requirements-dev.txt", "-r common.txt\n"))
        assert by_name(result)["requests"].dev is True


class TestDevDetection:
    @pytest.mark.parametrize(
        ("name", "is_dev"),
        [
            ("requirements.txt", False),
            ("requirements-dev.txt", True),
            ("dev-requirements.txt", True),
            ("requirements_test.txt", True),
            ("requirements/docs.txt", True),
            ("requirements-prod.txt", False),
        ],
    )
    def test_dev_file_names(self, tmp_path, name, is_dev):
        assert is_dev_requirements_file(tmp_path / name) is is_dev


class TestFileLevelErrors:
    def test_missing_file_raises_parse_error(self, tmp_path):
        with pytest.raises(ParseError):
            parse_requirements(tmp_path / "nope.txt")

    def test_utf8_bom_is_tolerated(self, tmp_path):
        # Windows Notepad / PowerShell often save files with a BOM.
        path = tmp_path / "requirements.txt"
        path.write_bytes("﻿requests==2.31.0\n".encode())
        assert "requests" in by_name(parse_requirements(path))

    def test_non_utf8_file_raises_parse_error(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_bytes(b"\xff\xfe\x00bad")
        with pytest.raises(ParseError, match="UTF-8"):
            parse_requirements(path)
