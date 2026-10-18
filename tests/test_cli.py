"""Tests for the command-line interface (cli.py)."""

import pytest

from chainsentry import __version__
from chainsentry.cli import EXIT_ERROR, EXIT_OK, EXIT_RISK, main


def test_version_flag_prints_version(capsys):
    # argparse's "version" action prints and then raises SystemExit(0).
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_command_prints_help(capsys):
    assert main([]) == EXIT_OK
    assert "usage: chainsentry" in capsys.readouterr().out


class TestDepsCommand:
    def test_lists_demo_dependencies(self, demo_dir, capsys):
        assert main(["deps", str(demo_dir)]) == EXIT_OK
        out = capsys.readouterr().out
        assert "lodash" in out
        assert "django" in out
        assert "13 dependencies" in out

    def test_direct_only_hides_transitive(self, demo_dir, capsys):
        main(["deps", str(demo_dir), "--direct-only"])
        out = capsys.readouterr().out
        assert "debug" not in out  # transitive dependency of express
        assert "showing 12 after filters" in out

    def test_no_dev_hides_dev_dependencies(self, demo_dir, capsys):
        main(["deps", str(demo_dir), "--no-dev"])
        assert "minimist" not in capsys.readouterr().out

    def test_missing_path_returns_error_code(self, tmp_path, capsys):
        assert main(["deps", str(tmp_path / "missing")]) == EXIT_ERROR
        assert "error:" in capsys.readouterr().out


class TestScanCommand:
    """`scan` runs offline here (typosquat + parser checks only), so no network is used."""

    def run(self, demo_dir, *extra: str) -> int:
        return main(["scan", str(demo_dir), "--offline", "--no-cache", *extra])

    def test_default_threshold_passes_offline_demo(self, demo_dir, capsys):
        assert self.run(demo_dir) == EXIT_OK
        assert "ChainSentry" in capsys.readouterr().out

    def test_fail_on_medium_fails(self, demo_dir, capsys):
        # colourama's typosquat finding alone is MEDIUM (30 points).
        assert self.run(demo_dir, "--fail-on", "medium") == EXIT_RISK
        assert "FAIL:" in capsys.readouterr().out

    def test_fail_on_none_never_fails(self, demo_dir):
        assert self.run(demo_dir, "--fail-on", "none") == EXIT_OK

    def test_min_score(self, demo_dir):
        assert self.run(demo_dir, "--fail-on", "none", "--min-score", "1") == EXIT_RISK

    def test_writes_requested_formats(self, demo_dir, tmp_path):
        out = tmp_path / "reports"
        self.run(demo_dir, "-f", "json", "-f", "sbom", "-f", "markdown", "-o", str(out))
        assert sorted(p.name for p in out.iterdir()) == [
            "report.json",
            "report.md",
            "sbom.cdx.json",
        ]

    def test_parse_error_exit_code(self, tmp_path):
        assert main(["scan", str(tmp_path / "nope"), "--offline"]) == EXIT_ERROR
