"""Tests for the command-line interface (cli.py)."""

import pytest

from chainsentry import __version__
from chainsentry.cli import EXIT_ERROR, EXIT_OK, main


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
        assert "12 dependencies" in out

    def test_direct_only_hides_transitive(self, demo_dir, capsys):
        main(["deps", str(demo_dir), "--direct-only"])
        out = capsys.readouterr().out
        assert "debug" not in out  # transitive dependency of express
        assert "showing 11 after filters" in out

    def test_no_dev_hides_dev_dependencies(self, demo_dir, capsys):
        main(["deps", str(demo_dir), "--no-dev"])
        assert "minimist" not in capsys.readouterr().out

    def test_missing_path_returns_error_code(self, tmp_path, capsys):
        assert main(["deps", str(tmp_path / "missing")]) == EXIT_ERROR
        assert "error:" in capsys.readouterr().out
