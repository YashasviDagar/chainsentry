"""Tests for the command-line interface (cli.py)."""

import pytest

from chainsentry import __version__
from chainsentry.cli import EXIT_OK, main


def test_version_flag_prints_version(capsys):
    # argparse's "version" action prints and then raises SystemExit(0).
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_command_prints_help(capsys):
    assert main([]) == EXIT_OK
    assert "usage: chainsentry" in capsys.readouterr().out
