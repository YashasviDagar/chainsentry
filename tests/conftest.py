"""Shared pytest fixtures.

Most parser tests write a tiny manifest into pytest's ``tmp_path`` (a fresh
temporary directory per test) so the input is visible right next to the
assertion. The realistic demo project lives in ``tests/fixtures/demo``.
"""

from __future__ import annotations

import json
import textwrap
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def demo_dir() -> Path:
    """Path to the deliberately risky demo project."""
    return FIXTURES / "demo"


@pytest.fixture
def write(tmp_path: Path) -> Callable[[str, str], Path]:
    """Return a helper that writes ``content`` to ``tmp_path / name``.

    The content is dedented, so tests can indent multi-line strings naturally.
    """

    def _write(name: str, content: str) -> Path:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
        return path

    return _write


@pytest.fixture
def write_json(tmp_path: Path) -> Callable[[str, Any], Path]:
    """Return a helper that writes a Python object as JSON to ``tmp_path / name``."""

    def _write_json(name: str, data: Any) -> Path:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    return _write_json
