"""Shared pytest fixtures."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

from agent_sandbox import Policy
from agent_sandbox.testing import FakeProcessRunner


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """A project root inside the temporary directory."""
    path = tmp_path / "root"
    path.mkdir()
    return path


@pytest.fixture
def policy(root: Path) -> Policy:
    """Policy allowing only the running interpreter, confined to ``root``."""
    return Policy(allowed_executables=frozenset({Path(sys.executable)}), allowed_roots=(root,))


@pytest.fixture
def loose(policy: Policy) -> Policy:
    """Same policy, but interpreter snippets may contain shell metacharacters."""
    return replace(policy, reject_shell_metacharacters=False)


@pytest.fixture
def fake() -> FakeProcessRunner:
    """A fresh fake runner."""
    return FakeProcessRunner()
