"""Environment scrubbing."""

from __future__ import annotations

import os
from collections.abc import Mapping

from .redaction import is_secret_name


def _fold(name: str) -> str:
    return name.upper() if os.name == "nt" else name


def scrub_env(allow: frozenset[str], source: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return the variables of ``source`` (default ``os.environ``) the child may inherit.

    A variable survives only when its name is in ``allow`` and is not secret-like. Names are
    compared case-insensitively on Windows only.
    """
    environment = os.environ if source is None else source
    allowed = {_fold(name) for name in allow}
    return {
        key: value
        for key, value in environment.items()
        if _fold(key) in allowed and not is_secret_name(key)
    }
