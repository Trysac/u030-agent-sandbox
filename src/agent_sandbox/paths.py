"""Path helpers: canonical comparison and containment."""

from __future__ import annotations

import os
from collections.abc import Iterable


def normalize(path: str | os.PathLike[str]) -> str:
    """Return ``os.path.normcase(os.path.realpath(path))``."""
    return os.path.normcase(os.path.realpath(path))


def _contains(root: str, path: str) -> bool:
    try:
        return os.path.commonpath([root, path]) == root
    except ValueError:
        return False


def is_inside(path: str, roots: Iterable[str]) -> bool:
    """Return whether the normalized ``path`` lies inside one of the normalized ``roots``."""
    return any(_contains(root, path) for root in roots)


def has_separator(value: str) -> bool:
    """Return whether ``value`` contains a path separator of this platform."""
    if "/" in value or os.sep in value:
        return True
    return os.altsep is not None and os.altsep in value
