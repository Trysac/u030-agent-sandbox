"""Secret-name detection and argv redaction for audit records."""

from __future__ import annotations

import re
from collections.abc import Sequence

REDACTED = "[REDACTED]"

_NEEDLES = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTH")
_SEGMENTS = re.compile(r"[_-]")
_ASSIGNMENT = re.compile(r"^(-{0,2})([A-Za-z_][A-Za-z0-9_.-]*)=")
_FLAG = re.compile(r"--([A-Za-z0-9_.-]+)")
_MAX_ITEMS = 256
_MAX_SCAN = 4096
_MAX_AUDIT_CHARS = 200


def is_secret_name(name: str) -> bool:
    """Return whether an environment or option name looks like it holds a secret.

    The check is case-insensitive: the name contains KEY, TOKEN, SECRET, PASSWORD, PASSWD,
    CREDENTIAL or AUTH, or has PAT as a whole underscore-separated segment (a hyphen also
    separates segments). ``PATH`` and ``PATTERN`` are not secret.
    """
    upper = name.upper()
    return any(needle in upper for needle in _NEEDLES) or "PAT" in _SEGMENTS.split(upper)


def _redact_item(item: str) -> str:
    match = _ASSIGNMENT.match(item)
    if match is not None and is_secret_name(match.group(2)):
        return f"{match.group(1)}{match.group(2)}={REDACTED}"
    return item


def _is_secret_flag(item: str) -> bool:
    match = _FLAG.fullmatch(item)
    return match is not None and is_secret_name(match.group(1))


def redact_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """Return an audit-safe copy of ``argv``.

    The value of ``NAME=VALUE`` or ``--name=VALUE`` with a secret-like name and the element
    after a ``--flag`` with a secret-like name become ``[REDACTED]``. At most 256 elements are
    kept and each is cut to 200 characters.
    """
    items = [item[:_MAX_SCAN] for item in argv[:_MAX_ITEMS]]
    result: list[str] = []
    after_secret_flag = False
    for item in items:
        if after_secret_flag:
            result.append(REDACTED)
        else:
            result.append(_redact_item(item)[:_MAX_AUDIT_CHARS])
        after_secret_flag = _is_secret_flag(item)
    return tuple(result)
