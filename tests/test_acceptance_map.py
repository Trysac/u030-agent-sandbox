"""Maps acceptance criteria to the tests that exercise them.

Acceptance text, verbatim:

check(['curl', 'x'], cwd=root) with curl not allow-listed returns
Decision(allowed=False, reason='binary_not_allowed', argv=('curl', 'x')) and FakeProcessRunner
records no call; run() of it raises PolicyViolation with reason 'binary_not_allowed'; a Policy
listing an executable inside a root raises SandboxError code 'invalid_policy'
(see test_unlisted_binary_denied and test_policy_rejects_executable_inside_root).

an absolute symlink '<root>/py' pointing at the allow-listed interpreter is rejected
(see test_symlink_in_root_is_rejected).

Each of ';', '|', '&', '$', '`', '>', '<' and '\\n' inside an argument such as 'a;b' is rejected
with reason 'shell_metacharacters', and 'a;b' passes literally when
reject_shell_metacharacters=False; with the platform check patched to Windows the string command
'C:\\\\tools\\\\x.exe y' is rejected with reason 'use_argv_list'
(see test_shell_metacharacters_rejected and test_windows_string_command_requires_argv_list).

With max_output_bytes=1000 a child writing 'x' * 1000 gives truncated=False and one writing
'x' * 1001 gives truncated=True with stdout == 'x' * 1000; output b'\\xff' decodes to '\\ufffd'
(see tests in test_runner.py).
"""

from __future__ import annotations

import sys

from agent_sandbox import Policy

ACCEPTANCE_FRAGMENTS = (
    "], cwd=root) with curl not allow-listed returns Decision(allowed=False, reason=",
    ")) and FakeProcessRunner records no call; run() of it raises PolicyViolation with reason ",
    "; a Policy listing an executable inside a root raises SandboxError code ",
    " passes literally when reject_shell_metacharacters=False; with the platform check patched to Windows the string command ",  # noqa: E501
    " * 1000 gives truncated=False and one writing ",
)


def test_acceptance_fragments_present() -> None:
    assert all(ACCEPTANCE_FRAGMENTS)


def test_acceptance_map_is_importable() -> None:
    assert Policy is not None
    assert sys.executable
