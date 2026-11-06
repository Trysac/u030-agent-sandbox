# agent-sandbox

[![PyPI version](https://img.shields.io/pypi/v/trysac-agent-sandbox)](https://pypi.org/project/trysac-agent-sandbox/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-agent-sandbox)](LICENSE)
[![CI](https://github.com/Trysac/u030-agent-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u030-agent-sandbox/actions/workflows/ci.yml)

Policy guard for agent shell commands: allow-listed absolute executables, path roots, process-tree timeout, capped output and scrubbed environment.

> **Threat model: a policy guard, not a security boundary.** Real isolation needs containers.
>
> Defended:
> - unlisted binaries
> - binaries planted in the workspace
> - PATH hijack
> - paths outside the allowed roots
> - environment secret leakage
> - runaway time and output
>
> Not defended:
> - interpreters or shells in the allow list grant arbitrary code execution
> - path checks are TOCTOU-racy
> - memory, CPU and network are not limited (needs containers)
> - semantics of allowed tools (`git -c`, `find -exec`)

## Problem

Agents that run shell commands can hang, flood output, read secrets from the environment, run a binary they just wrote or wander outside the project. Most tools lack even a policy layer in front of `subprocess`. This library is that layer: a deterministic policy check plus a guarded runner that kills the whole process tree, with its limits stated plainly.

## Install

```sh
pip install trysac-agent-sandbox
# or
uv add trysac-agent-sandbox
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import sys, tempfile
from pathlib import Path
from agent_sandbox import Policy, Sandbox

root = Path(tempfile.mkdtemp())
policy = Policy(frozenset({Path(sys.executable)}), (root,), timeout_seconds=5)
result = Sandbox(policy).run([sys.executable, "-c", "print('hello')"], cwd=root)
print(result.exit_code, result.stdout.strip())
print(Sandbox(policy).check(["curl", "x"], cwd=root).reason)
```

## Public API

- `Policy(allowed_executables, allowed_roots, timeout_seconds=30.0, max_output_bytes=1_000_000, env_allow=..., reject_shell_metacharacters=True, max_audit_entries=1000)`: frozen, validated on construction. Invalid values raise `SandboxError` with code `invalid_policy` (non-absolute paths, non-positive timeout, executable inside a root).
- `Sandbox(policy, runner=None, clock=time.monotonic, on_event=None)`: `check(command, cwd) -> Decision` decides without executing; `run(command, cwd) -> RunResult` raises `PolicyViolation` when denied; `audit() -> list[Decision]`.
- `Decision(allowed, reason, argv)`: `argv` is redacted.
- `RunResult(exit_code, stdout, stderr, timed_out, truncated, duration_seconds)`.
- `ProcessRunner` protocol and `SubprocessRunner` (default). `FakeProcessRunner` is in `agent_sandbox.testing`.
- Errors: `SandboxError` (with `code`), `PolicyViolation` (with `reason`). Denial reasons: `empty_command`, `argv_too_long`, `use_argv_list`, `shell_metacharacters`, `relative_executable`, `binary_not_allowed`, `executable_in_roots`, `path_outside_roots`. `spawn_failed` and `invalid_command` are also raised.
- Limits: 256 argv elements, 4096 characters per argument, 32 KiB per string command, `max_output_bytes` per stream, `timeout_seconds` per run.
- Options: see `Policy` fields above; `env_allow` lists the only environment names the child may inherit, and secret-like names are dropped even when listed.

## Why not subprocess with a timeout?

A plain `subprocess.run` call with a timeout does not check which binary runs, does not confine paths, does not scrub the environment and does not kill grandchild processes. This library adds those checks around the same mechanism.

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for the full threat model and limits.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
