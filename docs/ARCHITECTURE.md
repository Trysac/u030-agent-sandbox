# Architecture

## Purpose

`trysac-agent-sandbox` is a small, dependency-free Python package (import name `agent_sandbox`) that acts as a policy guard for agent shell commands. A deterministic check allows or denies a command before it runs; an allowed command runs with a scrubbed environment, a wall-clock timeout that kills the process tree, and capped output.

## Modules

- `models.py`: `Policy`, `Decision`, `RunResult`, `DEFAULT_ENV_ALLOW`; validation of policy values.
- `sandbox.py`: `Sandbox`, the ordered checks (`check`), execution (`run`), the bounded audit log and `on_event` callbacks.
- `runner.py`: `ProcessRunner` protocol and `SubprocessRunner`, which uses `shell=False`, its own process group (POSIX) or tree kill (Windows), two reader threads and bounded joins.
- `paths.py`: canonical comparison (`normcase(realpath)`) and containment (`commonpath`).
- `environment.py`: `scrub_env`, which keeps only allow-listed, non-secret variables.
- `redaction.py`: `is_secret_name` and `redact_argv` for audit records.
- `errors.py`: `SandboxError` and `PolicyViolation`, with stable codes and reasons.
- `testing.py`: `FakeProcessRunner` and `RecordedCall` for tests without starting processes.

## Shape

```text
caller --> Sandbox.check / Sandbox.run
              |
              +-- ordered checks (sandbox.py, paths.py, redaction.py)
              +-- scrub_env (environment.py)
              +-- ProcessRunner.run (runner.py)
              +-- audit log and on_event (redacted Decision)
```

- **Public API**: the names listed in `__all__` of `src/agent_sandbox/__init__.py`.
- **Errors**: `SandboxError` carries a `code`; `PolicyViolation` carries a `reason`.
- **Logging**: a logger named `agent_sandbox.runner` and `agent_sandbox.sandbox` with a `NullHandler` on the package logger.

## Quality contract

`scripts/check.py` defines the gates; see [TESTING.md](TESTING.md).

## Decisions

Architecture decisions are recorded in [decisions/](decisions/) as numbered ADRs.
