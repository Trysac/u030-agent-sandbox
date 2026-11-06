# Testing

## Running

```sh
uv run pytest --cov=agent_sandbox   # tests with coverage report
uv run python scripts/check.py      # every gate, as CI runs it
```

## What the tests cover

The tests run `sys.executable -c` snippets for real processes, and use `FakeProcessRunner` where no process should start. They cover:

- Policy validation: absolute paths, positive timeout and audit size, executables not inside roots (`invalid_policy`).
- Each ordered denial reason: `binary_not_allowed`, `relative_executable`, `executable_in_roots`, `path_outside_roots`, `shell_metacharacters`, `use_argv_list`, `argv_too_long`, `empty_command`.
- PATH resolution through `shutil.which` and planted binaries.
- Process-tree timeout: a grandchild inheriting stdout is killed and `timed_out=True` is returned.
- Output capping, `truncated` flag and `errors=replace` decoding.
- Environment scrubbing and secret-name detection, argv redaction and audit-log bounds.
- Event callbacks: exceptions raised by `on_event` are swallowed.

## Policy

- Branch coverage of `src/agent_sandbox` must stay at or above 80 %; the gate fails below it.
- Tests exercise the public API (`import agent_sandbox`) and assert return values, raised exceptions and their messages.
- Tests are intended to be deterministic: no network and no dependence on test order.

## Layout

`tests/test_<module>.py` mirrors each public module. Shared fixtures go in `tests/conftest.py`.
