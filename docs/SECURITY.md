# Security

`agent_sandbox` is a **policy guard, not a security boundary**. It puts a deterministic policy check and a guarded runner in front of `subprocess`. Real isolation of untrusted code needs containers or virtual machines.

## Threat model

The caller is an agent that proposes shell commands. The library decides, before anything runs, whether a command is acceptable, and then limits how it runs.

### Defended

- **Unlisted binaries**: only absolute executables in `Policy.allowed_executables` run; they are compared by `os.path.normcase(os.path.realpath(p))` (`binary_not_allowed`).
- **Binaries planted in the workspace**: an executable inside an allowed root is rejected (`executable_in_roots`), including a symlink inside a root that points to an allow-listed interpreter. A policy listing such an executable is invalid (`invalid_policy`).
- **PATH hijack**: a bare name is resolved with `shutil.which` on the scrubbed `PATH`; the command runs with argv[0] replaced by the real path only when it matches an allow-listed path. A planted program earlier on `PATH` is rejected (`binary_not_allowed`).
- **Relative executables**: a command such as `./tool` or `bin/tool` is rejected (`relative_executable`).
- **Paths outside the roots**: the working directory and every path-like argument (containing a separator, starting with `.` or `~`, or the value of `--opt=value`) must resolve inside an allowed root after `realpath`; `..`, `~` and symlinks pointing outside are rejected (`path_outside_roots`).
- **Shell metacharacters**: `; | & $ ` > <` and newline inside an argument are rejected (`shell_metacharacters`) when `reject_shell_metacharacters` is true. A NUL character is always rejected.
- **Environment secret leakage**: the child receives only variables listed in `env_allow` and never a secret-like name (contains KEY, TOKEN, SECRET, PASSWORD, PASSWD, CREDENTIAL or AUTH, or has PAT as a whole underscore-separated segment). Audit records and error messages redact `NAME=VALUE`, `--name=VALUE` and the value following a secret-like `--flag`.
- **Runaway time and output**: a wall-clock timeout kills the whole process group (POSIX, SIGKILL) or process tree (Windows, `taskkill /F /T`); output is capped per stream, the excess is drained and discarded, and reader threads are joined with a 5 second bound.

### Not defended

- Interpreters or shells in the allow list grant arbitrary code execution.
- Path checks are TOCTOU-racy: the file system can change between the check and the use.
- Memory, CPU and network are not limited. Use containers for that.
- The semantics of allowed tools are not inspected (`git -c`, `find -exec`, ...).
- Arguments such as `NAME=/path` or `-I/path` are not recognised as paths unless they are `--opt=value` or `-opt=value`.
- Redaction relies on names: a secret passed as a bare positional argument is not recognised.

## Limits enforced

| Input | Limit | Reason or effect |
|---|---|---|
| argv elements | 256 | `argv_too_long` |
| one argument | 4096 characters | `argv_too_long` |
| string command | 32 KiB | `argv_too_long` |
| audit log | `max_audit_entries` (default 1000) | oldest entries evicted |
| output per stream | `max_output_bytes` (default 1,000,000) | `truncated=True` |
| run time | `timeout_seconds` (default 30) | `timed_out=True` |

A string command that cannot be parsed by `shlex` is rejected as `use_argv_list`.

## Errors

Every error derives from `SandboxError`, which carries a stable `code`: `invalid_policy`, `invalid_command`, `policy_violation` (`PolicyViolation`, with a `reason`) and `spawn_failed`. Messages contain the reason and at most 200 redacted characters of the command.

## Reporting a vulnerability

See the repository `SECURITY.md` for the disclosure process.
