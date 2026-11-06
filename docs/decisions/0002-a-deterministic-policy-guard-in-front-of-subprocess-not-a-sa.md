# A deterministic policy guard in front of subprocess, not a sandbox

Status: accepted (generated, pending human review)

## Context

Agents that run shell commands can hang, flood output, leak environment secrets, run a binary they just wrote or leave the project directory. Real isolation needs containers, but most tools lack even a policy layer in front of subprocess. The library must be honest about what it can and cannot defend.

## Decision

Split the work into a pure, ordered policy check (Sandbox.check, first failure wins, stable reasons) and a replaceable ProcessRunner behind a Protocol. The default SubprocessRunner uses shell=False, a new process group or session, a process-tree kill on timeout, two reader threads that cap and drain output, and an environment scrubbed by allow-list plus secret-name filtering. Every decision is redacted before it is audited, emitted or placed in an error. Paths are compared as normcase(realpath) with commonpath containment, and an allowed executable may never live inside an allowed root. The threat model states both what is defended and what is not (interpreters in the allow list, TOCTOU, memory, CPU, network, tool semantics).

## Consequences

Decisions are deterministic and testable without starting processes, using FakeProcessRunner. Callers get strong defaults against accidental and naive misuse, but must not treat the library as isolation for hostile code: containers are still needed for that. Resolving argv[0] to its real path closes PATH-hijack and symlink tricks at the cost of running base interpreters instead of virtual-environment launchers. Path checks stay racy by design, and unparseable string commands are routed to the use_argv_list reason.
