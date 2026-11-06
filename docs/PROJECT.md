# Project record

## Objective

Provide a deterministic policy layer in front of `subprocess` for agent shell commands: allow-listed absolute executables, path roots, process-tree timeout, capped output and a scrubbed environment.

## Scope

- In scope: the public API documented in [README.md](../README.md): policy validation, ordered command checks, redacted audit log, guarded subprocess runner, typed errors and a test double.
- Out of scope: container or VM isolation, memory, CPU and network limits, inspection of the semantics of allowed tools (for example `git -c` or `find -exec`), and any runtime dependency.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 631569 / 126826 |
| Hours (human) | pending measurement |
| Cost (USD) | 1.0264 |

## Factory run u030 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | claude-sonnet-5-5 | yes | 2868 | 109284 | 0 | 4246 | 0.5497 |
| fix-1 | claude-sonnet-5-5 | no | 4 | 314 | 6279 | 25022 | 0.0213 |
| fix-2 | claude-sonnet-5-5 | no | 8 | 1728 | 15625 | 64014 | 0.0628 |
| fix-3 | claude-sonnet-5-5 | no | 8 | 1388 | 8339 | 56868 | 0.0404 |
| fix-4 | claude-sonnet-5-5 | no | 6 | 800 | 9192 | 44482 | 0.0354 |
| fix-1 | claude-sonnet-5-5 | no | 6 | 426 | 7180 | 41434 | 0.0264 |
| fix-2 | claude-sonnet-5-5 | no | 8 | 1002 | 9111 | 60744 | 0.0389 |
| audit | claude-sonnet-5-5 | no | 14 | 4421 | 28997 | 160696 | 0.1328 |
| fix-3 | claude-sonnet-5-5 | no | 6 | 1446 | 8031 | 41311 | 0.0387 |
| docs | claude-haiku-5-5 | no | 129824 | 6017 | 0 | 0 | 0.0800 |

Total: $1.0264. Prices: Anthropic list prices.
