# agent-sandbox

[![PyPI version](https://img.shields.io/pypi/v/trysac-agent-sandbox)](https://pypi.org/project/trysac-agent-sandbox/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-agent-sandbox)](LICENSE)
[![CI](https://github.com/Trysac/u030-agent-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u030-agent-sandbox/actions/workflows/ci.yml)

Policy guard for agent shell commands: allow-listed absolute executables, path roots, process-tree timeout, capped output and scrubbed environment

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-agent-sandbox
# or
uv add trysac-agent-sandbox
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import agent_sandbox

# normalize() trims surrounding whitespace and lower-cases the text.
print(agent_sandbox.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    agent_sandbox.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
