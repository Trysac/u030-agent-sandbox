# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `agent_sandbox`: a policy guard for agent shell commands with allow-listed absolute executables, path roots, redacted audit log, scrubbed environment, process-tree timeout and capped output, plus `FakeProcessRunner` for tests.
- Initial project structure from the factory utility template.
