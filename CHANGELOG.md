# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Added

- Modern Python package layout under `osniffy/` with executable CLI entrypoint.
- Centralized project metadata and tooling in `pyproject.toml`.
- Strong test suite for parser, config, CLI, DB repository, reader, dashboard, and sniffer behavior.
- CI workflow with lint, format-check, type-check, tests, build verification, and dependency audit.
- Declarative Grafana provisioning assets under `grafana/provisioning/`.
- Root `.env.example`, `CONTRIBUTING.md`, and architecture/spec updates in `README.md`.

### Changed

- Import-time side effects moved into explicit startup flow.
- Structured logging and explicit exit-code handling in CLI paths.
- Packet persistence logic hardened with batching, retries, rollback, and filtering.

### Security

- Added dependency audit in CI.
- Documented least-privilege DB user model and privileged capture requirements.
