# Repository Guidelines

## Fork & Upstream Patches

This repository is a fork of [EpicGames/lore](https://github.com/EpicGames/lore). Before updating from upstream or changing fork patches, read the [upstream patch register](docs/developing/upstream-patches.md) for acceptance contracts and replay/retirement guidance.

Record new fork patches that change core code or behavior in that register, including their purpose, acceptance criteria, and relevant tests. Documentation-only changes and similar changes outside the core do not require patch entries.

## Project Structure & Module Organization

Lore is a centralized version-control system organized as a Cargo workspace. `lore/` contains the core library, `lore-client/` the CLI, and `lore-server/` the server. Supporting `lore-*` crates handle storage, transport, credentials, telemetry, protocols, and C bindings (`lore-capi/`). Source lives in each crate's `src/`; Rust unit tests belong in `tests/unit/`. Python smoke tests live in `scripts/test/`, external-service tests in `lore-integration-tests/`, documentation and assets in `docs/`, and deployment examples in `contrib/`.

## Build, Test, and Development Commands

Use stable Rust, nightly Rust for formatting, and Python 3.13+ with `uv`. Run commands from the repository root:

- `cargo build`: build debug artifacts; add `--release` for release artifacts.
- `cargo build -p lore-capi`: build the C libraries and header.
- `cargo test --workspace`: run Rust tests; use `cargo test -p lore-server` for focused validation.
- `cargo +nightly fmt --all`: format Rust; add `--check` to verify formatting.
- `cargo clippy --all-targets -- -D warnings --no-deps`: lint with zero warnings.
- `uv run pytest scripts/test/ -m smoke`: run smoke tests after `cargo build --release`; the harness starts a local server and defaults to release binaries.
- `pre-commit run --all-files`: run configured repository hooks.

## Coding Style & Naming Conventions

Use four-space indentation, `snake_case` for Rust modules/functions and Python functions, and `UpperCamelCase` for Rust types. Follow nightly rustfmt's configured import grouping. Python tooling includes Ruff and Pyright. Read `docs/developing/code-standards/` before changing code; follow its error-handling, logging, and task-spawning conventions. Preserve copyright headers and add an MIT SPDX identifier to new source files.

## Testing Guidelines

Use Rust's test harness and Tokio for async tests. Register unit-test modules through `tests/unit/main.rs`; use descriptive names and Python `test_*.py` files. Test boundaries and error variants at unit level, and real user flows with pytest. Every CLI command requires smoke coverage. Start `lore-integration-tests/compose.yaml` services before running `cargo test -p lore-integration-tests --features integration_tests`.

## Commit & Pull Request Guidelines

Recent commits use prefixes such as `fix:`, `docs:`, and `authz:`. Keep imperative subjects under 72 characters and sign every commit with `git commit -s`. Submit focused PRs to `main` with the problem, approach, linked issue, validation, and relevant documentation updates; two maintainer approvals are required. Follow `CONTRIBUTING.md` for issue/LEP prerequisites.
