# ADR-0009: Developer tooling

Status: Accepted · Date: 2026-11-05

## Decision
- **mise** manages tool versions and tasks.
- **go.uber.org/mock** (`mockgen`) for mocks.
- **lefthook** for git hooks (`pre-commit`, `commit-msg`).
- **cocogitto** (`cog verify`) enforces Conventional Commits in the `commit-msg` hook; no Node dependency.

## Consequences
- Release tagging and changelog generation with cocogitto are not decided yet.
