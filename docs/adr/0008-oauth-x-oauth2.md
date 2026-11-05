# ADR-0008: OAuth via golang.org/x/oauth2

Status: Accepted · Date: 2026-11-05

## Decision
OAuth flows are built on `golang.org/x/oauth2`. Provider presets live in the `oauth/` package. Successful OAuth sign-in creates or links an `account` row (see [ADR-0004](0004-data-model.md)).

## Consequences
- Small, well-maintained dependency allowed in core.
- Provider-specific quirks are handled in presets, not in the flow.
