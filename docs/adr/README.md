# Architecture Decision Records

This directory records the significant architectural decisions for Kagi, in the
[Nygard format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions).
Product scope lives in the [PRD](../prd.md); delivery is tracked in the
[GitHub Project](https://github.com/users/kilip/projects/11).

## Index

| ADR | Title | Status |
| :--- | :--- | :--- |
| [0001](0001-http-agnostic-core.md) | HTTP-agnostic core service layer | Accepted |
| [0002](0002-multi-module-monorepo.md) | Multi-module monorepo | Accepted |
| [0003](0003-opaque-sessions.md) | Opaque session tokens | Accepted |
| [0004](0004-data-model.md) | Data model: user, account, session, verification, rate_limit | Accepted |
| [0005](0005-email-otp.md) | OTP via email, `Mailer` interface | Accepted |
| [0006](0006-ent-adapter-mixins-extension.md) | ent adapter via mixins and an entc extension | Accepted |
| [0007](0007-storage-ports-and-conformance.md) | Storage ports, optional secondary storage, conformance suite | Accepted |
| [0008](0008-oauth-x-oauth2.md) | OAuth via `golang.org/x/oauth2` | Accepted |
| [0009](0009-tooling.md) | Developer tooling | Accepted |
| [0010](0010-expiry-and-cleanup.md) | Expiry handling and cleanup | Accepted |
| [0011](0011-string-ids.md) | String IDs in domain and ports | Accepted |
| [0012](0012-account-linking-policy.md) | Account linking policy | Accepted |

## When to write an ADR

Write an ADR when a change is expensive to reverse, for example when it:

- changes the public API or a storage port contract,
- changes the data model,
- changes the security model (sessions, tokens, OTP, OAuth, linking),
- adds a dependency to the core module,
- changes module layout, tooling or the release strategy.

Ordinary implementation work does not need an ADR; link the relevant ADRs from
the issue or pull request instead.

## How to add one

1. Copy [template.md](template.md) to `NNNN-short-title.md` using the next number.
2. Open a pull request with status `Proposed`; set it to `Accepted` when merged.
3. Add it to the index above.
4. Never rewrite an accepted ADR's decision. Supersede it with a new ADR and set
   the old one to `Superseded by ADR-NNNN`.
