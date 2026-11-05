# ADR-0012: Account linking policy

Status: Accepted · Date: 2026-11-05

## Context
Multiple login methods per user are part of the MVP ([ADR-0004](0004-data-model.md)). When an OAuth sign-in returns an email that already belongs to a Kagi user, linking blindly allows account takeover through a provider that does not verify email ownership.

## Decision
- An OAuth sign-in is **auto-linked** to an existing user only when the provider asserts the email is verified (e.g. Google `email_verified`, GitHub primary verified email).
- If the provider email is not verified, Kagi does not link and returns an error. The user can sign in with an existing method and link explicitly.
- A signed-in user can link and unlink methods explicitly. Unlinking the last remaining login method is rejected.
- A new user created through a verified OAuth email starts with `email_verified = true`.

## Consequences
- Prevents takeover via unverified provider emails.
- Each provider preset must expose a reliable verified-email signal ([ADR-0008](0008-oauth-x-oauth2.md)).
- Some users with unverified provider emails need one extra explicit linking step.
