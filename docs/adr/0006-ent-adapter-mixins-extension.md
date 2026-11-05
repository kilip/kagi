# ADR-0006: ent adapter via mixins and an entc extension

Status: Accepted · Date: 2026-11-05

## Context
ent generates code per project, so a library cannot import the generated types of a user's schema. Users want full schema customization.

## Decision
`adapter/ent` ships (a) mixins (`UserMixin`, `AccountMixin`, `SessionMixin`, `VerificationMixin`) defining required columns and (b) an `entc.Extension` that generates the Kagi adapter into the user's own ent package. The adapter maps generated entities to Kagi domain structs and implements the storage ports.

## Consequences
- Full customization (extra fields, indexes, edges, hooks).
- More setup for users and higher maintenance for Kagi than shipping a fixed schema.
- Extra-field mapping is an open question.
