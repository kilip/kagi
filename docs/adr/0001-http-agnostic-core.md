# ADR-0001: HTTP-agnostic core service layer

Status: Accepted · Date: 2026-11-05

## Context
Fiber (MVP target) runs on fasthttp, not `net/http`. Other frameworks (net/http, gin) are expected later.

## Decision
The core is a service layer with no HTTP dependency (`SignUp`, `SignIn`, `VerifyOTP`, `OAuthCallback`, ...) returning plain structs. HTTP wrappers (`http/fiber` first) live in separate modules and are the only place that touches cookies, headers and requests.

## Consequences
- Adding a framework means writing a thin wrapper, not touching core.
- Core is easy to test without HTTP.
- Wrappers must each implement cookie and middleware handling.
