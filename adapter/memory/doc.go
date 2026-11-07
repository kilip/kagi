// Package memory provides in-memory implementations of Kagi primary storage ports
// (ADR-0004, ADR-0007).
//
// These implementations are goroutine-safe via sync.RWMutex and maintain full
// behavioral conformance with the adaptertest test suite. They are suitable for
// unit testing, local development, ephemeral test environments, and standalone
// examples where external databases are unnecessary or unavailable.
//
// All mutations and queries perform defensive copying to protect internal state
// against concurrent caller mutation. Optional clock injection is supported
// across all stores using Option and WithClock.
package memory
