# ADR 0004: TLS Interception Out of the MVP

Status: Accepted for the headless MVP; extended by ADR 0005

The initial explicit proxy supports HTTPS only as a blind CONNECT tunnel. TLS
interception is not required for the MVP and must never become an implicit
default. Later hardening added separately enabled, hostname-allowlisted
interception while preserving tunnel mode and the original MVP boundary.

Detailed records:
[`../src/content/docs/developer/adr/0004-tls-interception-out-of-mvp.md`](../src/content/docs/developer/adr/0004-tls-interception-out-of-mvp.md)
and
[`../src/content/docs/developer/adr/0005-opt-in-tls-interception.md`](../src/content/docs/developer/adr/0005-opt-in-tls-interception.md).
