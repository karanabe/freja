---
title: Competitive positioning
description: The existing proxy ecosystem and the product qualities Freja intentionally emphasizes.
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - project
  - positioning
sidebar:
  order: 6
---

Freja does not compete primarily on protocol breadth or raw proxy performance.
VEY, Rama, mitmproxy, Hudsucker, and Squid already exist and cover important
parts of this problem space.

- **VEY** is a broad Rust proxy with forward, stream, interception, ACL, and
  inspection capabilities.
- **Rama** is a programmable Rust networking framework with proxy and traffic
  tooling.
- **mitmproxy** is a mature interactive and scriptable HTTP/TLS inspection
  proxy.
- **Hudsucker** is a Rust HTTP/S interception library.
- **Squid** is a mature forward proxy and a reference point for ordered ACL and
  adaptation behavior.

Rust, ACL support, forward proxying, TLS interception, combined L4/L7 support,
and performance alone are not unique differentiators for Freja.

Freja instead emphasizes:

- explainable deterministic policy decisions as first-class data;
- typed hooks that cannot emit arbitrary HTTP wire bytes;
- shared live, headless, TUI, and offline replay pipelines;
- privacy-aware, redacted, tamper-evident audit records;
- local-first operation for controlled and air-gapped environments.

Keep public claims scoped to implemented and tested behavior. Protocol support
or benchmark results should never be presented as unique without current,
reproducible evidence.
