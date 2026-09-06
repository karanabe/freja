---
title: Use cases
description: Practical scenarios that connect a concrete purpose to actions and observed evidence.
publishedAt: 2026-09-06
updatedAt: 2026-09-06
tags:
  - testing
sidebar:
  order: 1
prev:
  link: /
  label: Documentation home
next:
  link: /use-cases/browser-form-lab/
  label: HTTP/1.1 browser form lab
---

A use case starts with something you want to accomplish or verify, then follows
preparation, actions, expected displays and what the evidence can establish.
Choose a purpose here and open its overview. Each scenario identifies its
prerequisites and distinguishes validated behavior from unobserved manual steps.

| What you need | Where to read |
| --- | --- |
| Verify a concrete purpose from start to finish | **Use cases** — preparation, actions, evidence, recovery and shutdown. |
| Learn general feature or configuration operations | **Guides** — [startup](../guides/getting-started/), [TUI and hooks](../guides/tui-and-hooks/) and other operations shared across scenarios. |
| Look up the complete option or schema contract | **Reference** — [CLI](../reference/cli/), [configuration](../reference/configuration/) and other definitions. |

## Available use cases

| Purpose | Entry point and outcome to check |
| --- | --- |
| Observe and intervene in browser HTTP/1.1 traffic, then match origin arrival | [HTTP/1.1 browser form lab](./browser-form-lab/) — follow local synthetic GET/POST, continue, edit, reject and Repeat; distinguish a direct echo success from evidence of proxy traversal. |

Next, read the lab overview for its page map and safety boundaries, then prepare
for one GET round trip.
