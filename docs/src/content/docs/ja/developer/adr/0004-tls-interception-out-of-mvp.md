---
title: "ADR 0004: MVP外のTLS interception"
description: 初期CONNECTをblind tunnelに保ち、interceptionを1つのreview済みfeatureとして導入します。
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - ADR
  - TLS
sidebar:
  order: 4
---

**Status:** Accepted

## Context

blind CONNECTはlocal CAが不要でend-to-end TLSを維持します。interceptionはkey custody、client trust変更、certificate生成、decrypted payload、ALPN、pinning、追加audit要件を導入します。

## Decision

headless MVPはblind TCP tunnelだけを実装します。後で追加するTLS interceptionもdefault disabledとします。protected CA input、SAN/SNI-correct leaf、bounded cache、明示hostname allowlist、HTTP/1.1/HTTP/2 handling、pinning behavior、capture control、dedicated audit eventを一緒に実装・reviewした場合だけ導入します。

## Consequence

- 初期配置ではtrust anchorを配布しなくてよい
- tunnel modeを恒久的に利用できる
- generic inspection有効化の暗黙side effectとしてinterceptionを導入しない
