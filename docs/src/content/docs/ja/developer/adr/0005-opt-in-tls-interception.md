---
title: "ADR 0005: Bounded opt-in TLS interception"
description: hostname allowlist、protected CA material、ALPN pinning、bounded leafでinterceptionを追加します。
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - ADR
  - TLS
  - セキュリティ
sidebar:
  order: 5
---

**Status:** Accepted

## Context

ADR 0004はblind CONNECTをdefaultに保ち、interception controlを一緒に導入するよう要求します。

## Decision

CA certificate、protected CA private key、非empty hostname allowlist、positive leaf-cache capacityが揃う場合だけcompileします。Unix key fileのgroup/other accessを拒否し、IP literal targetはinterceptしません。

CONNECT success前にupstream TCPを確立します。downstream TLSを先にnegotiateし、同じ`h2`/`http/1.1` ALPNでupstream TLSを認証します。RcgenがSAN付きleafを作り、in-memory cacheはhostname+ALPN offerでboundedです。auditはhostname、cache outcome、ALPNを記録しkey materialは記録しません。client pinning rejectionを含むhandshake failureはflowをcloseしてauditします。

両方のTLS handshake後、negotiateしたALPNでHyper HTTP/1.1またはHTTP/2のserver/client pairを選びます。inner requestはCONNECT destinationに固定し、`Host`/`:authority`を再生成して、plain forwardingと同じHTTP ACL、inspection、typed Hook、audit、replay pipelineへ通します。nested CONNECTは拒否します。HTTP/2のheader listとconcurrent streamには明示上限を設けます。

## Consequence

- managed clientはCONNECT全体をinterceptせず選択plaintextを公開できる
- operatorがCA custodyとplaintext retention責任を負う
- intercepted HTTP/1.1/HTTP/2はsemantic policyとtyped mutationを共有し、protocol framingはHyperに委ねる
