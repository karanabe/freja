---
title: "ADR 0002: ServerApp経由のPingora"
description: Pingora 0.8.1をtransport lifecycle adapterとしてだけ使用します。
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - ADR
  - Pingora
sidebar:
  order: 2
---

**Status:** Accepted

## Context

Pingora 0.8.1をcompatibility baselineとします。reverse-proxy parser/request lifecycle typeを採用せず、accepted transportへaccessする必要があります。

## Decision

`pingora_core::apps::ServerApp`で`Stream`を受け取ります。concrete generic adapterはpolicy logicを持たず、各streamを1回だけconsumeし、`PingoraConnectionHandler`へdelegateし、handler完了後に`None`を返します。explicit forward proxyに`pingora-proxy::ProxyHttp`を使いません。

all-feature gateはPingoraと`ServerApp` contractをcompileします。現在のmulti-listener CLIはTokio adapterを使い、full Pingora process wiringはdomain constraintではなくalternative adapterです。

## Consequence

- Pingora upgradeを1 boundaryで隔離・compile-testできる
- handlerがprotocol connection reuseとCONNECT upgrade ownershipをすべて担う
- runtime固有listener metadataはshared engineへ入る前に変換する
