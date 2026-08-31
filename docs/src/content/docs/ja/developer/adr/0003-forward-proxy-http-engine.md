---
title: "ADR 0003: Hyper HTTP/1 forward-proxy engine"
description: ProxyHttpやcustom parserではなくHyperでexplicit HTTP/1.1 semanticsを実装します。
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - ADR
  - HTTP
  - Hyper
sidebar:
  order: 3
---

**Status:** Accepted

## Context

explicit proxyはabsolute-form requestとCONNECT authority-formを受け取ります。origin/reverse proxyとはsemanticsが異なり、malformed framingは保守されたparserで扱う必要があります。

## Decision

選択listener adapterのtransport上でHyper 1.xがHTTP/1.1 connection state machineを所有します。Frejaはabsolute-form/CONNECTを受け、`Host`を再生成し、hop-by-hop headerを除去し、ambiguous framingを拒否し、bodyをstreamし、upgradeを有効化します。

CONNECTはsuccess前にupstreamをopen・policy-checkします。success commit後はtunnelなのでHTTP block/redirectを出せません。

HTTP parserを手書きしません。Pingora high-level parserへ合わせるため`http` crateをdowngradeしません。

## Consequence

- parser stateをHyperへ任せつつproxy correctnessを明示できる
- outbound client connection、synthetic response、tunnel task trackingはFrejaが所有
- このHTTP/1 engineはHTTP/2 extended CONNECT対応を意味しない
