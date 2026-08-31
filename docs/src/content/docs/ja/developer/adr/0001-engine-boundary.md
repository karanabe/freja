---
title: "ADR 0001: 交換可能なlistener engine"
description: policy/protocol semanticsをPingora/Tokio listener ownershipから分離します。
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - ADR
  - アーキテクチャ
sidebar:
  order: 1
---

**Status:** Accepted

## Context

runtime固有I/O typeがdomain、policy、inspection、audit、Hook、UI APIを形作ることなくlistener lifecycleを管理する必要があります。Pingoraのhigh-level reverse-proxy surfaceはFrejaに必要なexplicit forward-proxy semanticsを定義しません。

## Decision

狭いlistener engineがconnection acceptを所有し、Freja protocol engineへtransport streamを渡します。runtime identityはtransport typeをcrate間へ漏らさず`EngineKind`で表します。この境界の後ろでpure Tokio listenerを選択できます。

production CLIはFreja固有metadata/shutdownでHTTP、static TCP、SOCKS5を協調するためTokioを選びます。generic Pingora `ServerApp` transport adapterも独立して実装・compile-testします。

## Consequence

- runtime選択変更時もfact、decision、event、protocol testを再利用できる
- CLIがPingoraなら所有するlifecycle機能を提供する必要がある
- 将来のPingora process統合はadapter内に置き、wiring簡略化のためpolicy semanticsを変えない
