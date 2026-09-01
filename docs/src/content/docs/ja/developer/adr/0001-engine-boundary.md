---
title: "ADR 0001: frameworkを隔離したruntime adapter"
description: policy/protocol semanticsをPingora/Tokio listener ownershipから分離します。
publishedAt: 2026-08-31
updatedAt: 2026-09-01
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

`freja-proxy`をframework isolation境界とします。production CLIはconcrete Tokio accept loopを所有してFreja protocol engineへstreamを渡します。optional Pingora moduleは独立した`ServerApp` lifecycleを所有し、供給された各streamを狭いconnection handlerへ委譲します。

TokioとPingoraのlifecycle APIを共通listener traitへ無理に押し込みません。現時点ではruntime差し替え可能ではなく、identityだけのtraitは実装が提供しない能力を示唆するためです。共有契約はprotocol behaviorとframework typeの隔離であり、同一のlistener/process ownershipではありません。

production CLIはFreja固有metadata/shutdownでHTTP、static TCP、SOCKS5を協調するためTokioを選びます。generic Pingora `ServerApp` transport adapterも独立して実装・compile-testします。

## Consequence

- fact、decision、event、protocol testをruntime framework型から独立させられる
- CLIがPingoraなら所有するlifecycle機能を提供する必要がある
- 別process runtimeの選択には明示的なbootstrap統合が必要で、共通trait背後のruntime switchではない
- 将来のPingora process統合はadapter内に置き、wiring簡略化のためpolicy semanticsを変えない
