---
title: Competitive positioning
description: 既存proxy ecosystemと、Frejaが意図的に重視するproduct qualityです。
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - プロジェクト
  - positioning
sidebar:
  order: 6
---

Frejaはprotocol breadthやraw proxy performanceだけを主な競争軸にしません。VEY、Rama、mitmproxy、Hudsucker、Squidはすでに存在し、このproblem spaceの重要部分をcoverしています。

- **VEY**: forward、stream、interception、ACL、inspectionを持つ広範なRust proxy
- **Rama**: proxy/traffic toolingを持つprogrammable Rust networking framework
- **mitmproxy**: matureでinteractive/scriptableなHTTP/TLS inspection proxy
- **Hudsucker**: RustのHTTP/S interception library
- **Squid**: matureなforward proxyで、ordered ACL/adaptation behaviorのreference

Rust、ACL、forward proxy、TLS interception、L4/L7併用、performanceだけではFreja固有のdifferentiatorになりません。

Frejaは代わりに次を重視します。

- explainable deterministic policy decisionをfirst-class dataにする
- 任意HTTP wire byteを出せないtyped Hook
- live、headless、TUI、offline replayでpipelineを共有
- privacy-awareでredacted、tamper-evidentなaudit record
- controlled/air-gapped環境向けlocal-first運用

public claimは実装/test済みbehaviorに限定します。currentでreproducibleなevidenceなしにprotocol supportやbenchmarkをuniqueと表現しないでください。
