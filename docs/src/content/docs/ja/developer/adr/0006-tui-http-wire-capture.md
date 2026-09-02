---
title: "ADR 0006: TUI専用HTTP/1 wire capture"
description: Hyperを正としたまま、privateでboundedなobserverから正確なRaw表示を供給します。
publishedAt: 2026-09-02
updatedAt: 2026-09-03
tags:
  - ADR
  - TUI
  - HTTP
sidebar:
  order: 6
---

**Status:** Accepted

## Context

traffic screenではplain explicit HTTP/1 request/upstream responseについて、parsed Pretty viewと正確なRaw/Hex byteの両方が必要です。Hyperはsemantic messageを公開しますが、元のingress byte列は公開しません。この表示要件のために別のparserを正としたり、UIを外部capture dependencyへ結合したりしてはいけません。またFrejaはHyperをauthoritative HTTP parserとして維持し、presentation captureがforwardingへ影響しないようにする必要があります。

## Decision

`freja-proxy`がprivateなcapture-only HTTP/1 framerとasync I/O adapterを所有します。TUI bootstrapが`UiCaptureSettings`をattachした場合だけ設置します。request adapterはclient ingressを観測してmessageを`TransactionId`へcorrelateし、response adapterはupstream ingressを観測します。retentionは`header_bytes + ui_content_bytes`、correlation stateは`ui_retained_rows`でboundedです。

observerは正確なmessage境界に必要なframingだけを認識します。対象はheader終端、一致するContent-Length、extension/trailerを含むsingle chunked transfer coding、bodyを持たないstatus、informational response、close-delimited responseです。requestのacceptと全forwardingは引き続きHyperが決定します。observerのcomplete/failureはnon-blocking immutable UI eventを試行するだけで、protocol decisionを返したりbackpressureをかけたりできません。

framerはprivateのままとし、再利用可能なHTTP parser APIにしません。state machineには全split境界unit testがあり、HTTP framing fuzz targetへ接続します。追加のcapture dependencyは導入しません。

正確なRawの初期対象はplain explicit HTTP/1です。local synthetic response、persistent intercepted HTTP/1、HTTP/2はsemantic Prettyを維持しながらRaw unavailableを表示します。これらの対応にはpersistent streamのtransaction correlationを別設計する必要があります。HTTP/2 frameをHTTP/1 messageのように表示してはいけません。

## Consequences

- headless modeはwire-capture costを負わず、TUI payload snapshotを保持しません。
- TUI Raw contentは設定上限内で正確で、上限超過またはfailureを明示します。
- TUI contentはsensitiveかつunredactedで、audit capture/redaction policyから独立します。
- small private state machineはforwarding結果を変えられなくてもsecurity-relevant observer codeなので、split-boundary、malformed framing、fuzz、integration coverageを維持します。
