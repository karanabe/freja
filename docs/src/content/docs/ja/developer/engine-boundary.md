---
title: Engineとprotocol境界
description: Tokio、Pingora ServerApp、Hyper、CONNECT、relay ownershipの関係です。
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - アーキテクチャ
  - Pingora
  - Hyper
sidebar:
  order: 2
---

listener runtimeは交換可能です。transport adapterが変わってもprotocol semanticsとsecurity decisionを変えてはいけません。

## Runtime adapter

`ListenerEngine`は`EngineKind`だけを公開します。同梱CLIはFreja固有metadata、limit、shutdown、TUI、audit resourceを使ってHTTP、static TCP、SOCKS5を協調するためTokio listenerを選択します。

`pingora-adapter` featureはPingora 0.8.1のconcrete `ServerApp`をcompileします。`process_new` callbackは1つの`Stream`を狭い`PingoraConnectionHandler`へ渡し、ownership完了をawaitし、消費済みtransportがPingora reuse loopへ戻らないよう`None`を返します。このmoduleにpolicy/protocol ruleは置きません。

`freja-domain`、`freja-config`、`freja-policy`、`freja-audit`、`freja-ui`へPingora型を導入してはいけません。explicit forward proxyに`pingora-proxy::ProxyHttp`を使いません。

## HTTP ownership

Hyper 1.xがHTTP/1 connection state machineを所有します。downstream connectionはupgrade有効でserveし、CONNECTがtunnel taskへownershipを渡せるようにします。Freja codeは次を所有します。

- absolute-form target validationとorigin-form再生成
- request targetからの`Host`再生成
- parsed headerに対するframing/hop-by-hop policy
- destination authorizationとupstream client connection
- commit前のsynthetic error
- streaming body inspectionとtyped mutation

malformed wire parsingを保守されたHTTP実装へ任せながら、proxy固有invariantを明示できます。

## CONNECT commitment

```mermaid
stateDiagram-v2
    [*] --> Uncommitted
    Uncommitted --> Rejected: policy / port / connect failure
    Uncommitted --> UpstreamConnected: TCP connect succeeds
    UpstreamConnected --> TunnelCommitted: send 200
    TunnelCommitted --> BlindRelay: tunnel mode
    TunnelCommitted --> InterceptHandshake: allowlisted interception
    InterceptHandshake --> DecryptedRelay: both TLS handshakes succeed
    InterceptHandshake --> Closed: TLS or pinning failure
    BlindRelay --> Closed
    DecryptedRelay --> Closed
    Rejected --> [*]
    Closed --> [*]
```

`TunnelCommitted`後のHTTP block/redirectは不正です。failureはtunnelをcloseしてauditします。tunnel taskをtrackし、graceful shutdownでsignal/drainします。

## Relay ownership

static TCP、SOCKS5、blind CONNECT、decrypted TLS relayはbounded directional processingを共有します。各directionはscanner/Hook stateを所有し、idle timeout、byte count、shutdownを適用します。TCP preflightが保持するのは設定prefixまでで、benignな短いprefixは設定read timeout後に解放します。streamingは送信済みbyteを取り消せません。

listener追加時はdestination authorizationとrelay境界を再利用し、全DNS answerのpolicy確認前に1 addressを選択するpathを作らないでください。

[ADR 0001](/ja/developer/adr/0001-engine-boundary/)、[ADR 0002](/ja/developer/adr/0002-pingora-server-app/)、[ADR 0003](/ja/developer/adr/0003-forward-proxy-http-engine/)も参照してください。
