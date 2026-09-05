---
title: アーキテクチャ
description: Freja contributor向けのcrate境界、data flow、runtime snapshot、不変条件です。
publishedAt: 2026-08-31
updatedAt: 2026-09-03
tags:
  - アーキテクチャ
  - 開発者
sidebar:
  order: 1
---

Frejaはframework非依存のsecurity decisionをruntime/wire処理から分離します。protocol固有のfact/actionはdomain modelに含めますが、wire parserやconcrete networking runtimeからは独立させます。Pingora型はadapterだけに存在し、domain、configuration、policy、inspection、audit、Hook、UIは依存しません。

```mermaid
flowchart TD
    R[RawConfig] --> V[ValidatedConfig]
    V --> C[CompiledConfig]
    C --> S[ArcSwap policy snapshot]
    L[Tokio listeners or Pingora ServerApp] --> H[Hyper HTTP/1 engine]
    L --> T[Static TCP relay]
    L --> K[SOCKS5 CONNECT]
    H --> X[CONNECT tunnel or opt-in TLS interception]
    H --> S
    T --> S
    K --> S
    X --> S
    S --> I[Streaming or preflight inspection]
    I --> A[Bounded critical audit]
    I --> E[Best-effort data-plane events]
    E --> U[UI adapter and immutable UI events]
    A --> J[Hash-chained JSONL and signed checkpoints]
    J --> P[Offline replay]
```

## Crate境界

### `freja-domain`

validated identifier、endpoint、runtime mode、目的別fact、finding、decision、trace、listener specificationを所有します。全connectionは`SessionId`、全HTTP exchangeは`TransactionId`を持ちます。async runtime、parser、Pingoraには依存しません。

### `freja-config`

唯一のconfiguration compilerです。typestate pathにより、socketを開く前に不正なmode組み合わせ、zero bound、安全でないremote exposure、無制限capture、不正credential digest、empty CONNECT/interception allowlist、不正policy/detectorを拒否します。

内部では`raw`がSerde向けTOML model、`validation`がsemantic/cross-field invariant、`compiled`がimmutableなpolicy/inspection programの構築を所有します。listener、resource limit、audit、inspection、TLSのruleは各stage内の担当moduleへ分離し、crate rootはstableなpublic APIだけを公開します。commandless/config-free startupでは`freja` composition rootが`RawConfig::default()`へloopback HTTP listener 1件を追加し、socketを開く前に完全なcompilerを通します。`freja-config`自体はlistenerを暗黙生成しません。

### `freja-policy`

宣言順first-match ACLを評価します。requested destinationをDNS前に確認し、その後destination guardとACLが全addressを評価します。detectorは`Finding`を生成し、inspection policyがtraced decisionへ変換します。fixed-pattern scannerはchunk間のbounded overlapを保持します。typed automatic/interactive Hookもwire accessなしでここに置きます。

### `freja-audit`

central redaction後にtyped version-2 eventをserializeし、replayはversion 1との互換性を維持します。bounded channelと明示的fail-open/fail-closedはUI deliveryから独立しています。各recordは直前recordへlinkし、optional Ed25519 checkpointは外部pinされたkeyにより保持位置をauthenticateします。

### `freja-proxy`

transport behaviorを所有します。HyperがHTTP/1 absolute-formとCONNECTを処理し、Frejaが`Host`再生成、hop-by-hop除去、ambiguous framing拒否、body streamingを担います。CONNECT policyとupstream接続は200 commit前に完了します。static TCPとSOCKS5はdestination authorization、bounded relay、inspection、Hook、audit、metrics、shutdownを共有します。

public listener constructorはproxy所有の`ProxyLimits`を受け取り、TLS/capture setupもproxy所有のvalidated inputを使います。`freja-config`の値は`freja` composition rootで変換し、configuration/UI型をdata-plane crateへ漏らしません。

TUIがattachedの場合に限り、proxy所有の`UiCaptureSettings`がplain explicit HTTP/1 streamへnon-blocking ingress observerを設置します。protocol parse/forwardingの正はHyperです。privateで上限付きのcapture-only framerは、content-length、chunked trailer、informational response、close-delimited responseを含むmessage境界を検出し、正確なRaw表示だけに使います。結果はbest-effort UI eventしか生成できず、trafficのaccept/reject/mutation/delayには影響できません。third-party HTTP wire-capture dependencyと汎用public parser APIは追加しません。

TLS interceptionはhostname単位のopt-inです。CONNECT commit前にupstream TCPを確立し、downstream TLSをnegotiateして、選択された`h2`/`http/1.1` ALPNでupstream TLSを認証します。Rcgenはprotected CAからSAN付きleafを作り、host+ALPNのbounded cacheへ保存します。Hyperがintercepted HTTP/1.1/HTTP/2をdecodeし、semantic exchangeを同じ上限付きHTTP policy、inspection、typed Hook、audit、replay pipelineへ再接続します。
TUIはこれらintercepted exchangeをsemantic表示します。persistent intercepted HTTP/1とHTTP/2 framingの正確なRaw captureは、transaction correlationを専用設計するまで意図的にunavailableです。

trackedなsequential HTTP repeat executorはUI型へ依存せず、TUIから型付きの上限付きdraftを受け取ります。freshなflow IDを割り当て、policy inputとして元source IPだけを維持し、通常のdestination、HTTP policy、inspection、Hook、authenticated TLS、audit、replay fact境界へ再投入します。interactive pauseとlistener authenticationだけをskipします。request/result channelとresponse retentionはそれぞれboundedです。

### `freja-ui`

immutable snapshotを受け、isolated threadでRAII restoration guardのもとterminalを所有します。TUI modeではCLIがoperational tracingをbounded immutable UI eventへformatするため、raw terminalへ同時に書くproducerはありません。UI saturationはsnapshotまたはlog lineをdropしてmetricを増やします。interactive requestは別のbounded channel、paused-flow semaphore、timeout、oneshot responseを使います。
traffic rowとrepeat workspaceは設定でboundedです。screen 1はHTTPを`TransactionId`、TCPを`SessionId`でcorrelateし、screen 2はevidence/log/statisticsを分離し、screen 3は複数のHTTP/1.1 repeat draftと各draftの最新resultだけを保持します。HTTP interactive modeはcompleteでboundedなrequest snapshotをoperatorへ1回送ります。HTTP/1.1 text editorはそのcopy済みsnapshotだけを所有し、validate済みdraftを原子的な型付きheader/body planへ変換します。method、target、version、routing、framingはdata planeの責務のままです。responseとTCP dataはTUI decisionを待ちません。

domain所有の`EvaluationTarget` snapshotはruntime型を含まず、要求先または解決先の接続情報を表します。proxyがbest-effortな`DecisionMade` eventへ付帯し、composition rootのadapterがUIのboundedな`TraceSnapshot`へ評価結果と一緒に渡します。rendererは評価行に最新の解決先IPを後付けしません。このobserver情報はaudit schema、replay fact、policy評価を変更しません。

### `freja`

bootstrap/error-erasure境界です。複数listener、signal、audit writer、compatible SIGHUP reload、stored inputのverify/replayを所有します。compiled configurationをsubsystem所有runtime inputへ変換し、UI非依存data-plane eventを現在のpresentationへadaptします。listener起動前に通常terminal tracing writerまたはbounded TUI routerを選び、terminal threadをjoinする前にrouterを切断します。production multi-listener runtimeはTokioを使い、generic Pingora 0.8.1 `ServerApp` adapterもcompile-testします。

## Decision flow

```mermaid
sequenceDiagram
    participant Client
    participant Proxy
    participant Policy
    participant DNS
    participant Upstream
    participant Audit

    Client->>Proxy: target and request metadata
    Proxy->>Policy: RequestedTargetFacts
    Policy-->>Proxy: Decision + DecisionTrace
    Proxy->>DNS: resolve allowed hostname
    DNS-->>Proxy: all IP answers
    loop every resolved address
        Proxy->>Policy: ResolvedTargetFacts
        Policy-->>Proxy: guard + ACL decisions
    end
    Proxy->>Upstream: connect selected allowed address
    Proxy->>Audit: facts, decisions, lifecycle
```

HTTP request/response factとinspection findingは追加policy stageになりますが、requested/resolved authorizationを迂回しません。

## Reload state

1 immutable snapshotがACL、destination guard、enforcement mode、inspection program/mode、policy generationを保持します。compatible SIGHUP candidateはparse、validate、compile完了後に1回の`ArcSwap`で置換します。taskは旧snapshotか新snapshotのどちらかを見て、fieldの混在はありません。resourceを所有する設定はrestart-onlyです。

## Core invariant

- 選択する全DNS addressをauthorizeし、detour/new destinationも同じ検査へ戻す
- CONNECT tunnel commit後にHTTP responseを出さない
- body mutationはdecoded-body typeへ適用しframingを再構築する
- forwardingはUI publicationを待たず、critical audit failureを黙殺しない
- default runtimeはTui + Observe + Interactive、標準headless profileはHeadless + Enforce + Disabled。Observeはpolicy actionを実行せず、interactiveなoperator decisionは引き続き有効。各choiceは独立
- payload capture、TLS interception、remote exposureはopt-in
- connection、header、body prefix、cache、header/body read、upstream connect、relay無通信、paused flow、channelはbounded
- library crateはunsafeを禁止し、concrete error enumを公開する

## ルール確認の根拠

policy evaluatorは既存の`Decision`とともに、実際に選んだ借用`RuleDefinition`を返します。
ACL evaluatorは宣言順の設定への借用、正確な評価件数、先頭64件の結果を格納した固定長
配列も返します。結果は実際の評価中に記録し、UI描画による再評価やrequest factの
借用保持は行いません。proxyはobserverがある場合だけ、同じ`DecisionSnapshot`のenforcementとともにsnapshot化
します。rule IDによる結合やreload後のpolicy参照は行いません。継続中のscannerは元の
inspection programとenforcementを保持し、UI用にpolicy履歴を保存しません。

`freja-policy::evidence`がboundedなlocal定義表現を所有します。条件とアクションは
serialize時に各16 KiBで制限し、不完全なら明示します。ACLでは既定動作と先頭64件までの
宣言を追加保持し、宣言一覧全体を16 KiBに制限します。宣言には実際の不一致・情報未取得・
一致・first-matchによる未評価を付けます。空のACLを明示し、一覧を省略しても件数は
全宣言について保持します。採用ruleの定義は別途上限内で保持します。composition rootのbest-effort
adapterが`RuleEvidence`を渡し、`freja-ui`がtraceとともに保持します。このためUIの
`tui` featureを無効にしてもpolicy依存は存在し、ratatuiのみoptionalのままです。
`UiEvent`のserializeでは機密の定義fieldを除外し、audit eventとreplayにも追加しません。

TUIは保持する評価にprocess内で再利用しないIDを付け、Diagnosticsのアクセスを
TransactionId/SessionIdで固定します。追加保持は開いている詳細一件だけです。
到着・reloadで対象を置き換えず、削除された選択は明示的なnavigationまで欠落として
扱います。描画・入力はpolicyや通信を変更しません。
