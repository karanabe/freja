---
title: TUIと型付きHook
description: ratatuiでflowを観測し、automaticまたはinteractive Hookの挙動を理解します。
publishedAt: 2026-08-31
updatedAt: 2026-09-03
tags:
  - TUI
  - Hook
  - interception
sidebar:
  order: 5
---

TUIは表示modeであり、enforcement modeではありません。immutableで上限付きのsnapshotを受け取り、live network sessionを所有しません。

## TUIを有効にする

```toml
[runtime]
ui = "tui"
enforcement = "observe"
hooks = "interactive"
```

組み込みinteractive profileは直接起動できます。

```sh
cargo run -p freja
```

`examples/config/tui/freja.toml`はmulti-listener TUI profile向けにenforcementを明示的に有効化します。`examples/config/tui/freja.interactive.toml`は、小さい上限とpreflight inspectionを使うHTTP専用enforcement variantです。各example profileはlistener portを共有するため、1つずつ起動してください。

実terminalでFrejaを起動します。この画面のtraffic contentは意図的にredactせず、credential、cookie、query secret、個人情報を含む可能性があります。信頼できるlocal terminalだけで使用してください。audit redactionは変更されません。

TUIには3 pageあります。

- **1 Traffic**: 上25%をfull-widthのFlows listに使い、残りをdefaultでRequest/Client-to-Upstream 50%とResponse/Upstream-to-Client 50%に分割します。HTTPの1 rowは`TransactionId`、TCPの1 rowは`SessionId`を表します。
- **2 Diagnostics**: 上45%をFindings / DecisionTrace、可変の中央領域をOperational logs、末尾8 rowをStatisticsに使います。
- **3 Repeat**: 上25%に保持したHTTP/1.1 workspaceを表示し、残りを編集可能requestと最新response/failureに分割します。

DiagnosticsのFindings / DecisionTrace欄では、選択中のHTTP取引IDと観測済みrequest行を、scrollする評価行の上に固定表示します。同じURLへの繰り返しrequestは、省略しない取引IDで区別できます。request概要は通常最大2行、`z`で欄を拡大すると最大6行を使い、表示しきれない末尾には`... [shortened]`を付けます。拡大すると長いtargetをより多く確認でき、評価行は引き続きscrollできます。

各decision行には、その評価の接続情報を`接続元IP -> 要求先host:port / evaluated=IP:port`として付けます。DNS前は`evaluated=unresolved`、DNS候補の評価は各候補IP、HTTP bodyとCONNECT tunnelの検査は選択された接続先IPを表示します。評価結果と接続情報を一緒に保持するため、後から別のIPやrequestが届いても過去行の対象は変わりません。評価対象IPは接続成立の証明ではありません。評価時の接続情報がない行は`connection: unavailable`と表示します。

CONNECTは観測済みmethodとauthorityを表示し、tunnel内のURLは推定しません。origin-formや`*`のtargetには、同じ取引で観測したHost headerを明示します。request情報やHost headerがなければunavailableと表示し、sessionのtargetや別requestから補完しません。bounded snapshotを使い、terminal control文字をescapeし、payload captureや永続保存は追加しません。各Finding / DecisionTraceの評価行を維持し、Allowを通信成功や安全性の保証として扱いません。

HTTP Prettyはparsed request/status line、header、上限付きbodyをterminal幅で折り返します。有効なJSON bodyはindentします。Rawは保持した正確なHTTP/1 ingress byteを表示し、terminal control byteをescapeします。Hexは同じbyteをoffset/ASCII付きで表示します。正確なHTTP Rawは現在plain explicit HTTP/1 forwardingで利用できます。local synthetic response、intercepted HTTP/1、HTTP/2はsemantic Prettyを表示し、Raw unavailableを明示します。TCPのRaw/HexはHTTP message captureではなく、上限付きobserved stream snapshotを使います。

Raw captureはTUI専用のbest-effort observerです。headless modeには設置せず、forwardingを遅延できません。protocol結果はHyperがacceptedしたrequestを正とします。capture failure/truncationはnetwork結果を変えずStatisticsに表示します。

operational `tracing` lineはraw terminalへ直接書かず、同じbounded presentation channelを通るためcursor位置とlayoutを壊しません。best-effort queueが満杯でもforwardingは継続し、data-plane metrics snapshotの`event_sink_dropped_events`が増えます。

normal exit、error、panic unwind時にはRAII guardがterminalを復元します。cleanupできない方法でprocessを終了した場合は、shellのterminal reset commandを実行してください。

## Hook mode

| mode | 挙動 |
| --- | --- |
| `disabled` | 登録済みHookを呼び出さない。headless profileが選択 |
| `automatic` | 登録済みin-process Hookをtimeout付きで実行 |
| `interactive` | default。上限付きHTTP requestごとに1回だけTUI decisionまでpause |

interactive modeには`ui = "tui"`が必要で、不正な組み合わせは設定compile時に失敗します。enforcementが制御するのはpolicy actionでありoperator responseではないため、observe modeでもcontinue、reject、edit decisionは有効です。

automatic HookはHTTP request head/body、HTTP response head/body、両方向のTCP chunkという6つのtyped stageを維持します。HTTP Hookは型付きheaderまたはdecoded-body mutation planを返します。hop-by-hop header変更は拒否し、body置換後はHTTP engineがframingと`Content-Length`を再構築します。Hookは任意HTTP wire byteを書けません。

interactive controlは意図的に狭くしています。Frejaは`limits.body_prefix_bytes`以内でHTTP requestを収集し、preflight inspectionと登録済みrequest mutationを行った後、upstream forwarding前に1回pauseします。interactive上限を超えるrequest bodyには413を返します。responseは表示するだけでpauseしません。CONNECTはcommit前にempty bodyで1回pauseします。TCPは観測可能ですがoperator pauseを行わずforwardingを継続します。manual TCP drop/mutationはdeferredです。

:::note
同梱CLIのautomatic hook registryは現在空です。automatic modeはFreja crateをembedし、in-process Hookを登録するapplication向けです。設定だけでHook codeをloadすることはありません。
:::


## 評価で使ったルールを確認する

TrafficでHTTP取引またはTCP sessionを選び、`2`でDiagnosticsへ移ります。
Findings / DecisionTraceでは`j`/`k`で次／前の**Decision**を選択し、`>`で明示します。
`Enter`で読み取り専用の詳細を開きます。Findingは観測結果であり、detector IDが
rule IDと同じでもDecisionとして選択しません。`z`でペインを拡大し、arrowと
PageUp/PageDownで評価本文をscrollできます。詳細内では`j`/`k`、arrow、
PageUp/PageDownでscrollし、Homeで先頭へ戻ります。`Enter`または`q`は詳細だけを
閉じ、元の選択・閲覧位置・ペイン拡大を維持します。

詳細は取引／session、評価、判断時の世代とstageを示します。ACLでは先に、当時の
設定件数・宣言順・既定アクション・そのstageで利用できる入力を表示します。
空のACLなら「ルールが設定されていなかった」と明示します。ルールがあれば、実際の
条件不一致、必要な情報がそのstageでは未取得、先行ruleの一致による未評価を件数で
区別し、宣言順にID・条件・アクション・評価結果を表示します。例えばCONNECTの
`ResolvedDestination`評価では解決済みIPはありますが、HTTP method・path・headerは
入力に含まれません。path条件の未評価を、安全なpathだったという意味には扱いません。
接続先保護やpayload inspectionは別のcheckなので、ACLが空でも全保護が無効とは限りません。

定義の条件と設定アクション、記録された一致理由、policyのアクション種別を分けます。
ACL条件はJSON表現で、
`all`/`any`の全枝、`not`、両端を含むport範囲、hostnameの照合種別、header substringを
保持します。detourには接続先も含みます。評価結果は実際に評価した式全体についての
もので、不一致の各leafの特定や、first-matchで省略したruleの追加評価は行いません。
検出ルールには実際に選ばれたpattern policy、
十進数のbyte列、directionを示します。組み込み接続先保護、CONNECT port制限、
個別ruleのない既定方針は出所を区別し、原文TOMLや設定行番号を作りません。

Observeではpolicy上のdenyが遮断を意味しません。判断時snapshotのenforcementを
表示しますが、その評価だけから実際の通信結果は確定できず、Streamingで送信済みの
byteを取り戻すこともできません。

新しい通信が到着してもDiagnosticsの対象アクセスを保ちます。対象を変えるには
Trafficで別の行を選びます。開いた詳細を固定しても通信は継続します。同じIDのruleを
reloadしても旧定義を維持し、reload前から継続するscannerも判断時の世代を使います。
元の評価が保持上限で削除された場合は欠落を表示し、閉じても別の評価へ置き換えません。
`j`/`k`で保持中の評価を明示的に選ぶか、TrafficからDiagnosticsへ入り直して対象を
選びます。未保持の定義はunavailableとし、現在の同名ruleで補完しません。

定義は機密を含むlocalな一時情報です。条件・アクションは各16 KiBまで保持し、
不完全な場合は保持したprefixの前に警告を表示します。ACLの設定情報には既定動作と
先頭64件までのrule定義を追加保持し、定義一覧全体にも16 KiBの上限を設けます。
件数はpolicy全体について正確に保持し、採用ruleの定義は一覧の範囲外でも別途保持します。
件数上限・byte上限の両方による省略を明示します。一致理由は最大64件、
criterionとvalueは各1 KiB、詳細のrequest概要は16 KiBまでで、省略を明示します。
既存の行数・行内件数上限と、追加で開く詳細一件に保持量を制限します。terminal control
文字をescapeし、serializeするUIイベントやauditには定義を入れません。
audit/replay schema、capture、hook、forwardingの意味は変えません。

無害なfixtureと利用観察の手順は[ルール確認lab](../../developer/testing/#rule-inspection-lab)を参照してください。


## navigationとinteractive操作

| key | action |
| --- | --- |
| `1` / `2` / `3` | Traffic / Diagnostics / Repeatを選択 |
| `v` | split / request全幅 / response全幅をcycle |
| `m` | Pretty / Raw / Hexをcycle |
| `h` / `l` | request/client側またはresponse/upstream側を選択 |
| Ctrl+`j` / Ctrl+`k`、Tab | pane間でfocusを移動。Repeatではworkspace、request、latest resultの順にcycle |
| `j` / `k`、arrow | flow/workspace選択またはfocused detail paneをscroll |
| PageDown / PageUp | 10 row scroll |
| Enter | Diagnosticsでは選択したDecisionのルールを開く。それ以外はfocused paneを拡大 |
| Findings / DecisionTraceの`z` | 評価ペインを拡大 |
| ルール詳細のEnter / `q` | 詳細だけを閉じ、選択・scroll・ペイン拡大を維持 |
| `q` | floating表示を閉じて戻る |
| Ctrl+C / `Q` | 終了してterminalを復元 |

requestのpause中は次を操作できます。

| key | action |
| --- | --- |
| `c` | 変更せずcontinue |
| `r` | protocol commit前にreject |
| `e` | HTTP/1.1 request editorをNormal modeで開く |
| `i` | HTTP/1.1 request editorをInsert modeで開く |
| `x` | 保留中の変更をcancel |
| Shift+`R` | 元requestを変更せずcontinueし、copyをRepeatへ保持 |

Normal modeからは`i`でInsert modeへ入り、arrowまたは`h`/`j`/`k`/`l`で移動し、`s`またはCtrl+Sでvalidateしてsubmitします。Insert modeのEnterは改行を挿入し、EscでNormal modeへ戻ります。draftを破棄する`q`はNormal modeだけで有効です。Ctrl+Cと`Q`はどちらのmodeでもapplicationを終了します。

同梱editorはtextとして表現できるHTTP/1.1 requestを対象にします。end-to-end headerとUTF-8 bodyを1つの原子的decisionで変更でき、重複headerと複数行bodyにも対応します。method、request target、version、Host、hop-by-hop field、framing headerはread-onlyです。submit時に`httparse`でparseし、型付きmutation planへ変換して設定済みheader/body byte上限を検証した後、proxyが`Content-Length`を再構築します。HTTP/2と非UTF-8 requestは観測できますがtext editorでは開けません。

bounded queue、`limits.paused_flows`、`limits.interception_timeout_ms`により無期限の蓄積を防ぎます。CLIのtimeout動作はfail-closedです。

## Repeat workspace

Shift+`R`は、absolute `http`または`https` targetを持つ、現在pause中のtextual HTTP/1.1 requestだけで利用できます。独立した上限付きdraftを作成し、元requestは変更せず即座にcontinueします。CONNECTとHTTP/2はrepeat modeへ移せません。HTTPS draftはTLS interception allowlistで既に許可されたhostnameだけを対象とし、IP literalは引き続き除外します。

`q`、`1`、`2`で別pageへ戻ってもRepeat workspaceは残ります。個数は`ui_retained_rows`で制限し、draftを暗黙にevictしません。各workspaceのin-flight attemptは1件だけで、最新resultだけを保持します。`j`/`k`またはarrowでworkspaceを選びます。Ctrl+`j` / Ctrl+`k`またはTabでworkspace一覧、編集可能request、latest resultの順にfocusを移動でき、detail paneをfocusした後は`j`/`k`、arrow、PageDown/PageUpでscrollできます。`e`/`i`で編集して送信、`s`で保存済みdraftを再送、`d`でin-flightでないworkspaceを削除します。`q`はdraftを削除せずRepeatを開いたpageへ戻ります。

送信ごとに新しい`SessionId`と`TransactionId`を作ります。policy factでは元client IPを維持し、proxy credentialを除去して`Host`とframingを再生成します。そのうえで現在のrequested/resolved destination check、HTTP request/response ACL、inspection、typed Hook、必要なauthenticated upstream TLS、audit、replay-fact publicationを再実行します。interactive brokerだけを意図的に迂回するため、repeat自身は再pauseしません。attemptはlocal TUI内部から生成されるためproxy listener authenticationは再実行しません。response bodyは最後までdrainしますが`ui_content_bytes`までしか保持せず、repeat resultはingress wire captureではないsemantic snapshotなのでRaw/Hexはunavailableを表示します。

CONNECT成功後はtunnelなのでHTTP reject/redirectを挿入できません。manual actionは編集内容を保存せず監査します。

開発者向けcontractは[型付きHook設計](/ja/developer/hooks/)を参照してください。
