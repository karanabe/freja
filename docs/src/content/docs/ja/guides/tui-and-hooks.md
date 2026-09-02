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
enforcement = "enforce"
hooks = "interactive"
```

repositoryのdefault interactive profileは直接起動できます。

```sh
cargo run -p freja -- run --config examples/config/tui/freja.toml
```

`examples/config/tui/freja.interactive.toml`は、小さい上限とpreflight inspectionを使うHTTP専用variantです。各example profileはlistener portを共有するため、1つずつ起動してください。

実terminalでFrejaを起動します。この画面のtraffic contentは意図的にredactせず、credential、cookie、query secret、個人情報を含む可能性があります。信頼できるlocal terminalだけで使用してください。audit redactionは変更されません。

TUIには3 pageあります。

- **1 Traffic**: 上25%をfull-widthのFlows listに使い、残りをdefaultでRequest/Client-to-Upstream 50%とResponse/Upstream-to-Client 50%に分割します。HTTPの1 rowは`TransactionId`、TCPの1 rowは`SessionId`を表します。
- **2 Diagnostics**: 上45%をFindings / DecisionTrace、可変の中央領域をOperational logs、末尾8 rowをStatisticsに使います。
- **3 Repeat**: 上25%に保持したHTTP/1.1 workspaceを表示し、残りを編集可能requestと最新response/failureに分割します。

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

interactive modeには`ui = "tui"`が必要で、不正な組み合わせは設定compile時に失敗します。

automatic HookはHTTP request head/body、HTTP response head/body、両方向のTCP chunkという6つのtyped stageを維持します。HTTP Hookは型付きheaderまたはdecoded-body mutation planを返します。hop-by-hop header変更は拒否し、body置換後はHTTP engineがframingと`Content-Length`を再構築します。Hookは任意HTTP wire byteを書けません。

interactive controlは意図的に狭くしています。Frejaは`limits.body_prefix_bytes`以内でHTTP requestを収集し、preflight inspectionと登録済みrequest mutationを行った後、upstream forwarding前に1回pauseします。interactive上限を超えるrequest bodyには413を返します。responseは表示するだけでpauseしません。CONNECTはcommit前にempty bodyで1回pauseします。TCPは観測可能ですがoperator pauseを行わずforwardingを継続します。manual TCP drop/mutationはdeferredです。

:::note
同梱CLIのautomatic hook registryは現在空です。automatic modeはFreja crateをembedし、in-process Hookを登録するapplication向けです。設定だけでHook codeをloadすることはありません。
:::

## navigationとinteractive操作

| key | action |
| --- | --- |
| `1` / `2` / `3` | Traffic / Diagnostics / Repeatを選択 |
| `v` | split / request全幅 / response全幅をcycle |
| `m` | Pretty / Raw / Hexをcycle |
| `h` / `l` | request/client側またはresponse/upstream側を選択 |
| Ctrl+`j` / Ctrl+`k`、Tab | 上下のpane間でfocusを移動 |
| `j` / `k`、arrow | flow選択またはfocused paneをscroll |
| PageDown / PageUp | 10 row scroll |
| Enter | focused paneをfloating表示へ拡大 |
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

`q`、`1`、`2`で別pageへ戻ってもRepeat workspaceは残ります。個数は`ui_retained_rows`で制限し、draftを暗黙にevictしません。各workspaceのin-flight attemptは1件だけで、最新resultだけを保持します。`j`/`k`またはarrowでworkspaceを選び、`e`/`i`で編集して送信、`s`で保存済みdraftを再送、`d`でin-flightでないworkspaceを削除します。`q`はdraftを削除せずRepeatを開いたpageへ戻ります。

送信ごとに新しい`SessionId`と`TransactionId`を作ります。policy factでは元client IPを維持し、proxy credentialを除去して`Host`とframingを再生成します。そのうえで現在のrequested/resolved destination check、HTTP request/response ACL、inspection、typed Hook、必要なauthenticated upstream TLS、audit、replay-fact publicationを再実行します。interactive brokerだけを意図的に迂回するため、repeat自身は再pauseしません。attemptはlocal TUI内部から生成されるためproxy listener authenticationは再実行しません。response bodyは最後までdrainしますが`ui_content_bytes`までしか保持せず、repeat resultはingress wire captureではないsemantic snapshotなのでRaw/Hexはunavailableを表示します。

CONNECT成功後はtunnelなのでHTTP reject/redirectを挿入できません。manual actionは編集内容を保存せず監査します。

開発者向けcontractは[型付きHook設計](/ja/developer/hooks/)を参照してください。
