---
title: TUIと型付きHook
description: ratatuiでflowを観測し、automaticまたはinteractive Hookの挙動を理解します。
publishedAt: 2026-08-31
updatedAt: 2026-09-02
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
hooks = "disabled"
```

実terminalでFrejaを起動します。この画面のtraffic contentは意図的にredactせず、credential、cookie、query secret、個人情報を含む可能性があります。信頼できるlocal terminalだけで使用してください。audit redactionは変更されません。

TUIには2 pageあります。

- **1 Traffic**: 上25%をfull-widthのFlows listに使い、残りをdefaultでRequest/Client-to-Upstream 50%とResponse/Upstream-to-Client 50%に分割します。HTTPの1 rowは`TransactionId`、TCPの1 rowは`SessionId`を表します。
- **2 Diagnostics**: 上45%をFindings / DecisionTrace、可変の中央領域をOperational logs、末尾8 rowをStatisticsに使います。

HTTP Prettyはparsed request/status line、header、上限付きbodyをterminal幅で折り返します。有効なJSON bodyはindentします。Rawは保持した正確なHTTP/1 ingress byteを表示し、terminal control byteをescapeします。Hexは同じbyteをoffset/ASCII付きで表示します。正確なHTTP Rawは現在plain explicit HTTP/1 forwardingで利用できます。local synthetic response、intercepted HTTP/1、HTTP/2はsemantic Prettyを表示し、Raw unavailableを明示します。TCPのRaw/HexはHTTP message captureではなく、上限付きobserved stream snapshotを使います。

Raw captureはTUI専用のbest-effort observerです。headless modeには設置せず、forwardingを遅延できません。protocol結果はHyperがacceptedしたrequestを正とします。capture failure/truncationはnetwork結果を変えずStatisticsに表示します。

operational `tracing` lineはraw terminalへ直接書かず、同じbounded presentation channelを通るためcursor位置とlayoutを壊しません。best-effort queueが満杯でもforwardingは継続し、data-plane metrics snapshotの`event_sink_dropped_events`が増えます。

normal exit、error、panic unwind時にはRAII guardがterminalを復元します。cleanupできない方法でprocessを終了した場合は、shellのterminal reset commandを実行してください。

## Hook mode

| mode | 挙動 |
| --- | --- |
| `disabled` | default。登録済みHookも呼び出さない |
| `automatic` | 登録済みin-process Hookをtimeout付きで実行 |
| `interactive` | 上限付きHTTP requestごとに1回だけTUI decisionまでpause |

interactive modeには`ui = "tui"`が必要で、不正な組み合わせは設定compile時に失敗します。

automatic HookはHTTP request head/body、HTTP response head/body、両方向のTCP chunkという6つのtyped stageを維持します。HTTP Hookは型付きheaderまたはdecoded-body mutation planを返します。hop-by-hop header変更は拒否し、body置換後はHTTP engineがframingと`Content-Length`を再構築します。Hookは任意HTTP wire byteを書けません。

interactive controlは意図的に狭くしています。Frejaは`limits.body_prefix_bytes`以内でHTTP requestを収集し、preflight inspectionと登録済みrequest mutationを行った後、upstream forwarding前に1回pauseします。interactive上限を超えるrequest bodyには413を返します。responseは表示するだけでpauseしません。CONNECTはcommit前にempty bodyで1回pauseします。TCPは観測可能ですがoperator pauseを行わずforwardingを継続します。manual TCP drop/mutationはdeferredです。

:::note
同梱CLIのautomatic hook registryは現在空です。automatic modeはFreja crateをembedし、in-process Hookを登録するapplication向けです。設定だけでHook codeをloadすることはありません。
:::

## navigationとinteractive操作

| key | action |
| --- | --- |
| `1` / `2` | Traffic / Diagnosticsを選択 |
| `v` | split/focused traffic detailを切替 |
| `m` | Pretty / Raw / Hexをcycle |
| `h` / `l` | request/client側またはresponse/upstream側を選択 |
| Tab | pane間でfocusを移動 |
| `j` / `k`、arrow | flow選択またはfocused paneをscroll |
| PageDown / PageUp | 10 row scroll |
| `q` | 終了してterminalを復元 |

requestのpause中は次を操作できます。

| key | action |
| --- | --- |
| `c` | 変更せずcontinue |
| `r` | protocol commit前にreject |
| `e` | 上限付き`name:value` header置換を入力 |
| `b` | 上限付きbody置換を入力 |
| `x` | 保留中の変更をcancel |
| Enter | editor入力をsubmit |
| Esc | editorを閉じる。通常時は終了しない |

manual headerは8 KiB、bodyは4 KiBが上限です。bounded queue、`limits.paused_flows`、`limits.interception_timeout_ms`により無期限の蓄積を防ぎます。CLIのtimeout動作はfail-closedです。

CONNECT成功後はtunnelなのでHTTP reject/redirectを挿入できません。manual actionは編集内容を保存せず監査します。

開発者向けcontractは[型付きHook設計](/ja/developer/hooks/)を参照してください。
