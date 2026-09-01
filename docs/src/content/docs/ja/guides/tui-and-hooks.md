---
title: TUIと型付きHook
description: ratatuiでflowを観測し、automaticまたはinteractive Hookの挙動を理解します。
publishedAt: 2026-08-31
updatedAt: 2026-09-01
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

実terminalでFrejaを起動します。flow、HTTP metadata、上限付きhex/ASCII prefix、finding、decision trace、operational log、counterを表示します。operational `tracing` lineはraw terminalへ直接書かず、同じbounded presentation channelを通るためcursor位置とlayoutを壊しません。best-effort queueが満杯でもforwardingは継続し、data-plane metrics snapshotの`event_sink_dropped_events`が増えます。

normal exit、error、panic unwind時にはRAII guardがterminalを復元します。cleanupできない方法でprocessを終了した場合は、shellのterminal reset commandを実行してください。

## Hook mode

| mode | 挙動 |
| --- | --- |
| `disabled` | default。登録済みHookも呼び出さない |
| `automatic` | 登録済みin-process Hookをtimeout付きで実行 |
| `interactive` | 上限付きstageをTUI decisionまでpause |

interactive modeには`ui = "tui"`が必要で、不正な組み合わせは設定compile時に失敗します。

FrejaはHTTP request head/body、HTTP response head/body、両方向のTCP chunkという6 stageを定義します。HTTP Hookは型付きheaderまたはdecoded-body mutation planを返します。hop-by-hop header変更は拒否し、body置換後はHTTP engineがframingと`Content-Length`を再構築します。Hookは任意HTTP wire byteを書けません。

:::note
同梱CLIのautomatic hook registryは現在空です。automatic modeはFreja crateをembedし、in-process Hookを登録するapplication向けです。設定だけでHook codeをloadすることはありません。
:::

## interactive操作

requestのpause中は次を操作できます。

| key | action |
| --- | --- |
| `c` | 変更せずcontinue |
| `r` | protocol commit前にreject |
| `e` | 上限付き`name:value` header置換を入力 |
| `b` | 上限付きbody置換を入力 |
| `x` | 保留中の変更をcancel |
| Enter | editor入力をsubmit |
| Esc | editorまたはUIを閉じる |

manual headerは8 KiB、bodyは4 KiBが上限です。bounded queue、`limits.paused_flows`、`limits.interception_timeout_ms`により無期限の蓄積を防ぎます。CLIのtimeout動作はfail-closedです。

CONNECT成功後はtunnelなのでHTTP reject/redirectを挿入できません。TCP rejectはflowをcloseします。manual actionは編集内容を保存せず監査します。

開発者向けcontractは[型付きHook設計](/ja/developer/hooks/)を参照してください。
