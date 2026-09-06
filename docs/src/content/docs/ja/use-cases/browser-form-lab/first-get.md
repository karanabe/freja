---
title: 最初のGET
description: GET一件をbrowser、Freja TUI、origin stdout、responseで照合します。
publishedAt: 2026-09-06
updatedAt: 2026-09-06
tags:
  - tui
  - interception
  - testing
sidebar:
  order: 3
  label: 最初のGET
prev:
  link: /ja/use-cases/browser-form-lab/setup/
  label: labの準備
next:
  link: /ja/use-cases/browser-form-lab/interventions/
  label: POSTと介入操作
---

**前提：** [labの準備](../setup/)を終え、Terminal Aにorigin、Terminal BにFreja、専用browserに`/lab`が表示されています。このpageではGET一往復を照合します。TUI図はbrowser準備時の入口pauseにも使えます。loopbackのsynthetic dataだけを使い、stdout・echo・TUIの非redact表示に注意してください。成功後は[POSTと介入操作](../interventions/)、または[終了](../cleanup-and-recovery/#cleanup)へ進みます。

[lab概要とpage map](../#page-map)

<a id="tui-map"></a>

## TUI図：入口GETを選択した状態

現行rendererとlocalの`/lab` pause表示に照合したTraffic/Pretty/Splitの代表図です。
空行は省略し、`<TransactionId>`は実IDの代わり、**T1〜T4は文書用の注記**でUI labelではありません。
実際の罫線・折返し・表示できるhintはterminal幅とdataで変わり、最小サイズは80×24です。
図は`1`を押し、Flowsにfocusを置いた状態を表します。

```text
+[T1] Flows [1 Traffic]  mode=Pretty layout=Split  Ctrl+j/k pane | Enter expand-----------------------------------------------------------------------+
|[T2] > HTTP paused <TransactionId> GET http://127.0.0.1:3001/lab HTTP/1.1                                                                            |
|                                                                                                                                                     |
+-----------------------------------------------------------------------------------------------------------------------------------------------------+
+[T3] Request [Pretty]  m mode | v split/request/response | h/l side------+ +[T4] Response [Pretty]  m mode | v split/request/response | h/l side-----+
|GET http://127.0.0.1:3001/lab HTTP/1.1                                   | |No content observed                                                      |
|host: 127.0.0.1:3001                                                     | |                                                                         |
|                                                                         | |                                                                         |
+-------------------------------------------------------------------------+ +-------------------------------------------------------------------------+
```

1. **T1 — 上部Flows title：** `1`でTrafficへ戻りFlowsをfocusします。
   そこで`j/k`または矢印で行を選びます。`Ctrl+j/k`・Tabはpane focusの移動、
   Enterはfocus中paneの拡大、`q`は拡大を閉じる操作です。
2. **T2 — 選択行：** `>`が選択、`paused`が待機を示し、実TransactionIdで操作対象を一件に定めます。
   `/lab`を照合して`c`でcontinueします。editor外の選択済みpaused requestでは
   `e/i`が編集、`r`がreject、Shift+RがcontinueとRepeat draft作成です。
   これらは操作キーであり、図のTrafficに常設footerとして表示されるわけではありません。
3. **T3 — 下段Request：** HTTP/1.1・target・headerを見ます。POSTのcaseはbodyにあります。
   titleには`m`（Pretty/Raw/Hex）、`v`（layout）、`h/l`（side）のhintがあります。
   detailにfocusがあると`j/k`は行選択ではなくscrollになります。
4. **T4 — 下段Response：** 転送前は`No content observed`を期待し、`c`後に同じtransactionの
   responseを確認します。editorのInsert modeではdraftへ入力するため、EscでNormalへ戻り
   `s`で提出します。editor外の`3`はRepeat、そのpageの`s`は選択draftの送信です。
   `Q`/Ctrl+Cはeditor内からもFrejaを終了するので、操作キーの前にmode/focusを確認します。

<a id="step-5"></a>

<a id="5-getを一件送りcontinue後に四つの表示を照合する"></a>

<a id="get-round-trip"></a>

## GETを一件送り、continue後に四つの表示を照合する

**操作 — browser：** **GET**を選び、**Case label**を`get-01`、**Message**を
`hello origin`にします。**Prepared encoding — not sent yet**は次の表示になります。

```text
GET /lab/get?case=get-01&message=hello+origin
(empty body)
```

<a id="browser-map"></a>

### browser図：入力を確認してSendを押す

![実際のlocal labの送信前画面。GETを選び、caseはget-01、messageはhello origin。Send GET queryにfocusがあり、下にはPrepared encodingと未送信のLast submitted bytes・Latest response欄が見える。](/images/browser-form-lab/get-ready.png)

*図B — 実際の`/lab`から入力・結果sectionを切り出したcaptureです。
合成GET入力を用意し、**Send GET query**にfocus枠を表示しています。まだ送信していません。
Freja経由の証拠ではなく、Firefoxや別OSではnative controlの見た目が異なる場合があります。*

1. **B1 — 最上部のMethod and input location：** ここではGETを選び、[変更しないPOSTの例](../interventions/#continue-post)ではPOSTを選びます。
2. **B2 — 次のCase label欄：** `get-01`を入力し、次の送信では別caseにします。
3. **B3 — Messageのtextarea：** `hello origin`を入力し、button下のPrepared encodingを確認します。
   未送信の時点で`message=hello+origin`と表示されます。
4. **B4 — 左側の塗りつぶしたSend GET query：** 一度だけ押すか、focusしてEnterを押します。
   右のClear messageはmessageを空にするだけです。POST選択時の実際のbutton名は
   **Send POST body**です。
5. **B5 — 下sectionのLast submitted bytes：** Send後はFreja編集前のquery/bodyを固定表示します。
   図では未送信なのでNo submissionです。
6. **B6 — B5の下のLatest response：** 判断後の受信byteとdecoded fieldをここで比較します。
   送信前にはresponseがありません。
7. **B7 — 最下部のReturn to input：** 試行終了時に有効になり、送信せずcaseへfocusを戻します。
   この未送信captureでは無効です。

画像を見られなくても以下の既存手順で操作できます。
撮影・更新条件は[developer testing](../../../developer/testing/#browser-lab-visuals)に記載しています。

**Send GET query**を一度だけ押し、browserを開いたままTerminal Bへ移ります。

**操作と表示 — Terminal B：** `1`、`j`/`k`で新しいpaused `/lab/get`行を選び、
request lineの**HTTP/1.1**と、HTTP行の完全な**TransactionId**を確認・記録します。
必要ならTabでFlowsからdetailへ移り、`h`でRequest、`m`でPretty/Raw/Hexを切り替えます。
semanticなfield確認にはPrettyを使います。`v`はsplit/request全幅/response全幅を巡回し、
Enterでfocus中paneを拡大、`q`で拡大を閉じます。`1`でFlowsのfocusへ戻れます。

**continue前の表示とEvidence：** browserは待機中、行は`paused`で、Terminal Aには
対応する`get-01`のHTTP requestがまだありません。upstream TCP接続だけ開いていても、
HTTP request到達とは別です。選択したrequestで**`c`**を押します。

| 見る場所 | continue後の期待する表示 | そのEvidenceから言えること |
| --- | --- | --- |
| Terminal B — Traffic | 同じTransactionId、HTTP/1.1のrequest line、response status 200。`l`でResponse側を選択。 | このrequest/responseをFrejaが観測した。 |
| Terminal A — origin stdout | `[received] GET /lab/get?case=get-01&message=hello+origin` | 対応するHTTP requestがoriginへ到達した。 |
| browser — Last submitted bytes | 元のencoded queryを保持 | このbrowser送信がFreja編集前に用意した内容。 |
| browser — Latest response | `http_version: "HTTP/1.1"`、一致する`received.uri`、`interpretation`の`kind: "fields"`、`case: "get-01"`、`message: "hello origin"` | originが受信・decodeしたと報告している内容。 |

これらを合わせて、このHTTP/1.1一往復がFreja経由だったと確認できます。
browser自身はFrejaのTransactionIdを読めないため、照合後も経路を**unverified**と表示します。
caseラベルは照合の補助でありIDではなく、Repeatでも再利用されます。

**Return to input (does not send)**を押すとcase欄へfocusが戻り、入力と前回結果が残ります。
次はcaseを変えてから明示的にSendします。結果はまだ前回送信に属しています。
**ここまでが最短の成功経路です。** [POSTと介入操作](../interventions/)へ続けるか、[後片付け](../cleanup-and-recovery/#cleanup)へ進んでください。
