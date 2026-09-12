---
title: POSTと介入操作
description: POSTのcontinue、許可された編集、operator reject、Repeat、直通接続を比較します。
publishedAt: 2026-09-06
updatedAt: 2026-09-06
tags:
  - tui
  - interception
  - testing
sidebar:
  order: 4
  label: POSTと介入操作
prev:
  link: /ja/use-cases/browser-form-lab/first-get/
  label: 最初のGET
next:
  link: /ja/use-cases/browser-form-lab/cleanup-and-recovery/
  label: 終了と復旧
---

**前提：** [最初のGET](../first-get/)を終え、同じorigin・Freja・proxy経由browserを起動したままにします。このpageではPOST・編集・reject・Repeat・直通対照を確認します。非redact出力にはsynthetic dataだけを使います。[GETの証拠照合](../first-get/#get-round-trip)と同じようにtransactionとorigin到達を対応させ、最後に[labを後片付け](../cleanup-and-recovery/)します。

[lab概要とpage map](../#page-map)

<a id="post編集rejectrepeat"></a>

## POST・編集・reject

各手順を読んでから送ってください。同じ30秒の判断timeoutが適用されます。
一件ずつ送り、POSTのcaseはbodyにあるため、同じ`POST /lab/post`行でもRequest内容と
TransactionIdで区別します。以下のTUI page切替・移動キーはeditorを閉じた状態で使います。

<a id="step-6"></a>

<a id="6-postを変更せずcontinueする"></a>

<a id="continue-post"></a>

### POSTを変更せずcontinueする

**操作 — browser：** Return to inputで戻り、**POST**、case `post-02`、message
`hello origin`を入力します。次のprepared内容を確認して**Send POST body**を押します。

```text
POST /lab/post
Content-Type: application/x-www-form-urlencoded

case=post-02&message=hello+origin
```

**操作と表示 — Terminal B：** `1`、`j`/`k`でpaused POSTを選びます。
HTTP/1.1と新しいTransactionIdを確認し、Request bodyの`post-02`を照合して**`c`**を押します。

**表示とEvidence：** Terminal Aの`[received] POST /lab/post`とbody、browserの
`received.body.utf8`が上のencoded bodyと一致します。`interpretation.message`は
`hello origin`です。encodedの`+`とdecodedの空白は、同じ入力の異なる表現です。
これで変更しない転送を確認できます。

caseを変え、空message、空白一文字、`日本語 &=+`でもこの手順を繰り返します。
空欄は`message=`、空白は`message=+`、値の`+`・`&`・`=`は`%2B`・`%26`・`%3D`になります。
日本語はUTF-8のpercent encodingです。GET queryにも同じencodingを使います。

<a id="step-7"></a>

<a id="7-別のpostをorigin到達前に編集する"></a>

<a id="edit-post"></a>

### 別のPOSTをorigin到達前に編集する

**操作 — browser：** POSTでcase `edit-03`、message `before`を送ります。
**操作 — Terminal B：** paused requestのbodyとIDを照合し、**`i`**でInsert modeの
editorを開きます。cursorはbody先頭にあります。

1. EndとBackspace/Deleteを使い、message値の`before`だけを`after`へ変更して
   `case=edit-03&message=after`にします。
2. 許可されたheaderも確認する場合は、body行でHome、その後Upで空の区切り行へ移ります。
   `X-Lab-Edit: yes`を入力し、Enterでheaderとbodyの間に空行を残します。
   header/bodyの境界を確認してください。
3. Escまたは`jj`でNormal modeへ戻り、**`s`**で検証・continueします。Ctrl+Sも送信できます。
   検証失敗ならeditorの説明を読み、pauseが切れる前に修正します。
   Normal modeの`q`はdraftを破棄するだけで、continue/rejectではありません。

**表示とEvidence：** Terminal Aとbrowser receiptに変更後のencoded bodyが出ます。
headerを追加した場合は`received.headers["x-lab-edit"]: ["yes"]`も確認します。
`interpretation.message`は`after`、**Last submitted bytes**は`before`のままです。
browser入力と、Frejaの編集後に届いたbyteを区別できます。Content-LengthはFrejaが再構築します。
method、target/query、version、Host、hop-by-hop、framing headerを編集しないでください。
GET queryの編集は対象外です。

任意の追加確認では、別のPOSTのbody全体を`changed text`へ変えて送ります。
labのHTTP 400、`received.body.utf8: "changed text"`、理由付きの
`interpretation.kind: "unavailable"`を確認します。originはbyteを受け取りましたが、
元の二field formは届いていません。全操作は[TUIと型付きHook](../../../guides/tui-and-hooks/)を参照してください。

<a id="step-8"></a>

<a id="8-新しいrequestをrejectする"></a>

<a id="reject-request"></a>

### 新しいrequestをrejectする

**操作 — browser：** POSTでcase `reject-04`、message `do-not-forward`を送ります。
**操作 — Terminal B：** paused body/TransactionIdを照合し、editorの外で**`r`**を押します。
TrafficのResponseを確認します。Diagnostics（`2`）でも選択requestと運用情報を確認でき、
`1`で戻れます。

**表示とEvidence：** browserにはproxyのHTTP 403と`rejected by operator`が表示され、
originのlab receiptはありません。Terminal Aには対応する`reject-04`のbodyがありません。
明示的な`r`、対応transaction、未到達を合わせて、HTTP転送前の拒否と確認できます。
log一行の欠落や一般的なエラーだけでは不十分です。Observeのpolicy denyも、
実際の遮断やoperator rejectとは別です。

**戻り方：** Return to inputでcaseを変更し、準備ができてからSendします。
戻る操作は拒否したPOSTを再送しません。

<a id="step-9"></a>

<a id="9-元requestをcontinueしrepeat-draftを送る"></a>

<a id="repeat-request"></a>

## 元requestをcontinueし、Repeat draftを送る

**操作 — browser：** POSTでcase `repeat-05`、message `repeat me`を送ります。
**操作 — Terminal B：** paused requestを選び、元のTransactionIdを記録して、
**`c`の代わりにShift+R**（大文字`R`）を押します。元requestを変更せずcontinueし、
保持したdraftが**3 Repeat**に開きます。

**Repeat送信前の表示：** Terminal Aに元requestが一回届き、browserはそのresponseを表示します。
Repeatのworkspace一覧は**source** TransactionIdと`ready`を示します。
draftを作るだけでは二回目の送信になりません。

**操作 — Terminal B：** 必要なら`3`でRepeatへ移り、`j`/`k`または矢印でworkspaceを選び、
**`s`**を一度押します。TabまたはCtrl+`j`/Ctrl+`l`で次へ、Ctrl+`h`/Ctrl+`k`で前へ
**Workspaces → Editable request → Latest result**とfocusを移します。
結果はPrettyで確認し、semantic snapshotのためRaw/Hexがunavailableでも異常ではありません。
focusしたdetailは`j`/`k`・矢印・PageDown/PageUpでscrollします。

**表示とEvidence：** workspaceは`sending`から`complete`となり、**Latest result**に
最新のHTTP responseが出ます。新しいTransactionIdは**`1`**でTrafficへ戻り、
追加された`/lab/post`行と`repeat-05`のbodyを選んで確認します。
記録済みの元IDとは異なります。**`3`**で保持したworkspaceとLatest resultへ戻れます。
workspace一覧のIDは**source**のままで、Latest result自体に新transaction IDは表示しません。
Terminal Aには同じcase/bodyのPOSTがもう一件届きます。各Repeatには新しいSessionIdと
TransactionIdが付き、**再pauseしません**。browserは元のresponseを表示したままです。
`q`ではdraftを消さずに戻り、`d`は送信中でない選択workspaceを削除します。

<a id="step-10"></a>

<a id="10-直通の対照例を確認しproxy経由へ戻す"></a>

<a id="direct-control"></a>

## 直通の対照例を確認し、proxy経由へ戻す

[専用browserの設定](../setup/#dedicated-browser)で選んだbrowserに対応する操作だけを行います。

**Chromium — Terminal C：** もう一つの使い捨てprofileを明示的な直通接続で開きます。
この直通windowとproxy経由のwindowを区別してください。

```sh
lab_direct_profile="$(mktemp -d /tmp/freja-lab-direct.XXXXXX)"
printf '%s\n' "$lab_direct_profile"
chromium --user-data-dir="$lab_direct_profile" \
  --proxy-server="direct://" http://127.0.0.1:3001/lab &
```

**Firefox — 専用lab window：** [専用browserの設定](../setup/#dedicated-browser)と同じ接続設定dialogで**No proxy（プロキシーを使用しない）**
を選んで保存します（`network.proxy.type`は`0`になります）。使い捨てlab profile内だけの
変更です。別profileを作る必要はありません。

**操作と表示 — 直通browser：** GETでcase `direct-control`、message `hello`を送ります。
Terminal AとこのbrowserにはHTTP/1.1 echoが出ても、Terminal Bに対応transactionはありません。
**Evidenceから言えること：** Frejaを通らなくてもoriginは成功応答を返せるため、
Freja経由は未確認です。

**復帰：** Chromiumでは元のproxy経由のwindowへ戻ります。FirefoxではManual proxy
configurationを再び選び、[専用browserの設定](../setup/#dedicated-browser)の5 preferenceを戻して確認し、保存します
（`network.proxy.type = 1`も含む）。新しいcase `proxy-again`で[GET一往復](../first-get/#get-round-trip)を繰り返します。
TUIで選択して`c`を押し、新しいTransactionIdと照合できればproxy経由へ戻せています。
照合できなければ経路未確認と記録してproxy設定を調べます。
stdoutに一行ないことだけで原因を推定しないでください。
