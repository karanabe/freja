---
title: 終了と復旧
description: 今回のlabを終了し、専用profileを削除して、失敗からの復帰と観察記録を確認します。
publishedAt: 2026-09-06
updatedAt: 2026-09-06
tags:
  - tui
  - interception
  - testing
sidebar:
  order: 5
  label: 終了と復旧
prev:
  link: /ja/use-cases/browser-form-lab/interventions/
  label: POSTと介入操作
next:
  link: /ja/use-cases/browser-form-lab/http-contract/
  label: Web/API契約
---

**前提：** labを利用し、terminalとprofile変数を残しているか、失敗した試行からの復帰が必要な状態です。このpageでは終了と後片付けを行い、[失敗からの復帰](#failure-and-re-entry)と[上限・観察記録](#bounds-and-observation-record)を確認します。process停止前に[POSTと介入操作](../interventions/)のpending操作を処理してください。残す記録はsyntheticなものだけにし、responseの調査には次の[Web/API契約](../http-contract/)を使います。

[lab概要とpage map](../#page-map)

<a id="cleanup"></a>

<a id="step-11"></a>

<a id="11-終了して後片付けする"></a>

## 終了して後片付けする

**操作と表示：** 自分のpending requestを完了またはrejectし、Repeat送信中なら完了を待ちます。
今回開いた専用browser windowをすべて閉じます。Terminal Bで**Q**またはCtrl+Cを押し、通常のterminalへ
戻ることを確認します。Terminal AはCtrl+Cで停止し、shellへ戻ります。
停止するのは今回自分で起動したprocessだけです。browser/OSのproxy設定を手動変更した場合は、
通常の閲覧へ戻る前に元の値へ戻します。

Terminal Cで、作成した使い捨てprofileのpathを確認します。

```sh
printf '%s\n' "${lab_proxy_profile:-}" "${lab_direct_profile:-}" "${lab_firefox_profile:-}"
```

該当browser processが終了してから、必要なら表示されたlab directoryを削除します。
上の空行は、その選択肢を使わなかったという意味です。同じshellで、実際に作成した
profileのコマンドだけを選びます。各`${variable:?}`は[専用browserの設定](../setup/#dedicated-browser)で説明したとおり、
未設定・空のpathでの実行を止めます。

Chromiumの場合（二行目は[直通対照](../interventions/#direct-control)で直通profileを作った場合だけ）：

```sh
rm -r -- "${lab_proxy_profile:?}"
rm -r -- "${lab_direct_profile:?}"
```

Firefoxの場合、lab processが終了してから：

```sh
rm -r -- "${lab_firefox_profile:?}"
```

**Evidenceと残るfile：** `/lab`にfixtureの履歴・payload保存はありませんが、browser profileは
自身のfileを持ち、Frejaの既存audit writerはsampleのaudit pathへ
`freja-<timestamp>-<pid>-<collision>.jsonl`を作成します。
運用出力の`audit segment created` pathを確認します（TUI使用中はDiagnosticsのlog）。
今回のsegmentを特定してから、必要に応じて保管・削除してください。
他runのaudit fileまで一括削除しないでください。build artifactは残ります。
sensitiveなtrafficを含むterminal録画等は残さないようにします。

<a id="failure-and-re-entry"></a>

## 失敗からの復帰と再入力

失敗時は現在の**Last submitted bytes**、対応するTUI transaction、Terminal Aを確認してから
次の試行へ進みます。request完了またはbrowser待機終了後、Return to inputで値を保持したまま
case欄へ戻り、caseを変えて明示的にSendします。pending中は追加送信を無効にし、前のresponseを
消します。自動retry、POST navigation、redirect追従、履歴の再送は行いません。
45秒のbrowser待機をabortしても送信済みbyteを撤回できず、未到達の証明にもなりません。

| 症状・制御した確認例 | 見る場所と操作 | Evidenceと復帰 |
| --- | --- | --- |
| case不正・ページでの入力上限超過 | browserの検証表示。例えば`界`86文字（UTF-8で258 bytes）。 | Sendを止める。byte上限内へ短くする。新しいTUI/origin requestはないはず。 |
| ページ・入力操作・styleが欠ける | Terminal Bの`/lab`、`/lab/app.js`、`/lab/style.css`のpause。 | 各requestをcontinue。期限切れ後は入口GETをreloadして新pauseを扱う。browserでJavaScript無効の場合もformは操作できない。 |
| Send後に待機 | Trafficで対応paused transactionを照合。 | 30秒以内に判断。待機だけではpauseや未到達を確定できない。 |
| 400 / 415のlab receipt | browserの`received`と`interpretation.reason`。 | originはformとして受け付けないbyteを受信した。入力または編集を直し、新しい試行へ。 |
| labの413・表示省略 | error、omission flag、下記byte上限。 | byte/headerを取得できない場合がある。入力を減らし、欠落を空値と解釈しない。 |
| 判断timeoutの対照確認 | 新caseを送り意図的に30秒超判断せず、行と両terminalを確認。 | sampleは504 `interactive interception failed`、auditは`failed`。他broker失敗でも共通なので、意図した待機を追加証拠にする。次は新case。 |
| origin未起動・停止 | 前の試行完了後、Terminal AだけをCtrl+Cで止め、新caseを送る。 | 通常proxyの502だが起動・network失敗で表示は異なり得る。origin receiptはない。[originのready確認](../setup/#origin-readiness)で再起動・ready確認し、再入力で新caseを送る。 |
| network error・45秒でbrowser待機終了 | 両processの起動と、Freja側でまだpendingかを確認。 | 到達は未確認。旧transactionを調べて処理してから次を送る。 |
| echoはあるがTUI transactionがない | [直通対照](../interventions/#direct-control)とbrowser proxy設定を比較。 | Freja経由は未確認。proxied profileへ戻し、新transactionで照合する。 |
| `r`・`s`・移動が意図どおりでない | editorのInsert modeやpane拡大を確認。 | Escまたは`jj`でInsertを抜け、Normal modeの`q`でeditor draftを破棄。その外では`q`で拡大を閉じ、`1`でTraffic/Flowsへ。操作キーをbodyへ入力しない。 |

<a id="bounds-and-observation-record"></a>

## 上限と観察記録

| 対象 | 上限 |
| --- | --- |
| field | `case`と`message`の二項目だけ。重複・未知・欠落を拒否。空messageは許可。 |
| case | ASCII英数字・`_`・`-`の1〜32文字 |
| message | UTF-8で0〜256 bytes。`maxlength`だけでなくbrowser/server双方で検証。 |
| encoded query/body | 各2 KiB。不正percent encoding・非UTF-8 fieldを拒否。 |
| receiptのheader/URI | header値32件まで、name/value合計1 KiB。URI prefixは2 KiBまでで省略flag付き。 |
| response/browser表示 | 各64 KiB。過大responseの読取を止め、整形で増えたtextは省略を明示。 |
| 既存origin/interactive sample | body guard 1 MiB、escaped stdout body preview 4 KiB。interactive body 16 KiB、判断timeout 30秒。 |

exampleは7 production crateの外にある独立した非公開workspaceで、既存echo captureと
request logを再利用します。policy、enforcement既定値、TUIの編集境界、audit/replay schemaを
labのために変更しません。live出力は意図的に非redactなので、audit captureがmetadata-onlyでも
synthetic dataだけを使います。

[developer tests](../../../developer/testing/#browser-form-fixture)はlocal HTTP契約、実Frejaの
介入経路、Chromium動作を確認します。browser失敗・遅延simulationやtyped brokerでの判断は
自動fixtureであり、maintainerによるbrowser＋TUI利用観察ではありません。
各手動stepはrevision、browser/OS・proxy設定、case、HTTP/1.1の根拠、元/新transaction ID、
origin到達、再入力、迷った操作を記録します。未実施stepは**未観察**としてください。
実credentialやpayloadを保存せず、tests成功だけでoperatorのOutcomeや使いやすさの改善を
達成済みにしないでください。

Firefox/macOS実機と、maintainerによる一連のbrowser＋TUI通し操作は引き続き**未観察**です。Chromiumの自動fixture、実TUIの限定確認、未送信画像では代替できません。
