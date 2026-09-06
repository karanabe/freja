---
title: HTTP/1.1 browserフォームlab
description: local HTTP/1.1フォームlabの目的とpage map、証拠から判断できる範囲を確認します。
publishedAt: 2026-09-06
updatedAt: 2026-09-06
tags:
  - tui
  - interception
  - testing
sidebar:
  order: 1
  label: 概要
prev:
  link: /ja/use-cases/
  label: ユースケース
next:
  link: /ja/use-cases/browser-form-lab/setup/
  label: labの準備
---

`examples/http-test-server`は`http://127.0.0.1:3001/lab`にbrowserフォームを提供します。
これは**local development origin fixture**であり、Frejaのcontrol planeではありません。
ページは小さいfield二つを同じoriginへ送り、operatorの判断は既存のFreja TUIで行います。
まず[準備](./setup/)と[最初のGET](./first-get/)で一件をFreja経由で通し、その後POST・編集・reject・Repeatへ進みます。
[Web/API reference](./http-contract/#web-surfaces)と[失敗からの復帰](./cleanup-and-recovery/#failure-and-re-entry)は別pageで参照できます。

**synthetic dataだけを使ってください。** origin stdout、echo、live TUIには
Authorization/Cookieを含むheader、query、bodyが非redactで表示され得ます。
audit redactionとは別の境界です。echo成功だけではproxy経由を証明できません。

## このlabで確かめること

短いGET queryとPOST form bodyを送り、continue前後、許可された編集後、reject、
Repeatによる別送信を比較します。method・target・Host・framingは編集しません。
HTTP/1.1のlocal fixtureを使い、TLS/CA設定や任意の外部送信先は扱いません。

## 証拠の読み方

browserのPrepared encodingは送信予定、Last submitted bytesはFrejaの編集前の送信値です。
Latest responseはoriginが受け取ったbyteとその解釈を示します。FrejaのTransactionIdは
browserへ渡されないため、TUIの同じrequestとorigin stdoutを照合して初めて経路を確認できます。
TCP接続だけではHTTP request到達とは言えず、待機やlog欠落だけではrejectを証明できません。
Repeatの追加到達と新IDは元の送信とは別に確認します。

## Page map

最短の成功経路は**準備 → 最初のGET**です。続ける場合はPOSTと介入操作へ進み、
終える場合はいつでも後片付けを使います。目的からpageを選んでください。

| page | 前提・このpageで終えること | 次の行き先 |
| --- | --- | --- |
| **この概要** | 目的と証拠の境界を確認する。 | [準備](./setup/) |
| [labの準備](./setup/) | 道具・origin・Freja・ChromiumかFirefox一つを用意し、入口pauseを扱う。 | [最初のGET](./first-get/) |
| [最初のGET](./first-get/) | 起動済みのlabで、TUI図とbrowser画像を見ながら四つの表示を照合する。 | [POSTと介入操作](./interventions/)または[終了](./cleanup-and-recovery/#cleanup) |
| [POSTと介入操作](./interventions/) | GET成功後、POST・編集・reject・Repeat・直通対照を確認する。 | [終了と復旧](./cleanup-and-recovery/) |
| [終了と復旧](./cleanup-and-recovery/) | 自分のprocess/profile/auditを片付ける。失敗、上限、観察記録も参照できる。 | [Web/API契約](./http-contract/) |
| [Web/API契約](./http-contract/) | lab固有の5 path、receipt、error、既存JSON/curlを必要時に引く。 | [page mapへ戻る](#page-map) |

一般的なキー操作は[ガイド](../../guides/tui-and-hooks/)、設定全体の契約は
[リファレンス](../../reference/configuration/)にあります。

## 確認範囲

local自動検証と、実TUIの限定確認・送信前の実browser画像があります。
Firefox/macOS実機とmaintainerによる一連のbrowser＋TUI通し操作は**未観察**です。
tests成功や画像だけを、その利用結果の代わりにはしません。
[観察記録](./cleanup-and-recovery/#bounds-and-observation-record)を残して確認してください。
