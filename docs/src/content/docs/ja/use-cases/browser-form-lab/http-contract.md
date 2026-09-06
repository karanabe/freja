---
title: Web/API契約
description: local originの5 path、receiptのfield、error、上限、既存JSON/curl互換を確認します。
publishedAt: 2026-09-06
updatedAt: 2026-09-06
tags:
  - tui
  - interception
  - testing
sidebar:
  order: 6
  label: Web/API契約
prev:
  link: /ja/use-cases/browser-form-lab/cleanup-and-recovery/
  label: 終了と復旧
next:
  link: /ja/use-cases/browser-form-lab/
  label: lab概要へ戻る
---

**このpageを使う場面：** labのrequestやreceiptを解釈したいときに参照します。fixtureの5 path、field、error、既存JSON/curl互換をまとめ、操作手順は追加しません。利用目的は[概要](../)、proxy経由の根拠は[最初のGET](../first-get/)、失敗した試行は[復旧と上限](../cleanup-and-recovery/)へ進みます。loopback開発originの契約です。echoのheader/bodyは非redactになり得るため、synthetic dataだけを使ってください。

[lab概要とpage map](../#page-map)

<a id="web-surfaces"></a>

## 追加したWeb surfaceとHTTP契約

次の5 pathはすべて**port 3001の開発origin**が提供します。port 8080のFreja proxyは、
他の許可されたHTTP requestと同様に転送します。continue、編集、reject、Repeat、process管理を
browserから行うcontrol endpointはありません。routerは
`examples/http-test-server/src/lab.rs`にあり、`src/routes.rs`でmergeします。
assetは`src/lab/`から埋め込みます。

### 新しいページ・asset・form endpoint

| Methodとpath | query/body、request Content-Type | origin response | 用途と上限 |
| --- | --- | --- | --- |
| `GET /lab` | form入力なし、Content-Type指定不要 | 200 `text/html; charset=utf-8` | browser入口。固定の埋め込みHTML。次の二assetを読む。 |
| `GET /lab/app.js` | form入力なし、Content-Type指定不要 | 200 `text/javascript; charset=utf-8` | 検証・encoding・上限付きfetch/表示・再入力の固定local script。 |
| `GET /lab/style.css` | form入力なし、Content-Type指定不要 | 200 `text/css; charset=utf-8` | 固定local layout、明色/暗色style。 |
| `GET /lab/get` | queryにURL-encodedの`case`と`message`、bodyは空。Content-Type不要 | 正常入力は200のreceipt JSON。エラーは下表。 | GET入力と到達の照合。queryは2 KiB以下、[field/表示上限](../cleanup-and-recovery/#bounds-and-observation-record)も適用。 |
| `POST /lab/post` | queryは空。bodyにURL-encodedの`case`と`message`。`Content-Type: application/x-www-form-urlencoded`必須 | 正常入力は200のreceipt JSON。エラーは下表。 | POSTのcontinue・編集・Repeat照合。bodyは2 KiB以下、Content-Encodingは受け付けない。 |

pathは完全一致です。入口は`/lab`であり`/lab/`ではありません。AxumのGET登録には
response bodyのないHEAD fallbackもありますが、ここで説明するform操作はGET/POSTを使います。
登録pathの非対応methodは405、未知pathは既存JSONの404 fallbackになります。
既存global 1 MiB body guardはstatic routeを含めlab handlerより前に適用されます。

lab handlerのresponseには`Cache-Control: no-store`、`X-Content-Type-Options: nosniff`、
`Referrer-Policy: no-referrer`と、script/style/接続を同一originへ制限するCSPを付けます。
ページはresponseを`textContent`とcontrol文字escapeで表示し、echoのmarkupをHTMLとして
実行しません。フォームに任意送信先、upload、credential、自由なmethod/headerの入力欄はありません。

## receiptのfieldとエラー

GET/POSTのreceiptは`application/json`です。[変更しないPOST](../interventions/#continue-post)の抜粋は次のとおりです。

```json
{
  "lab": "http11-browser-form",
  "http_version": "HTTP/1.1",
  "received": {
    "method": "POST",
    "uri": "/lab/post",
    "body": { "utf8": "case=post-02&message=hello+origin" }
  },
  "interpretation": { "kind": "fields", "case": "post-02", "message": "hello origin" }
}
```

上は一部fieldを省いた抜粋です。完全なreceiptは次を含みます。

| Field | 意味 |
| --- | --- |
| `lab` | fixture markerの`http11-browser-form`。認証されたproxy経路の証拠ではない。 |
| `arrival` | originの受信説明。Freja経由は未確認と明記。 |
| `http_version` | HTTP/1のみのoriginが実際に受信したversion。Frejaのrequest lineと比較する。 |
| `received.method`, `received.uri` | 実methodと上限付きURI。GET queryを含む。 |
| `received.headers` | header名から保持した文字列値の配列へのmap。非redact。非text値には`base64:` prefixを付ける。 |
| `received.body.byte_length`, `.utf8`, `.base64` | 実bodyのbyte数、UTF-8 text（非UTF-8ならnull）、同じbyteのBase64。通常のGETは長さ0と空文字列。 |
| `headers_omitted`, `uri_omitted` | 該当する表示を省略したらtrue。欠落内容を推定しない。 |
| `interpretation` | `kind: "fields"`とdecodedの`case`/`message`、または`kind: "unavailable"`と`reason`。不正な編集byteを元browser入力で補完しない。 |

| origin status | responseと理由 |
| --- | --- |
| 200 | field解釈に成功したreceipt。 |
| 400 | field欠落・重複・未知名、不正escape/UTF-8/field長、GET body、POST query。解釈unavailableのreceipt。 |
| 413 | queryが2 KiB超なら上限付きreceiptと解釈unavailable。bodyが2 KiB超または読取失敗なら`{"error":"…"}`のみでreceipt/body fieldなし。global 1 MiB body guard超過はlab routing前に既存エラーを返す。 |
| 415 | POSTのContent-Type未指定・非対応、またはContent-Encodingあり。実byteと解釈unavailableのreceipt。decodeはUTF-8固定で、Content-Type parameterで別charsetへ切り替わらない。 |
| 500 | receiptのserializeまたは全体出力失敗。`{"error":"…"}`のみでreceipt fieldなし。 |

先にframing/router/proxyで拒否された場合、body形式は異なることがあります。
Frejaのoperator 403、interactive失敗504、接続失敗502はlab receiptではなく、
origin到達の証拠にもなりません。`error`だけの応答は`lab` markerを持たないため、
browserは受信済みと補完せずterminalでの確認を案内します。

## 既存のJSON・curl surface

`GET /`はJSONのroute一覧（`service`、`warning`、`endpoints`）を維持し、一覧にlabを加えています。
`GET /healthz`も[originのready確認](../setup/#origin-readiness)で使った既存health responseです。
既存`/get`、`/post`、`/put`、`/patch`、`/delete`、`/head`、`/options`、
`/anything`、`/anything/{*path}`はmethod/URI/header/bodyのecho契約を維持します。
既存status、redirect、delay、stream、bytes routeも上限を維持します。
HTMLへ置換せず、lab fieldも要求しません。例えば`/post`は従来どおりJSONを受け取れますが、
`/lab/post`はlab formが必要です。既存endpoint一覧は`examples/http-test-server/README.md`を参照してください。

interactive profileをまだ起動していれば、次の任意のcurl確認もrepository rootから使えます。
追加のpaused requestになるので、一件ずつTerminal Bでcontinueします。
browserの手順と混同しないよう別caseを使います。

```sh
curl --noproxy '' --http1.1 --proxy http://127.0.0.1:8080 -i \
  'http://127.0.0.1:3001/lab/get?case=curl-get&message=hello+origin'
curl --noproxy '' --http1.1 --proxy http://127.0.0.1:8080 -i \
  http://127.0.0.1:3001/lab/post \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'case=curl-post&message=hello+origin'
```
