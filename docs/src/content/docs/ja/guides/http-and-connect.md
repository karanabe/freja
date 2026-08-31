---
title: HTTP forwardingとCONNECT
description: HTTP/1.1 explicit forward proxy、CONNECT tunnel、proxy認証を運用します。
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - HTTP
  - CONNECT
  - 認証
sidebar:
  order: 2
---

FrejaはHTTP/1.1 explicit proxy requestを受け付けます。plain HTTPはabsolute URIを使い、HTTPS clientは通常CONNECT authority-formを送信してから、作成されたtunnel内でTLSを確立します。

## loopback listenerを設定する

```toml
[[listeners]]
kind = "http-forward"
bind = "127.0.0.1:8080"
connect_ports = [443]
```

curlでは次のように使います。

```sh
curl --proxy http://127.0.0.1:8080 http://example.com/path?q=value
curl --proxy http://127.0.0.1:8080 https://example.com/
```

proxy環境変数を扱うapplicationでは次も利用できます。

```sh
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

これらはFrejaの設定ではなくapplication側の慣習なので、各applicationのproxyと`NO_PROXY`の挙動を確認してください。

## リクエスト処理

plain HTTPに対してFrejaは次を行います。

1. 手書きparserではなくHyperでrequestをparseする
2. absolute request targetから接続先を導出し、`Host`を再生成する
3. framingを検証し、proxy credentialとhop-by-hop headerを除去する
4. request target policy、DNS解決、すべての解決済みIPのpolicyを順に評価する
5. HTTP method、path、header ruleを評価する
6. 設定された検査を適用しながらrequest/responseをstreamする

不正なtarget、競合する`Transfer-Encoding`と`Content-Length`、上限を超えるheaderは転送せず拒否します。

CONNECTでは、listenerのport allowlistとdestination policyを確認し、upstream TCP接続が成功した後にだけ成功応答を返します。200応答後はtunnelなので、commit済みbyte streamへ後からHTTP block pageを安全に挿入することはできません。

## responseの意味

| status | 意味 |
| --- | --- |
| `403 Forbidden` | policy、destination保護、preflight検査のいずれかが拒否 |
| `407 Proxy Authentication Required` | credentialがない、または不正 |
| `502 Bad Gateway` | upstream接続またはprotocol処理に失敗 |
| `504 Gateway Timeout` | 設定されたupstream処理がtimeout |

policy responseの一致ruleとgenerationは監査traceで確認できます。

## 認証付きでのみ外部公開する

非loopback HTTP listenerには、明示的なsafety opt-inとcredential digestの両方が必要です。

```toml
[safety]
allow_non_loopback = true

[[listeners]]
kind = "http-forward"
bind = "0.0.0.0:8080"
connect_ports = [443]

[listeners.authentication]
realm = "Freja"
credential_sha256 = "<16進64文字>"
```

digestは正確な`username:password` byte列のSHA-256です。cleartextをTOMLに書かずに生成します。

```sh
read -rsp 'username:password: ' FREJA_CREDENTIAL; echo
printf '%s' "$FREJA_CREDENTIAL" | sha256sum
unset FREJA_CREDENTIAL
```

clientから認証します。

```sh
curl --proxy http://127.0.0.1:8080 --proxy-user 'username:password' http://example.com/
```

:::danger
HTTP Basic proxy認証自体は暗号化されません。保護されたnetwork path、強いcredential、外部rate limitを使用してください。Frejaはonline guessing対策を提供しません。
:::

管理対象clientのtunnel plaintextをFrejaに見せる必要がある場合だけ、[TLS interception](/ja/guides/tls-interception/)を使用します。通常のCONNECTがより安全なdefaultです。
