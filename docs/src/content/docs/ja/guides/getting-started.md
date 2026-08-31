---
title: はじめに
description: Frejaをbuildし、安全なローカル設定を検証して、最初のリクエストをproxyします。
publishedAt: 2026-08-31
updatedAt: 2026-09-01
tags:
  - インストール
  - クイックスタート
  - CLI
sidebar:
  order: 1
---

このガイドではFrejaをsourceからbuildし、同梱されたloopback限定のサンプルを起動します。サンプルはHTTP forward proxy、SOCKS5 listener、static TCP listenerを開きます。テスト機以外で使う前に、不要なlistenerを削除してください。

## 前提条件

- Rust 1.88以降とCargo
- optional Pingora互換featureまたはall-feature開発gateをbuildする場合はC toolchainとCMake
- リクエスト例で使うcurl
- signalとserviceの例を実行する場合はLinuxなどのUnix系OS

## CLIをbuildする

repositoryのrootで実行します。

```sh title="ターミナル"
cargo build --release -p freja
./target/release/freja --help
```

binaryと設定ファイルは、通常のsoftware supply chain管理下に置いてください。

## サンプル設定を確認する

repository内のファイルを直接編集せず、copyします。

```sh title="ターミナル"
cp examples/freja.toml ./freja.toml
```

このファイルの重要なdefaultと明示設定は次のとおりです。

- すべてのlistenerは`127.0.0.1`にbindする
- enforcementはobserve-onlyのまま
- Hook、payload capture、TLS interceptionは無効
- auditは起動ごとにuniqueなlocal `freja-<timestamp>-<pid>-<counter>.jsonl` segmentへ書く
- static TCPの例が`127.0.0.1:9001`へ到達できるようlocal upstreamを許可
- CONNECT先はport 443に限定

:::caution
loopback destinationの許可はローカルテストには便利ですが、SSRF保護を弱めます。配置上local serviceへの接続が必要でなければ、`loopback_destinations = "allow"`を削除してください。
:::

## bind前に検証する

`check-config`はsocketを開かずに、設定全体をparse、validate、compileします。

```sh title="ターミナル"
./target/release/freja check-config --config ./freja.toml
```

成功時にはlistener数と非zeroのpolicy generationが出力されます。

```text
configuration valid: 3 listener(s), policy generation 1
```

未知のtop-level/strict section key、zeroのlimit、安全でないlistener公開、不正なpolicy、不完全なTLS interception設定がある場合は失敗します。

## 起動してリクエストを送る

```sh title="ターミナル1"
RUST_LOG=freja=info ./target/release/freja run --config ./freja.toml
```

別のterminalで実行します。

```sh title="ターミナル2"
curl --proxy http://127.0.0.1:8080 http://example.com/
curl --proxy http://127.0.0.1:8080 https://example.com/
```

1件目はHTTP absolute-form forwardingを使います。2件目はCONNECT tunnelを確立します。tunnel modeがdefaultなので、TLSはcurlと接続先の間でend-to-endのままです。

Ctrl+Cで停止します。SIGINTとSIGTERMは新規acceptを止め、active relayへ通知し、監査writerをflushし、有効ならTUIを復元します。

## 次に読むページ

- [HTTP forwardingとCONNECT](/ja/guides/http-and-connect/)を設定する
- [ポリシーと検査](/ja/guides/policy-and-inspection/)を追加する
- [監査とoffline replay](/ja/guides/audit-and-replay/)で保存内容を理解する
- [設定リファレンス](/ja/reference/configuration/)ですべてのkeyを確認する
