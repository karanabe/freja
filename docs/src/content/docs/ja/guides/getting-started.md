---
title: はじめに
description: Frejaをbuildし、安全なローカル設定を検証して、最初のリクエストをproxyします。
publishedAt: 2026-08-31
updatedAt: 2026-09-03
tags:
  - インストール
  - クイックスタート
  - CLI
sidebar:
  order: 1
---

このガイドではFrejaをsourceからbuildし、組み込みのloopback限定HTTP forward proxyを起動します。このlocal interactive pathにはcommandも設定fileも不要です。

## 前提条件

- Rust 1.98以降とCargo
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

## 組み込みdefaultを確認する

commandless startupは次の値を使います。

- HTTP forward listener 1件を`127.0.0.1:8080`にbind
- TUIが上限付きlive traffic snapshotを表示
- observe-only enforcementがACL、destination guard、inspection、CONNECT portのdeny/detour decisionを記録するが実行しない
- interactive Hookが上限付きHTTP requestをcontinue、reject、editのdecisionまでpause
- payload audit captureとTLS interceptionは無効
- auditは起動ごとにuniqueなlocal `freja-<timestamp>-<pid>-<counter>.jsonl` segmentへ書く
- loopback、private、link-local、metadata destinationをprotectに設定し、CONNECT policyにはport 443だけを含める。これらのpolicy denyでtrafficをblockするにはenforce modeが必要

## bind前に検証する

pathなしの`check-config`はsocketを開かず、同じ組み込み設定を検証します。

```sh title="ターミナル"
./target/release/freja check-config
```

成功時にはlistener数と非zeroのpolicy generationが出力されます。

```text
configuration valid: 1 listener(s), policy generation 1
```

未知のtop-level/strict section key、zeroのlimit、安全でないlistener公開、不正なpolicy、不完全なTLS interception設定がある場合は失敗します。

## 起動してリクエストを送る

```sh title="ターミナル1"
RUST_LOG=freja=info ./target/release/freja
```

別のterminalで実行します。

```sh title="ターミナル2"
curl --proxy http://127.0.0.1:8080 http://example.com/
curl --proxy http://127.0.0.1:8080 https://example.com/
```

1件目はHTTP absolute-form forwardingを使います。2件目はCONNECT tunnelを確立します。tunnel modeがdefaultなので、TLSはcurlと接続先の間でend-to-endのままです。各requestはTUI decisionを待ちます。変更せず続行する場合は`c`、拒否する場合は`r`、対応するHTTP/1.1 requestを編集する場合は`e`/`i`を押します。

Ctrl+Cで停止します。SIGINTとSIGTERMは新規acceptを止め、active relayへ通知し、監査writerをflushし、有効ならTUIを復元します。

## 設定fileでcustomizeする

repository内のfileを直接編集せず、完全なexampleをcopyします。

```sh title="ターミナル"
cp examples/config/tui/freja.toml ./freja.toml
./target/release/freja check-config --config ./freja.toml
./target/release/freja run --config ./freja.toml
```

TUI exampleはSOCKS5とstatic TCP listenerも追加します。headless用とfocused enforcement用のprofileも`examples/config/`以下にあります。これらのlocal-test profileはloopback destinationを許可するため、配置上local serviceへ到達する必要がなければopt-inを削除してください。

## 次に読むページ

- [HTTP forwardingとCONNECT](/ja/guides/http-and-connect/)を設定する
- [ポリシーと検査](/ja/guides/policy-and-inspection/)を追加する
- [監査とoffline replay](/ja/guides/audit-and-replay/)で保存内容を理解する
- [設定リファレンス](/ja/reference/configuration/)ですべてのkeyを確認する
