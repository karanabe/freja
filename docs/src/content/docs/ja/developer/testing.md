---
title: 開発とテスト
description: workspace構造、validation gate、integration test、fuzz target、documentation workflowです。
publishedAt: 2026-08-31
updatedAt: 2026-09-05
tags:
  - テスト
  - contribution
  - 開発者
sidebar:
  order: 5
---

FrejaはRust edition 2024を使い、workspaceで宣言および検証するminimum Rust versionは1.98です。Pingora compatibilityは0.8.1へ固定しています。

## 必須gate

milestone完了前にすべて実行します。

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo check --manifest-path fuzz/Cargo.toml --bins
(cd docs && pnpm check)
```

multi-listener CLIがTokioを選択していてもall-feature buildはPingora adapterをcompileします。integration testはlocal serverと外部観測可能なprotocol behaviorを使い、public network serviceへ依存しません。

## Test ownership

- `freja-policy`: first-match trace、destination guard、split-pattern、typed mutation、timeout、paused-flow bound
- `freja-audit`: redaction-before-hash、sequence/hash chain、checkpoint tamper detection
- `freja-proxy/tests/http_forward.rs`: absolute-form、framing limit、CONNECT、auth、response policy、inspection、Hook、reload、TLS interception、intercept後HTTP/1.1/HTTP/2 semantic forwarding、fresh correlation IDかつ再pauseなしのcleartext/TLS repeat HTTP/1.1実行、pinning failure、TUI専用plain HTTP/1 request/response ingress exact capture
- `tcp_static.rs`/`socks_forward.rs`: relay、DNS reauthorization、detour、limit、inspection、authentication
- CLI test: configuration、no-overwrite segment、pinned checkpoint replay、Cargo metadataによるworkspace dependency direction/Pingora isolation境界
- UI test: ratatui test backendによるsplit/片側全幅traffic、diagnostics、repeat render、pane/終了/editor/repeat key state、型付きrequest draft、non-blocking saturation、terminal-control escape。HTTP integration suiteはmanual header/bodyの原子的mutationとframing再構築をupstream serverで検証

local logicにはfocused unit test、externally observable network/CLI変更にはintegration testを追加します。

## ローカルHTTPテストorigin

非公開の`examples/http-test-server` packageは、public network serviceへ依存せずに手動でproxyを確認するためのAxum originです。defaultでは`127.0.0.1:3001`にbindし、GET、POST、PUT、PATCH、DELETE、HEAD、OPTIONS、任意methodのrequest echo routeを提供します。status、redirect、delay、streaming、固定size responseも上限付きで試せます。

Frejaで`examples/config/headless/freja.toml`を使い、それぞれ別のterminalで実行します。

```sh
cargo run --manifest-path examples/http-test-server/Cargo.toml
cargo run -p freja -- run --config examples/config/headless/freja.toml
curl --noproxy "" --proxy http://127.0.0.1:8080 \
  http://127.0.0.1:3001/get?name=freja
curl --noproxy "" --proxy http://127.0.0.1:8080 \
  http://127.0.0.1:3001/post --data 'hello through Freja'
```

`--noproxy ""`はenvironmentのloopback除外によってFrejaが迂回されるのを防ぎます。sample configurationはlocal test専用にloopback destinationを許可しています。serverは受信したmethod、URI、header一式、body全体のsize、最大4 KiBのbody previewをterminalへ表示します。credential/Cookieを含むすべてのheader値は、開発用として意図的に伏字にしません。binary previewはBase64、terminal control characterはescapeされます。URI、header、body previewはsensitiveなままなので、合成したsecretとpayloadだけを使ってください。route一覧と上限は`examples/http-test-server/README.md`に記載しています。

`examples/config/headless/`と`examples/config/tui/`以下のstandalone fileで、enforceするheadless運用、focused blocking detector、および広い上限またはfocusedな上限のinteractive TUIを試せます。CLI integration suiteは同梱する全templateへ`check-config`を実行し、schema変更でsampleが暗黙に無効にならないことを確認します。

## Fuzz target

nested `fuzz` workspaceはproduction parser/state machineを5 targetへ接続します。

```sh
cargo check --manifest-path fuzz/Cargo.toml --bins
```

configuration parsing、target parsing、HTTP mutation plan、binary scanning、malformed/ambiguous HTTP framingを対象にします。framing targetはprivate capture-only HTTP/1 message-boundary state machineも駆動します。target buildは接続維持を証明しますが、release hardeningではcorpusを保持したtime-bounded `cargo-fuzz` campaignも実行してください。

## Code constraint

- 全library crateは`#![forbid(unsafe_code)]`
- library layerで`anyhow`、`thiserror`等のerror erasureを使用しない
- non-test codeで`unwrap`、`expect`、`panic`、`todo`、`unimplemented`を使わない
- concrete sourceを保持しboundaryでcontextを追加
- unbounded channelを使わずUI deliveryでforwardingをblockしない
- public typeと自明でないinvariantにrustdocを付ける

## Documentation site

Astro siteは`docs/`にあり、英語/日本語でmatching contentを持ちます。

```sh
cd docs
pnpm install --frozen-lockfile
pnpm check
```

1 changeで両locale pathを更新します。pageとcodeが不一致なら、code、sample configuration、packaging、integration testを正とします。
