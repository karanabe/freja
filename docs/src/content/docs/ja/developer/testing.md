---
title: 開発とテスト
description: workspace構造、validation gate、integration test、fuzz target、documentation workflowです。
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - テスト
  - contribution
  - 開発者
sidebar:
  order: 5
---

FrejaはRust edition 2024を使い、workspaceのminimum Rust versionはratatui 0.30.2と解決済みTLS certificate stackに合わせた1.88です。Pingora compatibilityは0.8.1へ固定しています。

## 必須gate

milestone完了前にすべて実行します。

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

multi-listener CLIがTokioを選択していてもall-feature buildはPingora adapterをcompileします。integration testはlocal serverと外部観測可能なprotocol behaviorを使い、public network serviceへ依存しません。

## Test ownership

- `freja-policy`: first-match trace、destination guard、split-pattern、typed mutation、timeout、paused-flow bound
- `freja-audit`: redaction-before-hash、sequence/hash chain、checkpoint tamper detection
- `freja-proxy/tests/http_forward.rs`: absolute-form、framing limit、CONNECT、auth、response policy、inspection、Hook、reload、TLS interception、intercept後HTTP/1.1/HTTP/2 semantic forwarding、pinning failure
- `tcp_static.rs`/`socks_forward.rs`: relay、DNS reauthorization、detour、limit、inspection、authentication
- CLI test: configuration、no-overwrite segment、pinned checkpoint replay
- UI test: ratatui test backend renderとnon-blocking saturation

local logicにはfocused unit test、externally observable network/CLI変更にはintegration testを追加します。

## Fuzz target

nested `fuzz` workspaceはproduction parser/state machineを5 targetへ接続します。

```sh
cargo check --manifest-path fuzz/Cargo.toml --bins
```

configuration parsing、target parsing、HTTP mutation plan、binary scanning、malformed/ambiguous HTTP framingを対象にします。target buildは接続維持を証明しますが、release hardeningではcorpusを保持したtime-bounded `cargo-fuzz` campaignも実行してください。

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
pnpm build
```

1 changeで両locale pathを更新します。pageとcodeが不一致なら、code、sample configuration、packaging、integration testを正とします。
