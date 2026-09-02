---
title: CLIリファレンス
description: Frejaのcommand、option、終了動作、log、Unix signalです。
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - CLI
  - リファレンス
sidebar:
  order: 1
---

binary名は`freja`です。成功時はzero、失敗時はcontext付きerror chainを出力して非zeroで終了します。

```text
freja [COMMAND]

Commands:
  check-config  socketを開かず設定をparse、validate、compileする
  run           fileまたは組み込みdefaultのproxy listenerを実行する
  replay        保存済みfactを検証しcandidate設定で評価する
  help          helpを表示する
```

commandなしの`freja`は、`--config`なしの`freja run`と同じで、組み込みlocal interactive proxyを起動します。

## `check-config`

```sh
freja check-config [--config <PATH>]
```

short optionは`-c`です。pathを省略すると、config-free `run`が使う組み込み設定を検証します。pathを指定した場合も完全な`RawConfig -> ValidatedConfig -> CompiledConfig` pathを通ります。socket bind、audit sink作成、CA materialのreadは行わず、TOML key、endpoint、安全でないmode組み合わせ、resource bound、listener公開、credential、TLS必須設定field、ACL構造、detector定義を検証します。設定済みTLS interceptionのfilesystem/certificate検証は`run`が行います。

成功時はlistener数とpolicy generationを出力します。

## `run`

```sh
freja run [--config <PATH>]
```

組み込み設定を使う場合はcommand自体も省略できます。short optionは`-c`です。`--config`を省略すると、`127.0.0.1:8080`のHTTP forward listener 1件、TUI + enforce + interactive runtime、CONNECT port 443、tunnel TLS、metadata-only audit capture、通常のprotected destination classからなる組み込み設定を使います。pathを指定すると、この完全な設定を置き換えます。選択したsourceをcompileし、bounded audit/UI publisher、optional TLS interception、TUI stateを初期化し、全listenerをbindしてshutdown、早期listener failure、またはaudit writer failureを待ちます。

`RUST_LOG`でoperational diagnosticsを制御できます。

```sh
RUST_LOG=freja=debug,freja_proxy=trace freja run -c freja.toml
```

security recordは`RUST_LOG`の対象ではなく、設定済みaudit JSONL sinkへ出力します。TUI modeではoperational lineをraw terminalへ直接書かず、boundedな`Operational logs` panelへ表示します。

## `replay`

```sh
freja replay \
  --audit <JSONL-PATH> \
  --config <CANDIDATE-CONFIG> \
  [--checkpoint-public-key <16進64文字>]
```

short optionはauditが`-a`、configが`-c`です。segment全体を検証してからcandidate decisionをJSON lineとして標準出力へ出します。optional keyは16進encoded 32-byte Ed25519 public keyです。指定時にはそのkeyの有効なcheckpointが必須です。非対応audit schema versionは明示的に拒否し、このreleaseはversion 1だけを受け付けます。

listenerは開かず、source audit segmentも変更しません。

## signal

| signal | 動作 |
| --- | --- |
| SIGINT | graceful shutdown |
| SIGTERM | graceful shutdown |
| SIGHUP | file-backedのcompatible policy snapshotをreload。組み込み設定ではwarningを出して無視 |

signalはUnixでの動作です。拒否されたSIGHUP candidateではactive snapshotを維持し、operational warningを出します。新listener、sink、authentication、limit、TLS、capture、UI/Hook resourceが必要な変更はrestartしてください。
