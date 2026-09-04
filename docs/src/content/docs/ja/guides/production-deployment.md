---
title: production配置
description: systemdでFrejaをinstallし、安全にpolicyをreloadして、bounded shutdownとmetricsを運用します。
publishedAt: 2026-08-31
updatedAt: 2026-09-05
tags:
  - 運用
  - systemd
  - 配置
sidebar:
  order: 8
---

Frejaにはhardened systemd unit、sysusers、tmpfiles定義があります。target hostへinstallする前に、すべてのpathとlistenerを確認してください。

## buildとinstall

```sh
cargo build --release -p freja
sudo install -Dm0755 target/release/freja /usr/bin/freja
sudo install -Dm0644 packaging/freja.service /etc/systemd/system/freja.service
sudo install -Dm0644 packaging/freja.sysusers /usr/lib/sysusers.d/freja.conf
sudo install -Dm0644 packaging/freja.tmpfiles /usr/lib/tmpfiles.d/freja.conf
sudo systemd-sysusers /usr/lib/sysusers.d/freja.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/freja.conf
sudo install -Dm0640 examples/config/headless/freja.toml /etc/freja/freja.toml
```

`/etc/freja/freja.toml`を編集し、`audit.path = "/var/lib/freja"`を設定します。repositoryのサンプルは非privileged quick start向けにcurrent directoryを使います。同梱serviceは`/var/lib/freja`と`/run/freja`だけにwriteし、`freja` userで動作し、すべてのcapabilityをdropし、filesystem、kernel、process、syscall、address-family制限を適用します。

enable前に検証します。

```sh
sudo -u freja /usr/bin/freja check-config --config /etc/freja/freja.toml
systemd-analyze verify /etc/systemd/system/freja.service
systemd-analyze security --offline=yes /etc/systemd/system/freja.service
sudo systemctl daemon-reload
sudo systemctl enable --now freja.service
```

## processを観測する

```sh
systemctl status freja.service
journalctl -u freja.service -f
```

operational logは`tracing`からservice標準出力へ出ます。security audit JSONLは`audit.path`へ書きます。よりsensitiveなdataとして保護、rotate、export、retainしてください。FrejaはUnixで新規segmentを`0600`で作成し、同梱state directoryは`0750`です。

embedderは`DataPlaneServices::metrics_snapshot`からprocess-local lock-free counterを取得できます。CLIにはHTTP metrics endpointがありません。snapshotにはflow count、byte、policy action、finding、TLS interception/cache、manual action、audit reject、best-effort event-sink dropがあります。

## policyをreloadする

Unixでは設定fileをatomicに置換してSIGHUPを送ります。

```sh
sudo /usr/bin/freja check-config --config /etc/freja/freja.toml.new
sudo mv /etc/freja/freja.toml.new /etc/freja/freja.toml
sudo systemctl kill --signal=HUP freja.service
```

同梱unitは`ExecReload`を定義しないため、`systemctl reload`は利用できません。compatible hot reloadには上の明示的なsignal commandを使い、restart-only設定を変更した場合はserviceをrestartしてください。

1回の`ArcSwap`でACL、destination guard、enforcement mode、inspection program/mode、policy generationを置換します。listener、authentication、limit、TLS、UI/Hook、capture、audit変更はrestartが必要で、hot reloadとしては拒否します。

## graceful shutdown

SIGINT/SIGTERMはacceptを止め、active relayへ通知し、listener taskをdrainし、監査をflushし、TUIを復元します。unitはsystemdがshutdownを強制するまで90秒待ちます。connection idle timeoutはserviceのstop budgetに合わせてください。

systemd sandbox directiveはdistributionごとに異なるため、unit変更のたびにtarget hostでvalidatorを実行してください。
