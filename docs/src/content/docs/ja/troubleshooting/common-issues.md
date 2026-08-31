---
title: よくある問題
description: 設定拒否、proxy response、TLS failure、TUI復旧、replay errorを診断します。
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - トラブルシューティング
  - エラー
sidebar:
  order: 1
---

最初に設定compileとoperational logを確認します。

```sh
freja check-config --config freja.toml
RUST_LOG=freja=debug,freja_proxy=debug freja run --config freja.toml
```

security decisionはtracing出力だけでなくJSONL audit streamにあります。

## 設定が拒否される

| messageまたは症状 | 主な原因 | 解決方法 |
| --- | --- | --- |
| `at least one listener is required` | `[[listeners]]`がない | 対応listenerを最低1件追加 |
| `listener ... is not loopback` | opt-inなしのremote bind | loopbackを使うか`allow_non_loopback`と必須認証を設定 |
| remote HTTP/SOCKS requires authentication | 公開proxyにcredential digestがない | listener authentication tableを追加 |
| remote static TCP unsupported | generic TCPにauth handshakeがない | loopbackに限定するか外部protected transportを追加 |
| `limit ... must be non-zero` | bounded resourceがzero | positiveな運用上限を設定 |
| interactive hooks require TUI | headless UIで`hooks = "interactive"` | `ui = "tui"`またはinteractive無効化 |
| detector has invalid hex/empty pattern | `pattern_hex`が不正 | 非emptyで偶数長の16進byte列に修正 |
| TLS interception requires ... | CA pathまたはallowlist不足 | 全inputを設定するかtunnelへ戻す |

未知TOML keyはerrorです。`[listeners.authentication]`は直前のarray listenerに属するため、table nestingを確認してください。

## local upstreamが拒否される

listener自体がlocalでもloopback/private destinationはdefaultで保護されます。これは意図したSSRF保護です。明確なlocal testの場合だけ次を使います。

```toml
[safety]
loopback_destinations = "allow"
```

監査decision traceで一致built-in ruleを確認します。必要serviceを隔離できる別network設計が可能なら、address class全体をallowしないでください。

## HTTPが403、407、502、504を返す

- 403: `acl-evaluated`、`inspection-evaluated`、`action-executed`を確認
- 407: 正確なHTTP Basic credentialを指定。hashはnewlineなしの`username:password`が対象
- 502: DNS、upstream reachability、protocol、TLS trustを確認
- 504: 正当に遅い処理を特定してからtimeoutを調整

CONNECT先portが`connect_ports`にない場合も403です。

## TLS interceptionに失敗する

1. destination hostnameがexact/suffix allowlistに一致するか確認
2. 管理対象clientが設定CA certificateを信頼しているか確認
3. CA private keyへ`chmod 0600`を実行。group-readable keyは拒否
4. upstream certificateとDNS名がpublic rootでvalidateできるか確認
5. clientのcertificate pinningを確認。pinned clientの失敗は想定動作で安全な回避は不可
6. ALPNを確認。intercept connectionは`h2`と`http/1.1`に対応

## audit fileがすでに存在する

exact audit fileは上書きしません。新しいpathを選ぶか、`audit.path`を既存directoryにしてunique segmentを生成します。retention policyを満たすまで既存segmentを削除しないでください。

## replayがsegmentを拒否する

sequence、previous hash、record hash、checkpoint signature、checkpoint位置、pinned keyが不正な場合、policy評価前に停止します。sequence 1から始まるcompleteな1 segmentを指定してください。key pin時はそのkeyのcheckpointもsegment内に必要です。

## TUI終了後にterminal表示が壊れる

normal exitとunwindではterminalを復元しますが、SIGKILLやterminal emulator failureではcleanupできません。`reset`を実行するか新しいterminalを開きます。SIGINT/SIGTERMを使い、graceful shutdownが完了しなかった理由を調査してください。

## reloadが反映されない

hot reload対象はpolicy、destination guard、enforcement、inspectionだけです。listener、authentication、limit、TLS、UI/Hook、capture、audit変更はrestartします。validation/compatibility failure時は旧snapshotを維持するため、tracing warningを確認し、実際のcandidate fileへ`check-config`を実行してください。
