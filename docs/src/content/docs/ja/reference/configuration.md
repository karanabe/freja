---
title: 設定リファレンス
description: runtime、safety、limit、listener、policy、inspection、TLS、audit、captureの完全なTOMLリファレンスです。
publishedAt: 2026-08-31
updatedAt: 2026-09-03
tags:
  - 設定
  - リファレンス
  - ポリシー
sidebar:
  order: 2
---

Frejaは1つのTOML fileを読みます。未知のtop-level/strict section fieldは拒否します。省略sectionには安全なdefaultを使いますが、fileにはlistenerが最低1件必要です。commandなしの`freja`（または`--config`なしの`freja run`）はCLI composition rootでloopback限定HTTP listenerを追加し、同じcompilerを通します。fileは次のcommandで検証します。

```sh
freja check-config --config freja.toml
```

## サンプル設定

repositoryにはlocal test向けのstandalone profileが4つあります。

| path | runtimeの組み合わせ |
| --- | --- |
| `examples/config/headless/freja.toml` | headless、enforce、Hook無効、streaming inspection |
| `examples/config/headless/freja.enforce.toml` | headless、enforce、preflight deny marker |
| `examples/config/tui/freja.toml` | default TUI、enforce、interactive request decision |
| `examples/config/tui/freja.interactive.toml` | 小さい上限を持つHTTP専用interactive profile |

どちらのCLI commandにもpathを直接渡せます。

```sh
cargo run -p freja -- check-config --config examples/config/tui/freja.toml
cargo run -p freja -- run --config examples/config/tui/freja.toml
```

各profileは同じloopback portを使うため、1つずつ起動してください。同梱HTTP test originへ接続するためloopback destinationを許可しているので、配置用に変更する前に、この弱いdestination guardを見直してください。profile別の確認方法は`examples/config/README.md`にあります。

## Runtime

```toml
[runtime]
ui = "tui"
enforcement = "enforce"
hooks = "interactive"
```

| key | value | default | 説明 |
| --- | --- | --- | --- |
| `ui` | `headless`, `tui` | `tui` | 表示だけを選択 |
| `enforcement` | `observe`, `enforce` | `enforce` | deny decisionを実行するか |
| `hooks` | `disabled`, `automatic`, `interactive` | `interactive` | interactiveにはTUIが必要 |

`[runtime]`を省略すると、このlocal interactive profileを選択します。各選択は引き続き独立です。TUI自体がenforcementを暗黙に有効化するわけではなく、observe modeでもcaptureとauditは無効になりません。interactive Hookはdecision responderがTUIにあるため、TUIが必須です。標準headless profileは`headless`、`enforce`、`disabled`を明示します。`observe`はdeny actionを実行せずpolicyを評価する必要がある場合に利用できます。

## Safety

```toml
[safety]
allow_non_loopback = false
private_destinations = "protect"
link_local_destinations = "protect"
loopback_destinations = "protect"
metadata_destinations = "protect"
```

各destination controlは`protect`または`allow`です。unspecified/multicast IPは常に拒否します。`allow_non_loopback`はvalidationの継続を許可するだけで、remote HTTP/SOCKS5には認証が必要で、remote static TCPは常にunsupportedです。

既知metadata addressには`169.254.169.254`、`100.100.100.200`、`fd00:ec2::254`があります。guardはDNS後に全addressへ適用します。

## Limits

すべて非zeroでなければなりません。

| key | default | 意味 |
| --- | ---: | --- |
| `connections` | `1024` | listenerごとのconcurrent flow |
| `header_bytes` | `65536` | accepted HTTP header byte上限 |
| `body_prefix_bytes` | `65536` | bounded inspectionで利用できるbody prefix上限 |
| `connect_timeout_ms` | `10000` | 適用箇所のDNS解決/upstream接続/protocol handshake budget |
| `read_timeout_ms` | `30000` | HTTP request headerおよびbody frameのread budget |
| `idle_timeout_ms` | `60000` | relay read/write無通信budget |
| `paused_flows` | `16` | 同時にpauseできるinteractive flow |
| `interception_timeout_ms` | `30000` | Hook/manual/TLS interception待機budget |
| `ui_event_capacity` | `1024` | best-effort UI event queue capacity |
| `ui_content_bytes` | `65536` | TUI traffic片側または最新repeat responseに保持するpayload byte |
| `ui_retained_rows` | `128` | TUIが保持するtraffic rowとHTTP/1.1 repeat workspace |

```toml
[limits]
connections = 1024
header_bytes = 65536
body_prefix_bytes = 65536
connect_timeout_ms = 10000
read_timeout_ms = 30000
idle_timeout_ms = 60000
paused_flows = 16
interception_timeout_ms = 30000
ui_event_capacity = 1024
ui_content_bytes = 65536
ui_retained_rows = 128
```

pause中requestがrow evictionで操作不能にならないよう、`ui_retained_rows`は`paused_flows`以上でなければなりません。interactive modeでは`ui_content_bytes`を`body_prefix_bytes`以上にします。`header_bytes + ui_content_bytes`は`usize`に収まる必要があり、不正な組み合わせはlistener起動前に失敗します。これらTUI retention limitはpayload audit captureを有効にしません。

`ui_retained_rows`は独立したrepeat request/result channelも制限します。workspace上限に達した場合、operatorが実行中でないworkspaceを削除する必要があり、draftを暗黙にevictしません。

## Audit

```toml
[audit]
path = "."
channel_capacity = 1024
failure_policy = "fail-closed"
redact_query_parameters = ["access_token", "api_key", "password", "secret", "token"]
checkpoint_interval = 1000
# checkpoint_signing_key = "/etc/freja/audit-ed25519-seed.hex"
```

`failure_policy`は`fail-open`または`fail-closed`です。`channel_capacity`はpositive値です。signing keyを設定する場合、`checkpoint_interval`もpositive値でなければなりません。key fileは32-byte seedを16進64文字で格納し、Unixではgroup/otherからaccessできないpermissionにします。

`path`が既存directoryならunique segmentを作り、これがdefaultです。したがって`.`では以前のaudit dataを上書きせずlocal起動を繰り返せます。file pathはexclusive createし、上書きしません。Unixでは新規segmentをowner-onlyの`0600`で作成します。containing directoryもoperatorが保護してください。

## Capture

```toml
[capture]
mode = "metadata-only"
```

plaintext prefixを16進で保存する場合だけ明示します。

```toml
[capture]
mode = "prefix"
max_bytes = 4096
```

`max_bytes`はpositiveで、`limits.body_prefix_bytes`以下が必要です。

## Inspection

```toml
[inspection]
mode = "streaming" # または "preflight"

[[inspection.patterns]]
detector_id = "marker"
rule_id = "deny-marker"
pattern_hex = "deadbeef"
severity = "high"
confidence = "confirmed"
directions = ["client-to-upstream", "upstream-to-client"]
action = "deny"
tags = ["signature"]
```

| key | 必須 | default / value |
| --- | --- | --- |
| `detector_id` | 必須 | uniqueで非emptyなidentifier |
| `rule_id` | 必須 | 非emptyなdecision-trace identifier |
| `pattern_hex` | 必須 | 非emptyで有効な16進byte。`limits.body_prefix_bytes` 以下であること |
| `severity` | 任意 | `high`。ほかに`informational`、`low`、`medium`、`critical` |
| `confidence` | 任意 | `confirmed`。ほかに`heuristic`、`probable` |
| `directions` | 任意 | 4つのbody/stream direction全部 |
| `action` | 任意 | `deny`。`allow`も有効、detourは無効 |
| `tags` | 任意 | empty string list |

directionは`client-to-upstream`、`upstream-to-client`、`http-request-body`、`http-response-body`です。detector IDはuniqueでなければなりません。

## TLS

defaultはtunnel modeです。

```toml
[tls]
handling = "tunnel"
```

interceptionにはすべてのsecurity inputが必要です。

```toml
[tls]
handling = "intercept"
ca_certificate = "/etc/freja/ca.pem"
ca_private_key = "/etc/freja/ca-key.pem"
intercept_hosts = [
  { kind = "exact", value = "api.example.test" },
  { kind = "suffix", value = "example.internal" },
]
leaf_cache_entries = 256
```

`leaf_cache_entries`のdefaultは256でpositive値が必要です。`intercept_hosts`は非emptyです。IP literalはhostname patternに一致しません。

## Policy

```toml
[policy]
generation = 1
default_action = "allow"
```

generationは非zeroです。actionは`allow`、`deny`、またはTCP detourです。

```toml
action = { detour = { host = "sinkhole.example", port = 9000 } }
```

detourはdefault actionにはできず、protocol `tcp`を明示するrequested-stage expressionだけで有効です。

### ACL rule

```toml
[[policy.rules]]
id = "deny-admin"
matcher = { kind = "all", value = [
  { kind = "destination-host", value = { kind = "suffix", value = "example.com" } },
  { kind = "http-method", value = ["POST", "DELETE"] },
  { kind = "http-path-prefix", value = "/admin" },
] }
action = "deny"
```

rule IDはuniqueでなければなりません。ruleは宣言順のfirst-matchです。match expressionは`{ kind = "...", value = ... }`形式です。

| kind | value |
| --- | --- |
| `all` | 非empty array。全childが一致 |
| `any` | 非empty array。最初に一致したchildがreasonを提供 |
| `not` | 1つのnested expression |
| `source-ip` | IPv4/IPv6 CIDR string |
| `destination-ip` | IPv4/IPv6 CIDR string。DNS後に利用可能 |
| `destination-host` | `{ kind = "exact" | "suffix", value = "hostname" }` |
| `destination-port` | inclusiveな`{ start = 1, end = 65535 }` |
| `protocol` | `http`または`tcp` |
| `http-method` | method string array。case-insensitive比較 |
| `http-path-prefix` | string prefix |
| `http-header` | `{ name = "x-name", value_contains = "optional bytes" }` |

HTTP固有leafはrequested/resolved/TCP factには一致しません。header名はcase-insensitiveで、`value_contains`はoptional byte substringです。

## Listeners

`[[listeners]]` tableが最低1件必要です。listen addressは`127.0.0.1:8080`や`[::1]:8080`などのsocket addressです。

### HTTP forward proxy

```toml
[[listeners]]
kind = "http-forward"
bind = "127.0.0.1:8080"
connect_ports = [443]
```

`connect_ports`のdefaultは`[443]`で、emptyにはできません。remote listenerには次も必要です。

```toml
[listeners.authentication]
realm = "Freja"
credential_sha256 = "<16進64文字>"
```

realmのdefaultは`Freja`で、quote/backslashを含まない非empty visible ASCIIです。

### Static TCP

```toml
[[listeners]]
kind = "tcp-static"
bind = "127.0.0.1:9000"
upstream = "db.example.internal:5432"
```

upstreamには非zero portが必要です。hostnameはASCII DNS syntaxです。listenerはloopback bindだけを許可します。

### SOCKS5

```toml
[[listeners]]
kind = "socks5"
bind = "127.0.0.1:1080"
```

remote SOCKS5には次が必要です。

```toml
[listeners.authentication]
credential_sha256 = "<正確なusername:passwordのSHA-256>"
```

local認証が必要ならloopback listenerにも同じdigestを設定できます。

## Hot reload互換性

SIGHUPで変更できるのはpolicy rule/generation、destination guard、enforcement、inspection rule/modeです。ほかはrestartが必要です。candidate全体をvalidateしてから互換性を比較し、失敗時は旧snapshotを維持します。
