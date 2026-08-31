---
title: Static TCPとSOCKS5
description: fixed-upstream TCP relayとSOCKS5 CONNECT listenerを安全に設定します。
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - TCP
  - SOCKS5
  - listener
sidebar:
  order: 3
---

Frejaは2種類のL4入口を提供します。static TCP listenerは常に設定済みの1 upstreamを選びます。SOCKS5 listenerはCONNECT requestから接続先を受け取ります。

## static TCP relay

```toml
[[listeners]]
kind = "tcp-static"
bind = "127.0.0.1:9000"
upstream = "db.example.internal:5432"
```

requested-host policy、DNS解決、全解決済みaddressの確認を行い、設定timeout内に接続します。その後、idle timeout、byte count、検査、Hook、監査を適用して双方向にrelayします。

static TCPにはprotocol levelの認証handshakeがないため、`safety.allow_non_loopback`がtrueでも非loopback bindを拒否します。source IPをidentityとみなさず、認証済みtransportを前段に置いてください。

## SOCKS5 CONNECT

```toml
[[listeners]]
kind = "socks5"
bind = "127.0.0.1:1080"
```

curlの`socks5h`形式を使うとproxy側でDNS解決します。

```sh
curl --proxy socks5h://127.0.0.1:1080 https://example.com/
```

FrejaはIPv4、IPv6、domain targetのSOCKS5 CONNECTを実装します。UDP ASSOCIATEとBINDは実装しません。

## 認証付きSOCKS5公開

非loopback SOCKS5ではRFC 1929 username/password認証が必須です。

```toml
[safety]
allow_non_loopback = true

[[listeners]]
kind = "socks5"
bind = "0.0.0.0:1080"

[listeners.authentication]
credential_sha256 = "<正確なusername:passwordのSHA-256>"
```

```sh
curl --proxy socks5h://127.0.0.1:1080 --proxy-user 'username:password' https://example.com/
```

RFC 1929 credentialはSOCKS接続上ではcleartextです。HTTP Basicと同様に保護networkとrate limitを用意してください。監査にはidentityやsecretではなくaccept/reject結果だけを保存します。

## TCP detour

ordered ACLはapplication byte送信前に置換upstreamを選択できます。

```toml
[[policy.rules]]
id = "detour-legacy-service"
matcher = { kind = "all", value = [
  { kind = "protocol", value = "tcp" },
  { kind = "destination-port", value = { start = 9001, end = 9001 } },
] }
action = { detour = { host = "sinkhole.example.internal", port = 9002 } }
```

detour ruleはDNS前に利用できるTCP factへ制限する必要があります。選択先もrequested/resolved destination policyで再評価し、2回目のdetourはrouting loopとして拒否します。
