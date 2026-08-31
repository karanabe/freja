---
title: TLS interception
description: 選択した管理対象destinationへ上限付きTLS interceptionを安全にopt-inします。
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - TLS
  - 証明書
  - セキュリティ
sidebar:
  order: 6
---

CONNECTはdefaultでblind tunnelです。TLS interceptionは管理対象clientと明示allowlist済みhostnameだけに使う別opt-in機能です。Frejaがclient TLSをterminateし、real upstreamを認証して、復号byteを検査できるようになるため、trustとprivacy modelが変わります。

:::danger
管理外deviceへinterception CAをinstallしないでください。その鍵を制御する主体は、deviceが信頼するTLS destinationを偽装できます。
:::

## local CAを準備する

利用可能なら組織のCA運用を使います。隔離したテストでは、OpenSSLでPKCS#8 keyとCA certificateを作成できます。

```sh
install -d -m 0700 ./private
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out ./private/freja-ca-key.pem
openssl req -x509 -new -sha256 -days 365 \
  -key ./private/freja-ca-key.pem \
  -out ./private/freja-ca.pem \
  -subj '/CN=Freja local interception CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'
chmod 0600 ./private/freja-ca-key.pem
```

意図して管理するclientのtrust storeには`freja-ca.pem`だけをinstallします。private keyをclientへcopyしないでください。Unixではgroup/other permission bitのあるCA keyをFrejaが拒否します。

## allowlistを設定する

```toml
[tls]
handling = "intercept"
ca_certificate = "./private/freja-ca.pem"
ca_private_key = "./private/freja-ca-key.pem"
intercept_hosts = [
  { kind = "exact", value = "api.example.test" },
  { kind = "suffix", value = "example.internal" },
]
leaf_cache_entries = 256
```

exact/suffixはvalidated DNS nameのlabel境界で一致します。IP literalはinterceptしません。list外のCONNECT destinationはblind tunnelのままです。

## handshakeとprotocol

FrejaはCONNECT成功をcommitする前にupstream TCP socketを確立します。intercept対象では次を行います。

1. SAN付きleaf certificateを生成またはcacheから再利用
2. downstream TLSをnegotiateして`h2`または`http/1.1`を取得
3. public WebPKI rootと同じALPNでupstream TLSを認証
4. ALPNからHyper HTTP/1.1またはHTTP/2 engineを選択
5. inner exchangeをHTTP policy、上限付きinspection、typed Hook、audit、replay factsへ通し、固定CONNECT targetへforward

certificateとhostname verificationを無効化しません。original certificateをpinするclientは生成leafを拒否すると想定されます。Frejaはpinningを回避せず、接続をcloseして失敗を監査します。

HTTP/1.1とHTTP/2はFreja独自wire parserではなくHyperがdecodeします。CONNECT authorityが正であり、Frejaは`Host`/`:authority`を再生成し、inner requestによる別destination選択を許可せず、nested CONNECTを拒否します。このためHTTP method/path/header、request/response body inspection、typed HTTP mutationはplain/intercepted trafficで同じように動作します。

監査にはhostname、cache hit/miss、ALPN、handshake結果を記録し、CA private materialは記録しません。
