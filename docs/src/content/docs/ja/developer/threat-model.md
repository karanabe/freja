---
title: Threat model
description: trusted input、attack surface、実装済みcontrol、operatorに残るriskです。
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - セキュリティ
  - threat-model
  - 開発者
sidebar:
  order: 4
---

Frejaはattacker-controlled connection、protocol metadata、DNS answer、payload byte、replay inputを受け取り、security decisionを行い、TLS CA keyを保持する場合があります。configuration、signing key、CA material、binary、local OS環境はtrusted administrative inputです。remote control planeはscope外です。

## Assetと境界

assetには次があります。

- client/upstreamのconfidentialityとintegrity
- policy identityとdecision trace integrity
- service availabilityとresource budget
- authentication materialとintercepted plaintext
- audit continuity、captured evidence、checkpoint signing key
- TLS interception CA private key

untrusted dataはTCP/SOCKS handshake、Hyper parsing、DNS、TLS handshake、streaming inspection、Hook mutation、TUI input、audit serialization、replay parsingを通過します。

## 実装済みcontrol

### 公開とdestination選択

- listenerはdefaultでloopback限定。remote HTTP/SOCKS5はopt-in+認証、remote static TCPは拒否
- configurationには正確な`username:password`のSHA-256だけを保存。constant-time比較、一時decoded credentialのzero化、forward前strip、outcome-only auditを実施
- requested hostname/port policyをDNS前に実行し、全resolved IPをACLとloopback/private/link-local/metadata guardで確認
- CONNECT portをallowlistし、200前にupstream TCPを接続

### Protocolとresource safety

- HTTP/1は手書きparserではなくHyperで処理。conflicting framing、oversized header、ambiguous target、unsafe hop-by-hop forwardingを拒否
- connection、header/body prefix、DNS/connect/idle/interception timeout、leaf cache、audit/UI queue、paused flow、manual editをbounded化
- streaming signatureはbounded overlapを保持し、preflightはprefix budgetだけ保持
- Hookはwire byteを出力できずhop-by-hop framingを変更不可。interactive requestはboundedでCLI timeoutはfail-closed

### Auditとsensitive data

- secret header/query parameterをhash前にredact。default captureはmetadata-only、明示prefix以外のevidenceはhash
- Audit/UIは別publisher。UI lossはcountし、audit failureは明示policyに従い黙殺しない。CLIはwriterを監視し、eventごとにflushしてwriter failure時にshutdown
- record/previous hashで内部改変とreorderを検知。trusted keyをpinしたEd25519 checkpointでchain位置をauthenticate
- Unixでは新規audit segmentをowner-onlyの`0600`で作成。directory access、storage durability、rotation、exportはoperator control

### TLS interceptionとservice isolation

- 明示hostname allowlistとCA inputが必須。Unix CA keyはgroup/other permissionを拒否。upstream certificate/name verificationを維持し、SAN付きcertificateとhost+ALPN bounded cacheを使用
- payload relay前にdownstream-selected ALPNでupstream TLS handshakeを完了。CONNECT後failureはclose+audit
- systemd unitはcapability drop、privilege escalation拒否、writable path/address family制限、kernel/process/syscall controlを適用

## 残るriskとoperator責任

- CA/signing key compromiseは対応trust claimを破壊する。access制限、rotation、managed client限定CA配布が必要
- HTTP Basic/RFC 1929 credentialはprotected pathだけで安全。Frejaにonline guessing rate limitはなくnetwork controlが必要
- certificate-pinned applicationはgenerated leafを拒否でき、安全な回避はない
- DNS answerは変化する。毎回再評価するがresolver compromise/rebindingは環境risk
- hash chainとsegment内checkpointは未知tail/segment全体の削除を証明できない。key pinと別管理storageへのexportが必要
- prefix captureはbreach impactを増やす。最小bound、access、retention、deletion policyが必要
- content-encoded representationは自動展開しない。streaming body replacementはencoded messageを拒否し、preflight replacementは古いrepresentation metadataを明示的に除去する
- built-in admin HTTP metrics endpointはなく、embedderがprocess-local APIをsampleする

security-sensitive変更ではこのpageと該当境界のtestを更新してください。
