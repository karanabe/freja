---
title: ポリシーと検査
description: ordered ACL、解決済み接続先の保護、上限付きbyte stream検査を設定します。
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - ポリシー
  - 検査
  - セキュリティ
sidebar:
  order: 4
---

Frejaはfact、finding、decision、enforcementを分離します。ACLとdetectorの結果には常に`DecisionTrace`が付き、`runtime.enforcement`がdenyを観測だけにするか実行するかを決めます。

## observeまたはenforceを選ぶ

```toml
[runtime]
enforcement = "observe" # または "enforce"
```

observe modeでは意図的に通信を遮断せず、実trafficに対してruleを検証できます。finding、decision、実行予定actionは監査とTUIに残ります。traceを確認してからenforceへ移行してください。

## ordered ACL

ruleは宣言順に評価し、最初の一致で終了します。一致がなければ`policy.default_action`を使います。

```toml
[policy]
generation = 42
default_action = "allow"

[[policy.rules]]
id = "deny-example-admin"
matcher = { kind = "all", value = [
  { kind = "destination-host", value = { kind = "suffix", value = "example.com" } },
  { kind = "http-path-prefix", value = "/admin" },
] }
action = "deny"

[[policy.rules]]
id = "deny-metadata-ip"
matcher = { kind = "destination-ip", value = "169.254.0.0/16" }
action = "deny"
```

source CIDR、destination CIDR、exact/suffix hostname、destination port range、protocol、HTTP method集合、HTTP path prefix、HTTP header名と任意byte substringを使用できます。`all`、`any`、`not`で組み合わせます。空のboolean expressionは不正です。

traceと監査recordが1つのruleを曖昧なく示せるよう、policy内のrule IDはuniqueでなければなりません。

policyの意味を変更するたびに`policy.generation`を増やしてください。generationはdecisionと監査recordに付き、reload/replay結果を識別できます。

## destination保護

resolved address guardはordered ACLとは独立して動作します。loopback、private、link-local、既知metadata-service addressのdefaultは`protect`で、unspecifiedとmulticastは常に拒否します。

```toml
[safety]
private_destinations = "protect"
link_local_destinations = "protect"
loopback_destinations = "protect"
metadata_destinations = "protect"
```

hostnameや最初のanswerだけでなく、DNSの全結果を検査します。配置上明確に必要なaddress classだけを`allow`にしてください。

## 固定byte検査

patternは非emptyの16進byte列です。detectorがfindingを作り、別の設定actionがfindingをdecisionに変換します。

```toml
[inspection]
mode = "streaming"

[[inspection.patterns]]
detector_id = "known-marker"
rule_id = "deny-known-marker"
pattern_hex = "deadbeef"
severity = "high"
confidence = "confirmed"
directions = ["client-to-upstream", "http-request-body"]
action = "deny"
tags = ["signature", "controlled-test"]
```

directionは`client-to-upstream`、`upstream-to-client`、`http-request-body`、`http-response-body`です。scannerは上限付きoverlapを保持するため、read chunkをまたぐpatternも検出します。各patternは`limits.body_prefix_bytes`以下でなければならず、超える署名は一致不能なまま実行せず設定compile時に拒否します。

### Streamingとpreflight

- どちらもflow方向ごとに先頭`limits.body_prefix_bytes`までだけを検査し、それ以降のbyteにはdetectorを適用せず転送します。
- `streaming`はchunkを転送しながらscanします。prefix内で後から一致した場合、以後のbyteは止められますが送信済みbyteは取り消せません。
- `preflight`は`limits.body_prefix_bytes`までbufferし、転送前にscanします。buffer範囲内ならHTTP block pageまたはTCP closeを送信前に実行できます。短いTCP prefixをpreflight timeoutでreleaseした後は、後続byteで検査を再開しません。

どちらも無制限のfull-content scanではありません。pattern matchingとcaptureは設定上限に従います。entropyだけではblockしません。

matcher表現とdefaultは[設定リファレンス](/ja/reference/configuration/)を参照してください。
