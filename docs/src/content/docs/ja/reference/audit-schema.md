---
title: 監査schema
description: version 2 JSONL field、compatibility、event variant、redaction、hash chain、signed checkpointです。
publishedAt: 2026-08-31
updatedAt: 2026-09-03
tags:
  - 監査
  - schema
  - リファレンス
sidebar:
  order: 3
---

Frejaは1行に1つのJSON objectを書きます。新しく書くschema version 2 recordのtop-level fieldは次のとおりです。

| field | type | 意味 |
| --- | --- | --- |
| `schema_version` | integer | 現在は`2`で書き出し、replayは`1`も受け付ける |
| `sequence` | non-zero integer | 1 segment内でmonotonic |
| `occurred_at` | integer | Unix時刻millisecond |
| `session_id` | UUID | connection correlation ID |
| `transaction_id` | optional UUID | HTTP exchange correlation ID |
| `policy_generation` | non-zero integer | eventで使用したsnapshot identity |
| `event` | tagged object | typed event payload |
| `previous_hash` | optional 16進64文字 | 直前record hash。sequence 1ではなし |
| `record_hash` | 16進64文字 | それ以前の全record fieldのSHA-256 |

hashはprevious linkを含むdeterministic JSON serializationを対象にします。partial writeが発生したsinkはpoisonされ、誤解を招くchainを継続しません。

## Event type

`event` objectはkebab-caseの`event_type`と`event` payloadを持ちます。version 2は次を含みます。

- `connection-accepted`、`target-resolved`、`tunnel-closed`、`flow-closed`
- 完全なdecision/trace付き`acl-evaluated`、`inspection-evaluated`、`action-executed`
- `http-request-observed`、`http-response-observed`
- outcomeだけを持つ`proxy-authentication`
- hashed evidence付き`finding-detected`
- edit内容を持たない`hook-executed`、`manual-modification`
- source session/transaction IDだけを持つ`http-repeat-started`
- `tls-certificate-generated`、`tls-interception-established`
- `replay-facts-observed`、明示有効化された`payload-prefix-captured`
- `signed-checkpoint`

version 2は`http-repeat-started`を追加し、それ以前のevent shapeは変更しません。replayはversion 1と2を受け付け、v1と表示されたrecord内のv2専用repeat event、および未知のversionをfield意味の推測なしで拒否します。

## Redactionとcapture

redactionはhash/serialization前に実行します。Authorization、Proxy-Authorization、Cookie、Set-Cookie、設定したquery parameter名、URL userinfo、replay fact内のsecret headerが対象です。authentication eventにはusername、password、digestを含めません。

defaultはmetadata-onlyです。prefix captureはdirection、protocol、上限付きbyteの16進表現を追加します。16進化は保護ではないため、sensitive plaintextとして扱ってください。

## Signed checkpoint

signed checkpoint payloadは次を持ちます。

| field | 意味 |
| --- | --- |
| `covers_sequence` | 直前のsegment sequence |
| `record_hash` | そのsequenceのhash |
| `public_key_hex` | Ed25519 verification key |
| `signature_hex` | Freja domain tag、sequence、hashへの署名 |

replayはsignatureを検証し、署名位置がcheckpoint recordの実際の直前recordであることを要求します。segment全体の置換に対するauthenticityには、`public_key_hex`をsegment外でpinする必要があります。

## Failure policy

AuditとUI publisherは別のbounded channelです。`fail-closed`はaudit capacityを待ち、consumer closeをenforcement failureとして伝播します。`fail-open`は即座にrejectし、`audit_rejected_events`を増やして、明示された配置判断どおりcallerを継続させます。critical recordを黙ってdropしません。CLIはeventごとにprocess bufferをflushし、audit writerが早期終了またはerrorを返した場合はshutdownします。Unixでは新規segmentを`0600`で作成します。
