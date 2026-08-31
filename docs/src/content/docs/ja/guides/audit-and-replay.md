---
title: 監査とoffline replay
description: redact済み監査証跡を保持し、checkpointへ署名して、candidate policyで再評価します。
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - 監査
  - replay
  - integrity
sidebar:
  order: 7
---

operational diagnosticsは`tracing`へ、security eventは別のtyped JSONL streamへ出力します。publisherはboundedで、設定したfailure policyに従います。

## 監査pathを選ぶ

```toml
[audit]
path = "/var/lib/freja"
channel_capacity = 1024
failure_policy = "fail-closed"
redact_query_parameters = ["access_token", "api_key", "password", "secret", "token"]
checkpoint_interval = 1000
```

`path`が既存directoryなら、起動ごとに`freja-<unix-ms>-<pid>-<collision>.jsonl`というunique segmentを作ります。file名の場合、そのfileは存在していてはいけません。既存segmentを黙って上書きしません。Unixでは新規segmentをowner-onlyの`0600`で作成します。containing directoryも保護してください。

`fail-closed`はbounded capacityを待ち、consumer closeをenforcement failureとして扱います。`fail-open`は待たずにrejectを報告し、`audit_rejected_events`を増やします。traffic継続が監査完全性より明示的に優先される場合だけfail-openを使います。各event後にprocess bufferをflushし、writer error時にはdegradedなproxyを動かし続けずCLIを停止します。

## capture policy

defaultはmetadata-onlyです。

```toml
[capture]
mode = "metadata-only"
```

明示的prefix captureはsensitive plaintextを16進で保存します。

```toml
[capture]
mode = "prefix"
max_bytes = 4096
```

`max_bytes`は`limits.body_prefix_bytes`以下でなければなりません。Authorization、Proxy-Authorization、Cookie、Set-Cookie、設定済みquery parameter、replay fact内のsecret headerはhash前にredactします。

## 定期checkpointへ署名する

32-byte Ed25519 seedを作り保護します。

```sh
install -d -m 0700 /etc/freja
openssl rand -hex 32 > /etc/freja/audit-ed25519-seed.hex
chmod 0600 /etc/freja/audit-ed25519-seed.hex
```

```toml
[audit]
path = "/var/lib/freja"
checkpoint_signing_key = "/etc/freja/audit-ed25519-seed.hex"
checkpoint_interval = 1000
```

各checkpointは直前sequenceとrecord hashへ署名します。公開verification keyは別管理場所へ保存してください。checkpoint eventにも含まれますが、authenticity確立にはsegment外でのpinが必要です。

## candidate policyでreplayする

```sh
freja replay \
  --audit /var/lib/freja/freja-....jsonl \
  --config ./candidate.toml \
  --checkpoint-public-key '<16進64文字>'
```

replayはsequence continuity、previous-hash link、record hash、checkpoint signature、checkpoint chain位置を先に検証します。audit schema version 1だけを受け付け、非対応versionは明示的に拒否します。keyをpinした場合、そのkeyのcheckpointが最低1件必要です。integrity検証後にだけ、保存されたrequested/resolved/HTTP/finding factを評価し、captured prefix用direction別scannerを再構築します。16 MiBを超えるJSONL行と、candidateの`limits.body_prefix_bytes`を超えるcapture byteはdetector評価前に拒否します。

`--checkpoint-public-key`なしの場合、埋め込みsignatureは内部self-consistencyだけを示します。segment全体を置換できる攻撃者は埋め込み公開keyも置換できます。またhash chainとsegment内checkpointだけでは未知のtail削除を証明できません。truncation耐性が必要ならsegmentまたはcheckpointを別管理storageへexportしてください。

fieldとevent typeは[監査schema](/ja/reference/audit-schema/)を参照してください。
