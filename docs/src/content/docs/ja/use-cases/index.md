---
title: ユースケース
description: 具体的な目的から、使い方と観測した証拠へ進む実用シナリオです。
publishedAt: 2026-09-06
updatedAt: 2026-09-06
tags:
  - testing
sidebar:
  order: 1
prev:
  link: /ja/
  label: ドキュメントホーム
next:
  link: /ja/use-cases/browser-form-lab/
  label: HTTP/1.1 browserフォームlab
---

ユースケースは「何を確かめたいか」から出発し、必要な準備、操作、期待する表示、
そこから判断できることまでを一通り辿る実用シナリオです。このpageで目的を選び、
対象の概要から始めてください。各シナリオが前提と確認済み・未観察の範囲を説明します。

| 読みたいこと | 使うsection |
| --- | --- |
| 具体的な目的を最初から最後まで確かめたい | **ユースケース** — 準備、操作、証拠の照合、復帰と終了。 |
| 機能や設定の一般的な操作を知りたい | **ガイド** — [起動](../guides/getting-started/)、[TUIとHook](../guides/tui-and-hooks/)など、シナリオをまたいで使う操作。 |
| optionやschemaの完全な契約を引きたい | **リファレンス** — [CLI](../reference/cli/)、[設定](../reference/configuration/)などの定義。 |

## 現在利用できるユースケース

| 目的 | 入口と終わったときの状態 |
| --- | --- |
| browserから送ったHTTP/1.1をFrejaで観測・介入し、origin到達と照合する | [HTTP/1.1 browserフォームlab](./browser-form-lab/) — localなsynthetic GET/POST、continue・編集・reject・Repeatを辿り、直通のecho成功とproxy経由の証拠を区別する。 |

次は上のlab概要でpage mapと安全境界を確認し、準備からGET一往復へ進みます。
