---
title: labの準備
description: originとFrejaを起動し、ChromiumかFirefoxの専用profileと入口requestのpauseを準備します。
publishedAt: 2026-09-06
updatedAt: 2026-09-06
tags:
  - tui
  - interception
  - testing
sidebar:
  order: 2
  label: labの準備
prev:
  link: /ja/use-cases/browser-form-lab/
  label: 概要
next:
  link: /ja/use-cases/browser-form-lab/first-get/
  label: 最初のGET
---

**前提：** [lab概要](../)を確認してから始めます。このpageでは三つのterminal、二つのlocal process、専用browser一つでformを操作できる状態にします。browser設定中はこのpageを残し、次は[最初のGET](../first-get/)へ進みます。stdout・echo・live TUIは非redactなのでsynthetic dataだけを使ってください。profile作成前に[後片付け](../cleanup-and-recovery/#cleanup)も確認します。

[lab概要とpage map](../#page-map)

## Quickstart

<a id="step-1"></a>

<a id="1-前提条件と三つのterminalを準備する"></a>

<a id="prerequisites"></a>

### 前提条件と三つのterminalを準備する

**操作：** Rust 1.98以上のtoolchainとrepositoryのnative build前提、JavaScriptを有効にした
desktop browser、repository rootで開いた三つのterminalを用意します。TUIには実際の
interactive terminalが必要です。loopbackの**3001**をorigin、**8080**をFreja用に確保し、
同じportを使う別のexample profileを同時に起動しないでください。初回buildではCargoが
依存を取得する場合がありますが、labの送信先はlocal fixtureだけです。
Node/pnpmはbrowser開発test用で、`/lab`の起動・利用には不要です。

| 見る場所 | 役割と期待する状態 |
| --- | --- |
| Terminal A | origin processと`[received]` request log |
| Terminal B | Freja config検証、その後TUIのTraffic・Repeat |
| Terminal C | ready確認コマンドとbrowserの手動起動 |
| 専用browser window | 入力フォーム、送信時preview、最新のorigin/proxy response |

**Evidenceから言えること：** 各画面を同時に見られるようにします。browserと両processが
意図したloopback環境を共有する必要があります。host browserとcontainer・VM・WSL内の
processではloopbackが異なる場合があるため、先に接続経路を揃えてください。
この手順はplain `http://`を使い、CA導入やTLS interceptionは不要です。
build前提は[Getting started](../../../guides/getting-started/)も参照してください。

<a id="step-2"></a>

<a id="2-originを起動しreadyを確認する"></a>

<a id="origin-readiness"></a>

### originを起動しreadyを確認する

**操作 — Terminal A：** repository rootから次を実行し、起動したままにします。

```sh
cargo run --manifest-path examples/http-test-server/Cargo.toml
```

**期待する表示 — Terminal A：** compile後、次のready行が表示されます。

```text
freja HTTP test server listening on http://127.0.0.1:3001
browser form lab: http://127.0.0.1:3001/lab (HTTP/1.1; verify the proxy path in Freja)
```

**操作 — Terminal C：** 必要なら既存health endpointへ直通で確認します。

```sh
curl --noproxy '*' --http1.1 -i http://127.0.0.1:3001/healthz
```

**表示とEvidence：** Terminal CにHTTP 200と`{"status":"ok"}`、Terminal Aに
`[received] GET /healthz`が出れば、originが直通で応答できています。
このready確認にFrejaは関与しません。bind失敗ならport競合を解決してから次へ進みます。

<a id="step-3"></a>

<a id="3-configを検証してfreja-tuiを起動する"></a>

<a id="freja-startup"></a>

### configを検証してFreja TUIを起動する

**操作 — Terminal B：** 先に設定を検証します。

```sh
cargo run -p freja -- check-config --config examples/config/tui/freja.interactive.toml
```

**期待する表示：** `configuration valid: 1 listener(s), policy generation 4`と正常終了を
確認します。その後、同じterminalでTUIを起動します。

```sh
cargo run -p freja -- run --config examples/config/tui/freja.interactive.toml
```

**表示とEvidence：** TUIに`Flows [1 Traffic]`が開き、まだlab requestはありません。
sampleは**TUI + Enforce + Interactive**で、lab用にloopback宛てを明示許可しています。
interactive body上限は16 KiB、未判断requestのtimeoutは30秒です。これはlabでのopt-inであり、
headlessではこのoperator操作を行えません。`freja.rules.toml`もhook無効のルール閲覧用です。
sampleは既存Freja audit segmentを`.`（このコマンドではrepository root）へ作成します。
[後片付け](../cleanup-and-recovery/#cleanup)も確認してください。

<a id="step-4"></a>

<a id="4-専用browserで開き入口requestをcontinueする"></a>

<a id="dedicated-browser"></a>

## 専用browserで開き、入口requestをcontinueする

**AのChromiumかBのFirefoxのどちらか一方**を選びます。後片付けのためTerminal Cを
残してください。両方を起動する必要はありません。

**browser起動前：** 入口requestを30秒以内にcontinueできるよう、[TUI図](../first-get/#tui-map)も見られる状態にします。

### A. Chromium

**操作 — Terminal C、UnixのChromium例：** `chromium`は手元のChromium/Chromeの
実行ファイル名へ置き換えてください。

```sh
lab_proxy_profile="$(mktemp -d /tmp/freja-lab-proxy.XXXXXX)"
printf '%s\n' "$lab_proxy_profile"
chromium --user-data-dir="$lab_proxy_profile" \
  --proxy-server="http://127.0.0.1:8080" \
  --proxy-bypass-list="<-loopback>" \
  http://127.0.0.1:3001/lab &
```

**`lab_proxy_profile`とは？** `mktemp -d`が作った一時directoryのpathを保持する、
このshell内の普通の変数です。上の`printf`でそのpathを表示しています。
Chromiumの`--user-data-dir`へ渡すことで、labのprofile・cookies・cache・extension・
proxy設定を普段のbrowser dataから分離します。Frejaのprofile/configでもHTTP parameterでも
特別な環境変数でもなく、**`export`は不要**です。

後片付けも同じ変数を読むのでshellを残し、browser processを閉じてからdirectoryを削除します。
`${lab_proxy_profile:?}`は未設定・空のときに`rm`の前でshellを止めるguardであり、
空でないpathが正しいdirectoryかまでは検証しません。変数を失ったら、表示したpath、
shell履歴、起動中browserのprocess args等から今回のdirectoryだけを特定します。
曖昧なwildcardでの一括削除に置き換えないでください。

Chromiumの`<-loopback>`は暗黙のlocalhost/loopback bypassを解除します。
画面の除外一覧を空にするだけでは不十分な場合があります。
[Chromiumのproxy仕様](https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md#overriding-the-implicit-bypass-rules)を参照してください。
Bは実行せず、下の**入口request**へ進みます。

### B. Firefox

以下のFirefox CLI/preferenceは公式資料・sourceと照合していますが、記録済みのlab検証ではFirefoxおよびmacOS実機での操作は未確認です。対応するTUI transactionで経路を確認してください。

**操作 — Terminal C：** 普段のFirefox instanceへcommandを渡さず、独立した使い捨て
profileを起動します。普段のprofileをimportせず、Syncへsign inせず、lab instanceを
既定browserにしないでください。

```sh
lab_firefox_profile="$(mktemp -d /tmp/freja-lab-firefox.XXXXXX)"
printf '%s\n' "$lab_firefox_profile"
firefox --no-remote --profile "$lab_firefox_profile" about:blank &
```

Linuxでは通常`firefox`、macOSの標準的な配置では
`"/Applications/Firefox.app/Contents/MacOS/firefox"`を使います。実際のinstall先に合わせて
実行ファイル名を置き換えてください。`--profile`はこのdirectoryを指定し、`--no-remote`は
remote commandの使い回しを避け、new instanceを含意します。別profileのFirefoxは起動したままで
構いませんが、同じdirectoryを二つのprocessで開かないでください。
[Firefoxの公式CLI仕様](https://firefox-source-docs.mozilla.org/browser/CommandLineParameters.html)に
記載されたswitchを使っています。`lab_firefox_profile`も後片付けに使うshell変数です。
実行ファイルから表示したdirectoryへアクセスできる必要があります。隔離されたpackageでは、
アクセスを許可されたfilesystem内にprofile directoryを作る必要があります。

**このFirefox windowでproxyを設定します。** 上のcommandはprofileを選ぶだけで、
proxy設定は行いません。Firefoxに上のChromium用proxy flagと同じものはありません。
対応する設定画面を使います。

1. `about:preferences`を開き、**proxy**（日本語UIなら**プロキシ**）を検索して接続/proxy
   設定dialogを開きます。現行版はPrivacy & Security → Connection and software security →
   Advanced settings → Proxy settings、旧版はGeneral → Network Settings → Settingsの配置です。
   locale/versionで表示名が異なるため、固定位置に頼らずSettings内の検索を使います。
2. **Manual proxy configuration（手動でプロキシを設定）**を選び、**HTTP Proxy**を
   `127.0.0.1`、**Port**を`8080`にします。**No Proxy For（プロキシなしで接続）**は空にし、
   `localhost`・`127.0.0.1`・`::1`・`<local>`も除外しません。plain HTTPのlabなので
   HTTPS/SOCKSは未設定、HTTPSへ同じproxyを使うcheckboxもoffにして保存します。
3. この専用windowの`about:config`で設定変更の警告を確認し、
   `network.proxy.allow_hijacking_localhost`を探して**true**にします。
   No Proxy Forを空にするだけではFirefox内蔵のloopback bypassを解除できません。
   使い捨てのlab profile内だけで変更します。
4. `about:config`で下表の値を照合します。設定したwindowが不明なら`about:support`で
   profile directoryが表示済みの`lab_firefox_profile`と一致するか確認します。
   その後`http://127.0.0.1:3001/lab`を開きます。

| Firefox preference | Lab value |
| --- | --- |
| `network.proxy.type` | `1` (manual) |
| `network.proxy.http` | `127.0.0.1` |
| `network.proxy.http_port` | `8080` |
| `network.proxy.no_proxies_on` | empty string |
| `network.proxy.allow_hijacking_localhost` | `true` |

[Firefoxの接続設定](https://support.mozilla.org/en-US/kb/connection-settings-firefox)と
[sourceのloopback bypass判定](https://github.com/mozilla-firefox/firefox/blob/main/netwerk/base/nsProtocolProxyService.cpp)を
参照してください。組織policyで変更不可、またはprofile使用中のエラーなら、普段のprofileへ
変更を加えず、専用profileの準備を確認します。設定値だけでは経路の証拠にならないため、
FrejaのTUIで実際のrequestを照合します。

### 入口request — どちらのbrowserでも共通

fixture自体はbrowserを起動せず、browser/OS設定も変更しません。

**操作と表示 — Terminal B：** フォームを使える前に、ページ自身のrequestを扱います。

1. **`1`**でTrafficに移動し、上部の**Flows**一覧にfocusを置きます。
2. `j`/`k`またはDown/Upで`/lab`の`HTTP paused`行を選びます。
   選択行には`>`が付きます。**`c`**で変更せずcontinueします。
3. `/lab/app.js`と`/lab/style.css`のGETもpauseしたら同じ操作でcontinueします。
   順序は一定ではありません。各pauseから30秒以内に判断します。

**表示とEvidence：** continue後にTerminal Aへ対応するGETが出ます。
browserには**One request. Follow it through.**と、操作可能な**Send GET query**が出ます。
scriptがpause中でもHTMLだけ先に表示される場合があります。入力欄が無効、
**Waiting for the local script**なら`/lab/app.js`、装飾がなければ`/lab/style.css`を確認します。
入口requestが期限切れならTUIを準備して`/lab`をreloadします。
この入口GETのreloadはフォームPOSTを再送しません。

対応するTUI requestなしでページ全体が表示された場合は、次をFrejaの検証成功とする前に
proxy経路を確認してください。
