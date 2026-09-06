---
title: 開発とテスト
description: workspace構造、validation gate、integration test、fuzz target、documentation workflowです。
publishedAt: 2026-08-31
updatedAt: 2026-09-06
tags:
  - テスト
  - contribution
  - 開発者
sidebar:
  order: 5
---

FrejaはRust edition 2024を使い、workspaceで宣言および検証するminimum Rust versionは1.98です。Pingora compatibilityは0.8.1へ固定しています。

## 必須gate

milestone完了前にすべて実行します。

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo check --manifest-path fuzz/Cargo.toml --bins
(cd docs && pnpm check)
```

multi-listener CLIがTokioを選択していてもall-feature buildはPingora adapterをcompileします。integration testはlocal serverと外部観測可能なprotocol behaviorを使い、public network serviceへ依存しません。

## Test ownership

- `freja-policy`: first-match trace、destination guard、split-pattern、typed mutation、timeout、paused-flow bound
- `freja-audit`: redaction-before-hash、sequence/hash chain、checkpoint tamper detection
- `freja-proxy/tests/http_forward.rs`: absolute-form、framing limit、CONNECT、auth、response policy、inspection、Hook、reload、TLS interception、intercept後HTTP/1.1/HTTP/2 semantic forwarding、fresh correlation IDかつ再pauseなしのcleartext/TLS repeat HTTP/1.1実行、pinning failure、TUI専用plain HTTP/1 request/response ingress exact capture
- `tcp_static.rs`/`socks_forward.rs`: relay、DNS reauthorization、detour、limit、inspection、authentication
- CLI test: configuration、no-overwrite segment、pinned checkpoint replay、Cargo metadataによるworkspace dependency direction/Pingora isolation境界
- UI test: ratatui test backendによるsplit/片側全幅traffic、diagnostics、repeat render、pane/終了/editor/repeat key state、型付きrequest draft、non-blocking saturation、terminal-control escape。HTTP integration suiteはmanual header/bodyの原子的mutationとframing再構築をupstream serverで検証

Diagnostics testは、同じURLへの別request、複数評価、未取得・遅延・eviction後のmetadata、CONNECT、部分的targetについてrequestと評価の所属を検証します。長いUnicode targetの最小terminalサイズ・拡大表示、評価行scroll中のrequest情報の固定表示、既存TCPのsession相関も確認します。評価ごとのIPv4/IPv6 targetと結果が保持上限下でも対応し、target情報のない旧UI eventがunavailable表示になることも検証します。local CONNECT integration testはobserverのtargetとpolicyが実際に評価した記録済みfactを照合し、HTTP body inspection testはcaptureを有効にせず選択接続先がdecisionへ付帯することを確認します。

local logicにはfocused unit test、externally observable network/CLI変更にはintegration testを追加します。

## ローカルHTTPテストorigin

非公開の`examples/http-test-server` packageは、public network serviceへ依存せずに手動でproxyを確認するためのAxum originです。defaultでは`127.0.0.1:3001`にbindし、GET、POST、PUT、PATCH、DELETE、HEAD、OPTIONS、任意methodのrequest echo routeを提供します。status、redirect、delay、streaming、固定size responseも上限付きで試せます。

Frejaで`examples/config/headless/freja.toml`を使い、それぞれ別のterminalで実行します。

```sh
cargo run --manifest-path examples/http-test-server/Cargo.toml
cargo run -p freja -- run --config examples/config/headless/freja.toml
curl --noproxy "" --proxy http://127.0.0.1:8080 \
  http://127.0.0.1:3001/get?name=freja
curl --noproxy "" --proxy http://127.0.0.1:8080 \
  http://127.0.0.1:3001/post --data 'hello through Freja'
```

`--noproxy ""`はenvironmentのloopback除外によってFrejaが迂回されるのを防ぎます。sample configurationはlocal test専用にloopback destinationを許可しています。serverは受信したmethod、URI、header一式、body全体のsize、最大4 KiBのbody previewをterminalへ表示します。credential/Cookieを含むすべてのheader値は、開発用として意図的に伏字にしません。binary previewはBase64、terminal control characterはescapeされます。URI、header、body previewはsensitiveなままなので、合成したsecretとpayloadだけを使ってください。route一覧と上限は`examples/http-test-server/README.md`に記載しています。

`examples/config/headless/`と`examples/config/tui/`以下のstandalone fileで、enforceするheadless運用、focused blocking detector、および広い上限またはfocusedな上限のinteractive TUIを試せます。CLI integration suiteは同梱する全templateへ`check-config`を実行し、schema変更でsampleが暗黙に無効にならないことを確認します。

## Browser form fixture

[HTTP/1.1 browser form lab](../../use-cases/browser-form-lab/)にinteractive profile、
loopback proxy設定、入口ページのpause、手動で照合する証拠を記載しています。
`/lab`は独立example内の同一origin向け静的ページで、既存JSON/curl routeも使えます。

exampleは7 crateのworkspace外にあるため、個別に検証します。

```sh
cargo fmt --manifest-path examples/http-test-server/Cargo.toml -- --check
cargo clippy --manifest-path examples/http-test-server/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path examples/http-test-server/Cargo.toml --all-features
```

`tests/browser_form.rs`はlocal HTTP契約、上限付きform解釈、不正な編集済みbyte、
header/表示上限、既存JSON route互換を確認します。`tests/freja_form.rs`はlocal
originとFrejaを起動し、既存typed brokerでcontinue、編集、reject、pause期限切れ、
新しいtransactionに対応するRepeatを実行します。upstream TCP接続とHTTP request
到達を分けて確認し、直通とorigin停止の対照も含みます。TUIのキー操作は行いません。

Node.js 22+とpnpm 11+でbrowser testを実行します。

```sh
cd examples/http-test-server
pnpm install --frozen-lockfile
pnpm exec playwright install chromium
pnpm test:browser
```

Chromiumが必要とするhost libraryはinstallerの案内に従って用意します。
`tests/browser.mjs`は使い捨てlocal originを起動し、GET/POST encoding、空欄・日本語、
UTF-8上限、再入力、keyboard送信、安全な文字表示、両color modeの狭い画面、失敗、
送信待ち・timeout、response上限を確認します。browserの失敗・遅延は制御した模擬応答で、
実際のFrejaを確認するRust testとは区別します。どちらもmaintainerがbrowserとTUIの
workflowを完遂した証拠にはなりません。手動ではrevision、browser/OSとproxy設定、
HTTP/1.1と取引の対応、origin到達、迷った手順を記録し、未実施は未観察と明示します。

## Browser lab visuals

両言語の[最初のGET page](../../use-cases/browser-form-lab/first-get/)は`/images/browser-form-lab/get-ready.png`を共有します。`docs/public/`に置き、
static siteへそのままcopyします。controlやlayoutを変更したら、実際の埋め込み`/lab`から
再撮影してください。上記の固定版Playwright依存、Chromium、host libraryを用意したうえで、
**repository rootから**次を実行します。

```sh
cargo build --manifest-path examples/http-test-server/Cargo.toml
node docs/scripts/capture-browser-form-lab.mjs
(cd docs && pnpm check)
```

scriptはephemeral portのloopback originを自分で起動・停止します。新しいChromium contextを
1100×2400 CSS pixel、device scale 1、`en-US`、light color scheme、reduced motionで使います。
GETを選び、case `get-01`、message `hello origin`を入れ、送信せずkeyboard focusをSendへ
移します。prepared encodingと未送信状態を確認し、fontの準備を待って実際のinput/result
sectionを切り出します。DOMの改変や架空controlの描画は行いません。guideのB1–B7 legendが
実際のcontrolを説明します。address bar、machine固有のorigin port、header、credential、
実trafficは画像に含めません。

基準の撮影環境はLinux、Chromium 153.0.8010.12（Playwright固定版のbuild 1243）です。
OSのfontやnative controlでpixelは変わるため、hashを環境共通のvisual testとせず、
再撮影した画像、buttonのfocus、syntheticな文字を目視確認してください。
英日のalt text、caption、legendを同期します。この未送信のorigin画像だけではFreja経由を
証明できません。

TUIのASCII図はTraffic/Pretty/Splitの代表状態で、空行を省略し、文書の注記T1–T4を付けています。
更新時は`crates/freja-ui/src/tui/render.rs`と現在のkey処理に照合し、localのpaused `/lab`
requestでも確認します。`1`でFlowsへfocusして対象行を選び、Request/Responseのtitleを
確認してください。幅やdataにより折り返しとhintは変わります。文書の注記を実際のUI labelとして
扱わず、実traffic入りのterminal録画も使わないでください。browserとTUIを通した一連の
手動観察は別の確認として残ります。

## Fuzz target

nested `fuzz` workspaceにはproduction parser/state machineの5 targetに加え、
開発originの上限付きapplication form decoder用targetがあります。

```sh
cargo check --manifest-path fuzz/Cargo.toml --bins
```

configuration parsing、target parsing、HTTP mutation plan、binary scanning、malformed/ambiguous HTTP framingを対象にします。framing targetはprivate capture-only HTTP/1 message-boundary state machineも駆動します。
`browser_form`はexampleの`fuzzing` feature経由で実際のlab form decoderへ最大2 KiBを
渡します。HTTP wire framingのparserではありません。target buildは接続維持を証明しますが、release hardeningではcorpusを保持したtime-bounded `cargo-fuzz` campaignも実行してください。

## Code constraint

- 全library crateは`#![forbid(unsafe_code)]`
- library layerで`anyhow`、`thiserror`等のerror erasureを使用しない
- non-test codeで`unwrap`、`expect`、`panic`、`todo`、`unimplemented`を使わない
- concrete sourceを保持しboundaryでcontextを追加
- unbounded channelを使わずUI deliveryでforwardingをblockしない
- public typeと自明でないinvariantにrustdocを付ける

## Documentation site

Astro siteは`docs/`にあり、英語/日本語でmatching contentを持ちます。

```sh
cd docs
pnpm install --frozen-lockfile
pnpm check
```

1 changeで両locale pathを更新します。pageとcodeが不一致なら、code、sample configuration、packaging、integration testを正とします。

## Rule inspection lab

`examples/config/tui/freja.rules.toml`は無害なfixture用で、Observe、hook無効、
保持8行です。一つのterminalで同梱originを起動し、別terminalでFrejaをbuildして
使い捨ての設定コピーを起動します。

```sh
cargo run --manifest-path examples/http-test-server/Cargo.toml
```

```sh
cargo build -p freja
cp examples/config/tui/freja.rules.toml /tmp/freja-rules.toml
./target/debug/freja run --config /tmp/freja-rules.toml
```

三つ目のterminalから、無害なrequestをproxy経由で送ります。

```sh
curl --noproxy "" -x http://127.0.0.1:8080 http://127.0.0.1:3001/get
curl --noproxy "" -x http://127.0.0.1:8080 http://127.0.0.1:3001/get
curl --noproxy "" -x http://127.0.0.1:8080 http://127.0.0.1:3001/healthz
curl --noproxy "" -x http://127.0.0.1:8080 http://127.0.0.1:3001/post --data freja-deny
curl --noproxy "" -x http://127.0.0.1:8080 --proxytunnel http://127.0.0.1:3001/healthz
```

最初のGET二件は異なるTransactionIdを持ち、`lab-compound`のdenyがあっても
Observeのためoriginの200を受け取ります。定義はGET、3000–3010の両端を含むport範囲、
`/get`または`/anything/private`、そして`yes`を含む`x-lab-bypass` headerではないことの
組合せです。`/healthz`のHTTP request評価は、設定済みACL 2件と既定allowを示し、
条件不一致を確認できます。それ以前の宛先評価はHTTP条件の情報未取得を示します。
使い捨て設定から両方の`[[policy.rules]]`ブロックを削除して`[policy]`に`rules = []`を
設定した場合とも比較します。ACL未設定の場合は0件と明示します。
POSTは`lab-post`と検出判断の
`lab-body-deny`を持ちます。proxytunnelは組み込みCONNECT制限（許可port 443）を
示しますが、Observeなのでdenyが遮断を意味しません。接続先保護を確認する場合は、
設定コピーの`loopback_destinations = "protect"`と`enforcement = "enforce"`で別起動し、
loopback requestが他hostに接続せず拒否されることを確認します。その後はlab設定へ戻します。

operatorにTrafficでアクセスを選び、`2`、`j/k`、Enterで使用ルールを開き、条件・
アクション・記録された理由・世代を説明してもらいます。`z`での拡大も試し、Enterと
`q`の両方で閉じて、選択と閲覧位置を維持できるか観察します。詳細を開いたまま
別requestを到着させ、対象が入れ替わらないことも確認します。

Unixのreloadでは世代101の詳細を開いたまま、使い捨て設定のgenerationを102にし、
`lab-compound`のactionだけを`allow`へ、第二path枝を`/anything/reloaded`へ変更します。
このlabのFreja processのPIDにSIGHUPを送り、同じ`/get`を再送します。旧詳細は
世代101・deny・`/anything/private`、新取引は世代102・allow・`/anything/reloaded`を
示すことを確認します。継続scannerの世代を現在のglobal policyから推定しません。

行の削除は詳細を開いたままさらに10件のrequestを順次送って確認します。
各curl processが接続を閉じるため、8行の上限により元アクセスが消え得ます。
詳細には削除を表示し、閉じても別評価を暗黙に選びません。Trafficへ戻って保持中の
アクセスを選びます。長い定義、行内上限による削除、serialize後の定義未保持、
継続scannerのreloadなど手動再現が難しい項目は、決定的なfixture検証と利用観察を区別します。

自動検証は`freja-policy/src/evidence/tests.rs`、`freja-ui/src/tui/evidence_tests.rs`、
proxyのHTTP Diagnostics integration suiteにあります。ACL未設定と設定済みの既定動作、
実際の条件不一致と情報未取得、first-matchによる未評価、reload前の設定保持、
複合定義全体、出所のID衝突、
上限・escaping、modal操作、同URLの対応、reload前からのscanner、未読のboundedな
UI queueがあっても転送が進むことを確認します。test成功だけではoperatorのOutcomeを
証明しません。各ケースについてrule・世代、外部設定画面への往復回数、誤選択、
開閉で迷った操作、不足情報、説明を完了できたかを記録し、未実施は**未観察**とします。
実credentialや実payloadは使わず、追加の通信内容を保存しません。
