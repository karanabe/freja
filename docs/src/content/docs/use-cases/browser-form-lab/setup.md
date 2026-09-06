---
title: Prepare the lab
description: Start the origin and Freja, isolate a Chromium or Firefox profile, and handle entry-page pauses.
publishedAt: 2026-09-06
updatedAt: 2026-09-06
tags:
  - tui
  - interception
  - testing
sidebar:
  order: 2
  label: Prepare the lab
prev:
  link: /use-cases/browser-form-lab/
  label: Overview
next:
  link: /use-cases/browser-form-lab/first-get/
  label: First GET
---

**Before you start:** read the [lab overview](../). This page prepares three terminals, two local processes and one dedicated browser with the form ready. Keep this page open for browser setup; next, [send the first GET](../first-get/). Use synthetic data only: stdout, echo and the live TUI are unredacted. Review [cleanup](../cleanup-and-recovery/#cleanup) before creating profiles.

[Lab overview and page map](../#page-map)

## Quickstart

<a id="step-1"></a>

<a id="1-prepare-the-tools-and-three-terminals"></a>

<a id="prerequisites"></a>

### Prepare the tools and three terminals

**Do:** use a Rust 1.98+ toolchain with the repository's native build prerequisites,
a JavaScript-enabled desktop browser, and three terminals opened at the repository
root. A real interactive terminal is required for the TUI. Reserve loopback
ports **3001** for the origin and **8080** for Freja; do not run another example
profile on the same ports. Cargo may fetch dependencies on the first build;
the lab requests themselves use only a local fixture. Node/pnpm is needed for
browser development tests, not for serving or using `/lab`.

| Where to look | Role and expected state |
| --- | --- |
| Terminal A | Origin process and its `[received]` request log |
| Terminal B | Freja config check, then the TUI: Traffic and Repeat |
| Terminal C | Readiness commands and manual browser launch |
| Dedicated browser window | Form, submitted preview and latest origin/proxy response |

**Evidence:** keep these views visible together. The browser and both processes
must share the intended loopback environment. A host browser and a container,
VM or WSL process can have different loopbacks; resolve that before proceeding.
This walkthrough uses plain `http://`, without CA installation or TLS interception.
See [Getting started](../../../guides/getting-started/#prerequisites) for build prerequisites.

<a id="step-2"></a>

<a id="2-start-the-origin-and-confirm-readiness"></a>

<a id="origin-readiness"></a>

### Start the origin and confirm readiness

**Do — Terminal A:** run from the repository root and leave it running:

```sh
cargo run --manifest-path examples/http-test-server/Cargo.toml
```

**Look — Terminal A:** after compilation, expect these ready lines:

```text
freja HTTP test server listening on http://127.0.0.1:3001
browser form lab: http://127.0.0.1:3001/lab (HTTP/1.1; verify the proxy path in Freja)
```

**Do — Terminal C:** optionally check the existing health endpoint directly:

```sh
curl --noproxy '*' --http1.1 -i http://127.0.0.1:3001/healthz
```

**Look / evidence:** Terminal C returns HTTP 200 and `{"status":"ok"}`; Terminal A
prints `[received] GET /healthz`. This proves that the origin responds directly.
Freja is not involved in this readiness check. If binding fails, resolve the
port conflict before starting another process.

<a id="step-3"></a>

<a id="3-validate-the-config-and-start-freja"></a>

<a id="freja-startup"></a>

### Validate the config and start Freja

**Do — Terminal B:** validate first:

```sh
cargo run -p freja -- check-config --config examples/config/tui/freja.interactive.toml
```

**Look:** expect `configuration valid: 1 listener(s), policy generation 4` and a
successful exit. Then start the TUI in the same terminal:

```sh
cargo run -p freja -- run --config examples/config/tui/freja.interactive.toml
```

**Look / evidence:** the TUI opens, with `Flows [1 Traffic]` and initially no lab
requests. The sample is **TUI + Enforce + Interactive**, explicitly permits
loopback destinations, limits interactive bodies to 16 KiB, and expires undecided
requests after 30 seconds. This is the lab's opt-in configuration. Headless cannot
perform these operator actions; `freja.rules.toml` disables hooks for rule inspection.
The sample also writes existing Freja audit segments under `.` (the repository
root for these commands); see [cleanup](../cleanup-and-recovery/#cleanup).

<a id="step-4"></a>

<a id="4-open-the-dedicated-browser-and-continue-the-entry-requests"></a>

<a id="dedicated-browser"></a>

## Open the dedicated browser and continue the entry requests

Choose **one** browser: Chromium in A or Firefox in B. Keep Terminal C open
for that option's cleanup; do not start both as a prerequisite.

**Before launching the browser:** keep the [TUI map](../first-get/#tui-map) available to help continue the entry requests within 30 seconds.

### A. Chromium

**Do — Terminal C, Chromium on Unix:** replace `chromium` with your installed
Chromium/Chrome executable if necessary:

```sh
lab_proxy_profile="$(mktemp -d /tmp/freja-lab-proxy.XXXXXX)"
printf '%s\n' "$lab_proxy_profile"
chromium --user-data-dir="$lab_proxy_profile" \
  --proxy-server="http://127.0.0.1:8080" \
  --proxy-bypass-list="<-loopback>" \
  http://127.0.0.1:3001/lab &
```

**What is `lab_proxy_profile`?** It is an ordinary variable in this shell,
containing the path of the temporary directory created by `mktemp -d` (printed
above). Chromium receives that path through `--user-data-dir`, keeping the lab's
profile, cookies, cache, extensions and proxy setup apart from your everyday
browser data. It is not a Freja profile/config, an HTTP parameter or a special
environment variable; **no `export` is needed**.

Cleanup later reads the same variable, so keep this shell and close the browser
process before deleting its directory. `${lab_proxy_profile:?}` stops the shell
before `rm` if the variable is unset or empty; it does not verify that a nonempty
path is the right directory. If you lose the variable, identify only this run's
directory from the printed path, shell history or the running browser's process
arguments. Never replace it with an ambiguous wildcard deletion.

In Chromium, `<-loopback>` removes the implicit localhost/loopback proxy bypass;
clearing only a visible exception list can be insufficient. See
[Chromium's proxy rules](https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md#overriding-the-implicit-bypass-rules).
Continue at **Entry requests** below; skip option B.

### B. Firefox

The Firefox CLI/preferences below were checked against official documentation/source; Firefox and macOS have not been exercised on actual devices in the recorded lab validation. Confirm traversal with a matching TUI transaction.

**Do — Terminal C:** create a separate disposable profile and start it without
handing the command to an everyday Firefox instance. Do not import a profile,
sign in to Sync or make this lab instance your default browser.

```sh
lab_firefox_profile="$(mktemp -d /tmp/freja-lab-firefox.XXXXXX)"
printf '%s\n' "$lab_firefox_profile"
firefox --no-remote --profile "$lab_firefox_profile" about:blank &
```

`firefox` is a common Linux executable name. For a standard macOS installation,
replace it with `"/Applications/Firefox.app/Contents/MacOS/firefox"`; use the
actual installation path on your machine. `--profile` selects this directory;
`--no-remote` prevents remote command reuse and implies a new instance. Other
Firefox profiles can remain open, but do not open this same directory in two
processes. These are [documented Firefox switches](https://firefox-source-docs.mozilla.org/browser/CommandLineParameters.html).
`lab_firefox_profile` is another shell variable with the same cleanup role.
The executable must be able to access the printed directory; a confined package
may need a profile directory within its permitted filesystem paths.

**Set the proxy in this Firefox window.** The command above selects a profile;
it does **not** configure a proxy. Firefox has no equivalent of the Chromium
proxy flags used above. Use its supported settings instead:

1. Open `about:preferences`, search for **proxy**, and open the connection/proxy
   settings dialog. Current versions place this under Privacy & Security →
   Connection and software security → Advanced settings → Proxy settings;
   older versions use General → Network Settings → Settings. Labels vary by
   locale/version; the Settings search avoids relying on one fixed location.
2. Select **Manual proxy configuration**. Set **HTTP Proxy** to `127.0.0.1` and
   **Port** to `8080`. Leave **No Proxy For** empty, including no `localhost`,
   `127.0.0.1`, `::1` or `<local>` exclusions. Leave HTTPS/SOCKS unset and the
   HTTPS-sharing checkbox off for this plain-HTTP lab. Save the dialog.
3. In this dedicated window's `about:config`, acknowledge the settings warning,
   find `network.proxy.allow_hijacking_localhost`, and set it to **true**.
   Clearing No Proxy For alone does not remove Firefox's built-in loopback
   bypass. Change this only in the disposable lab profile.
4. Verify the following values in `about:config`. Open `about:support` and check
   that its profile directory is the printed `lab_firefox_profile` path if you
   are unsure which window you configured. Then open `http://127.0.0.1:3001/lab`.

| Firefox preference | Lab value |
| --- | --- |
| `network.proxy.type` | `1` (manual) |
| `network.proxy.http` | `127.0.0.1` |
| `network.proxy.http_port` | `8080` |
| `network.proxy.no_proxies_on` | empty string |
| `network.proxy.allow_hijacking_localhost` | `true` |

See [Firefox connection settings](https://support.mozilla.org/en-US/kb/connection-settings-firefox)
and the [loopback bypass check in Firefox source](https://github.com/mozilla-firefox/firefox/blob/main/netwerk/base/nsProtocolProxyService.cpp).
A locked enterprise setting or a profile-in-use error is not a reason to change
your normal profile. Resolve the dedicated-profile setup and verify the path in
Freja's TUI. Setting values alone is not evidence of proxy traversal.

### Entry requests — either browser

The fixture does not launch browsers or change browser/OS settings itself.

**Do / look — Terminal B:** before the form is usable, handle its own requests:

1. Press `1` to select Traffic and focus its top **Flows** list.
2. Use `j`/`k` or Down/Up to select the `HTTP paused` row for `/lab`.
   The selected row has `>`. Press **`c`** to continue it unchanged.
3. Continue paused `/lab/app.js` and `/lab/style.css` GETs in the same way.
   Their order can vary. Decide within 30 seconds of each pause.

**Look / evidence:** Terminal A logs the corresponding GETs after continue.
The browser shows **One request. Follow it through.** with an enabled **Send GET
query** button. HTML can appear while the script is still paused; disabled fields
and **Waiting for the local script** are a cue to check `/lab/app.js`. Missing
styling is a cue to check `/lab/style.css`. If an entry request expired, prepare
the TUI and reload `/lab`; this entry GET does not resubmit a form POST.

If the entire page loads without matching TUI requests, verify the proxy route
before treating the next step as a Freja test.
