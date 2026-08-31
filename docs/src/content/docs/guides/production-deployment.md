---
title: Production deployment
description: Install Freja under systemd, reload policy safely, and operate bounded shutdown and metrics.
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - operations
  - systemd
  - deployment
sidebar:
  order: 8
---

Freja includes a hardened systemd unit, sysusers declaration, and tmpfiles
declaration. Review every path and listener before installing them on a target
host.

## Build and install

```sh
cargo build --release -p freja-cli
sudo install -Dm0755 target/release/freja /usr/bin/freja
sudo install -Dm0644 packaging/freja.service /etc/systemd/system/freja.service
sudo install -Dm0644 packaging/freja.sysusers /usr/lib/sysusers.d/freja.conf
sudo install -Dm0644 packaging/freja.tmpfiles /usr/lib/tmpfiles.d/freja.conf
sudo systemd-sysusers /usr/lib/sysusers.d/freja.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/freja.conf
sudo install -Dm0640 examples/freja.toml /etc/freja/freja.toml
```

Edit `/etc/freja/freja.toml` and set `audit.path = "/var/lib/freja"`; the
repository example uses a local file for its unprivileged quick start. The packaged service writes only below
`/var/lib/freja` and `/run/freja`, runs as the `freja` user, drops all
capabilities, and applies filesystem, kernel, process, syscall, and
address-family restrictions.

Validate before enabling:

```sh
sudo -u freja /usr/bin/freja check-config --config /etc/freja/freja.toml
systemd-analyze verify /etc/systemd/system/freja.service
systemd-analyze security --offline=yes /etc/systemd/system/freja.service
sudo systemctl daemon-reload
sudo systemctl enable --now freja.service
```

## Observe the process

```sh
systemctl status freja.service
journalctl -u freja.service -f
```

Operational logs go to the service's standard output through `tracing`.
Security audit JSONL is written to `audit.path`; protect, rotate, export, and
retain it according to its higher sensitivity. Freja creates new segments with
`0600` permissions on Unix, while the supplied state directory is `0750`.

Freja exposes process-local lock-free counters through
`DataPlaneServices::metrics_snapshot` for embedders. The CLI does not expose an
HTTP metrics endpoint. The snapshot includes flow counts, bytes, policy
actions, findings, TLS interception/cache activity, manual actions, rejected
audit events, and dropped UI events.

## Reload policy

On Unix, replace the configuration file atomically and send SIGHUP:

```sh
sudo /usr/bin/freja check-config --config /etc/freja/freja.toml.new
sudo mv /etc/freja/freja.toml.new /etc/freja/freja.toml
sudo systemctl kill --signal=HUP freja.service
```

The supplied unit does not define `ExecReload`; `systemctl reload` is therefore
not available. Use the explicit signal command above for a compatible hot
reload, or restart the service when restart-only settings change.

One `ArcSwap` operation replaces ACL, destination guard, enforcement mode,
inspection program/mode, and policy generation. Listener, authentication,
limits, TLS, UI/hooks, capture, and audit changes require restart and are
rejected as hot reloads.

## Graceful shutdown

SIGINT and SIGTERM stop accepts, signal active relays, drain listener tasks,
flush audit records, and restore the TUI. The unit allows 90 seconds before
systemd escalates shutdown. Choose connection idle timeouts that fit the
service's stop budget.

Run the target host's systemd validators after every unit change because
available sandbox directives differ across distributions.
