# freja-ui

Immutable UI events, bounded non-blocking publication, and an optional ratatui
traffic interface with typed HTTP/1.1 editing and Repeat workspaces. Enable the
`tui` feature for the terminal implementation. Diagnostics selects decisions
with `j/k`, opens their bounded read-only rule definitions with Enter, and returns
with Enter/q. ACL details show the configured rule count, default action,
ordered conditions/actions and actual outcomes, distinguishing empty policies,
nonmatches and unavailable stage inputs. Definitions preserve evaluation provenance and generation and are
excluded from serialized UI events; they are sensitive local memory only.

See the [API documentation](https://docs.rs/freja-ui) and the
[Freja repository](https://github.com/karanabe/freja).

### License

<sup>
Licensed under either of <a href="https://github.com/karanabe/freja/blob/master/LICENSE-APACHE">Apache License, Version 2.0</a> or <a href="https://github.com/karanabe/freja/blob/master/LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
</sub>
