<br />
<h1 align="center">Freja</h1>
<h3 align="center">A command-line toolbox integrating multiple utilities, starting with a WebSocket tester.</h3>
<br />
<br />

Freja aims to bundle several small command-line tools into a single binary.
Currently it provides a WebSocket client and a simple echo server so you can
quickly debug or demonstrate WebSocket interactions from the terminal.

### Goals

- Combine several lightweight utilities under one CLI
- Offer an easy-to-use WebSocket client and server
- Serve as a minimal example of `tokio` + `tokio-tungstenite`

### Feature

- Initial command provides a WebSocket client
- Server mode running a local echo service

### TODO

- TLS support
- Configurable logging

### Getting Started

```shell
# Build and run as a client
cargo run -- websocket example.com --port 4444

# Listen as an echo server
cargo run -- websocket -l 0.0.0.0 --port 4444
```


## License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version 2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
</sub>
