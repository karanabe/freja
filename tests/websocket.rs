use freja::commands::websocket::{self, WebsocketOpts};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[tokio::test]
async fn run_with_calls_client() {
    let opts = WebsocketOpts {
        listen: false,
        url: "host".into(),
        port: 1234,
    };
    let called = Arc::new(AtomicBool::new(false));
    let called_clone = called.clone();
    let client = move |h: String, p: u16| {
        assert_eq!(h, "host");
        assert_eq!(p, 1234);
        called_clone.store(true, Ordering::SeqCst);
        async { Ok(()) }
    };
    let server = |_opts: WebsocketOpts| async { Ok(()) };
    websocket::run_with(opts, client, server).await.unwrap();
    assert!(called.load(Ordering::SeqCst));
}

#[tokio::test]
async fn run_with_calls_server() {
    let opts = WebsocketOpts {
        listen: true,
        url: "host".into(),
        port: 4321,
    };
    let called = Arc::new(AtomicBool::new(false));
    let called_clone = called.clone();
    let client = |_h: String, _p: u16| async { Ok(()) };
    let server = move |o: WebsocketOpts| {
        assert!(o.listen);
        assert_eq!(o.url, "host");
        assert_eq!(o.port, 4321);
        called_clone.store(true, Ordering::SeqCst);
        async { Ok(()) }
    };
    websocket::run_with(opts, client, server).await.unwrap();
    assert!(called.load(Ordering::SeqCst));
}
