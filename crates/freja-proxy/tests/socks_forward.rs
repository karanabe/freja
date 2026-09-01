use std::{net::IpAddr, time::Duration};

use freja_audit::{AuditEnvelope, AuditEvent, AuditFailurePolicy, AuditPublisher};
use freja_domain::{
    EnforcementMode, ListenEndpoint, PolicyGeneration, ProxyCredentialHash, Socks5Listener,
};
use freja_policy::{
    AclPolicy, DestinationAccess, DestinationGuard, DestinationGuardSettings, RuleAction,
};
use freja_proxy::{DataPlaneServices, ProxyLimits, Socks5Server, shutdown_channel};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::timeout,
};

fn limits() -> ProxyLimits {
    ProxyLimits::new(
        8,
        16 * 1_024,
        16 * 1_024,
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(2),
    )
    .unwrap()
}

fn services() -> (DataPlaneServices, mpsc::Receiver<AuditEnvelope>) {
    let generation = PolicyGeneration::new(31).unwrap();
    let policy = AclPolicy::new(generation, Vec::new(), RuleAction::Allow).unwrap();
    let guard = DestinationGuard::new(DestinationGuardSettings {
        loopback: DestinationAccess::Allow,
        ..DestinationGuardSettings::default()
    })
    .unwrap();
    let (audit, receiver) = AuditPublisher::channel(128, AuditFailurePolicy::FailClosed).unwrap();
    (
        DataPlaneServices::new(policy, guard, EnforcementMode::Enforce, audit),
        receiver,
    )
}

async fn echo_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0_u8; 32];
        let count = stream.read(&mut bytes).await.unwrap();
        stream.write_all(&bytes[..count]).await.unwrap();
    });
    (address, task)
}

async fn start_server(
    authentication: Option<ProxyCredentialHash>,
) -> (
    std::net::SocketAddr,
    freja_proxy::ShutdownSender,
    tokio::task::JoinHandle<Result<(), freja_proxy::ProxyError>>,
    mpsc::Receiver<AuditEnvelope>,
) {
    let (services, audit) = services();
    let mut specification = Socks5Listener::new(ListenEndpoint::new(
        (IpAddr::from([127, 0, 0, 1]), 0).into(),
    ));
    if let Some(authentication) = authentication {
        specification = specification.with_authentication(authentication);
    }
    let server = Socks5Server::bind(specification, services, limits())
        .await
        .unwrap();
    let address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    let task = tokio::spawn(server.run(signal));
    (address, shutdown, task, audit)
}

async fn stop_server(
    shutdown: freja_proxy::ShutdownSender,
    task: tokio::task::JoinHandle<Result<(), freja_proxy::ProxyError>>,
) {
    shutdown.shutdown();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

async fn socks_connect(client: &mut TcpStream, upstream: std::net::SocketAddr) {
    let mut request = vec![5, 1, 0, 1];
    let IpAddr::V4(address) = upstream.ip() else {
        panic!("test upstream must use IPv4");
    };
    request.extend_from_slice(&address.octets());
    request.extend_from_slice(&upstream.port().to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0_u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..2], &[5, 0]);
}

#[tokio::test]
async fn unauthenticated_connect_relays_bytes() {
    let (upstream, echo_task) = echo_server().await;
    let (address, shutdown, task, _audit) = start_server(None).await;
    let mut client = TcpStream::connect(address).await.unwrap();

    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0_u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    socks_connect(&mut client, upstream).await;
    client.write_all(b"freja-socks").await.unwrap();
    let mut echoed = [0_u8; 11];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"freja-socks");

    drop(client);
    echo_task.await.unwrap();
    stop_server(shutdown, task).await;
}

#[tokio::test]
async fn username_password_authentication_rejects_then_accepts_without_auditing_identity() {
    let expected = Sha256::digest(b"alice:correct");
    let authentication = ProxyCredentialHash::new(expected.into());
    let (upstream, echo_task) = echo_server().await;
    let (address, shutdown, task, mut audit) = start_server(Some(authentication)).await;

    let mut rejected = TcpStream::connect(address).await.unwrap();
    rejected.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0_u8; 2];
    rejected.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);
    rejected
        .write_all(&[
            1, 5, b'a', b'l', b'i', b'c', b'e', 5, b'w', b'r', b'o', b'n', b'g',
        ])
        .await
        .unwrap();
    let mut response = [0_u8; 2];
    rejected.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [1, 1]);
    drop(rejected);

    let mut accepted = TcpStream::connect(address).await.unwrap();
    accepted.write_all(&[5, 1, 2]).await.unwrap();
    accepted.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);
    accepted
        .write_all(&[
            1, 5, b'a', b'l', b'i', b'c', b'e', 7, b'c', b'o', b'r', b'r', b'e', b'c', b't',
        ])
        .await
        .unwrap();
    accepted.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [1, 0]);
    socks_connect(&mut accepted, upstream).await;
    accepted.write_all(b"ok").await.unwrap();
    let mut echoed = [0_u8; 2];
    accepted.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ok");

    drop(accepted);
    echo_task.await.unwrap();
    stop_server(shutdown, task).await;
    let events: Vec<_> = std::iter::from_fn(|| audit.try_recv().ok()).collect();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.event, AuditEvent::ProxyAuthentication { .. }))
            .count(),
        2
    );
    let serialized = format!("{events:?}");
    assert!(!serialized.contains("alice"));
    assert!(!serialized.contains("correct"));
    assert!(!serialized.contains("wrong"));
}
