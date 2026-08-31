use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use freja_config::TlsConfig;
use freja_domain::TargetHost;
use freja_policy::HostPattern;
use rcgen::{CertificateParams, Issuer, KeyPair};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{
        CertificateDer, PrivatePkcs8KeyDer, ServerName,
        pem::{Error as PemError, PemObject as _},
    },
};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector, client::TlsStream as ClientTlsStream};

const ALPN_HTTP_2: &[u8] = b"h2";
const ALPN_HTTP_1_1: &[u8] = b"http/1.1";

/// An opt-in TLS interception engine with an in-memory, bounded leaf cache.
///
/// The CA signing key never leaves this object and is not included in its
/// debug representation. Interception remains restricted by an explicit host
/// allowlist even when the engine is installed.
pub struct TlsInterceptor {
    issuer: Issuer<'static, KeyPair>,
    ca_chain: Vec<CertificateDer<'static>>,
    intercept_hosts: Vec<HostPattern>,
    cache: Mutex<LeafCache>,
    upstream: Arc<ClientConfig>,
}

impl fmt::Debug for TlsInterceptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsInterceptor")
            .field("intercept_hosts", &self.intercept_hosts)
            .field("cache", &"bounded leaf-certificate cache")
            .field("upstream", &"rustls client configuration")
            .finish_non_exhaustive()
    }
}

impl TlsInterceptor {
    /// Loads the configured CA and creates an interceptor, or returns `None`
    /// when TLS handling is tunnel-only.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] for unreadable or insecure CA inputs and invalid
    /// certificate/key material.
    pub fn from_config(config: &TlsConfig) -> Result<Option<Self>, TlsError> {
        let roots = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
            .collect::<RootCertStore>();
        Self::from_config_and_roots(config, roots)
    }

    /// Loads an interceptor with an explicitly supplied upstream trust store.
    /// This supports private PKI deployments without disabling certificate
    /// verification.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] under the same conditions as [`Self::from_config`].
    pub fn from_config_and_roots(
        config: &TlsConfig,
        roots: RootCertStore,
    ) -> Result<Option<Self>, TlsError> {
        let TlsConfig::Intercept {
            ca_certificate,
            ca_private_key,
            intercept_hosts,
            leaf_cache_entries,
        } = config
        else {
            return Ok(None);
        };
        validate_private_key_permissions(ca_private_key)?;
        let ca_pem = read_text(ca_certificate, TlsInput::Certificate)?;
        let key_pem = read_text(ca_private_key, TlsInput::PrivateKey)?;
        Self::from_material(
            &ca_pem,
            &key_pem,
            intercept_hosts.clone(),
            *leaf_cache_entries,
            roots,
        )
        .map(Some)
    }

    fn from_material(
        ca_pem: &str,
        key_pem: &str,
        intercept_hosts: Vec<HostPattern>,
        cache_capacity: usize,
        roots: RootCertStore,
    ) -> Result<Self, TlsError> {
        let signing_key = KeyPair::from_pem(key_pem).map_err(TlsError::CaPrivateKey)?;
        let issuer =
            Issuer::from_ca_cert_pem(ca_pem, signing_key).map_err(TlsError::CaCertificate)?;
        let ca_chain = CertificateDer::pem_slice_iter(ca_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(TlsError::CaCertificatePem)?;
        if ca_chain.is_empty() {
            return Err(TlsError::MissingCaCertificate);
        }
        let mut upstream = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        upstream.alpn_protocols = vec![ALPN_HTTP_2.to_vec(), ALPN_HTTP_1_1.to_vec()];
        Ok(Self {
            issuer,
            ca_chain,
            intercept_hosts,
            cache: Mutex::new(LeafCache::new(cache_capacity)),
            upstream: Arc::new(upstream),
        })
    }

    /// Reports whether the requested hostname is explicitly authorized for
    /// interception. IP literals are never matched by hostname patterns.
    pub fn should_intercept(&self, host: &TargetHost) -> bool {
        self.intercept_hosts
            .iter()
            .any(|pattern| pattern.matches_target(host))
    }

    /// Establishes and authenticates TLS to the selected upstream after the
    /// outer CONNECT response is committed but before intercepted payload
    /// forwarding begins.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] for an invalid server name or failed TLS handshake.
    pub async fn connect_upstream(
        &self,
        stream: TcpStream,
        host: &TargetHost,
        downstream_alpn: Option<&[u8]>,
    ) -> Result<ClientTlsStream<TcpStream>, TlsError> {
        let host_text = host.as_host_text();
        let server_name = ServerName::try_from(host_text.clone())
            .map_err(|_| TlsError::InvalidServerName { host: host_text })?;
        let mut upstream = (*self.upstream).clone();
        upstream.alpn_protocols = match downstream_alpn {
            Some(ALPN_HTTP_2) => vec![ALPN_HTTP_2.to_vec()],
            Some(ALPN_HTTP_1_1) | None => vec![ALPN_HTTP_1_1.to_vec()],
            Some(other) => {
                return Err(TlsError::UnsupportedApplicationProtocol {
                    protocol: String::from_utf8_lossy(other).into_owned(),
                });
            }
        };
        TlsConnector::from(Arc::new(upstream))
            .connect(server_name, stream)
            .await
            .map_err(|source| TlsError::UpstreamHandshake {
                host: host.to_string(),
                source,
            })
    }

    /// Produces a downstream acceptor for one hostname and negotiated upstream
    /// application protocol. The returned boolean reports a cache hit.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] if certificate generation or rustls validation
    /// fails, or if the bounded cache lock is unavailable.
    pub fn downstream_acceptor(
        &self,
        host: &TargetHost,
        negotiated_alpn: Option<&[u8]>,
    ) -> Result<(TlsAcceptor, bool), TlsError> {
        let key = LeafCacheKey {
            host: host.as_host_text(),
            alpn: negotiated_alpn.map(<[u8]>::to_vec),
        };
        {
            let mut cache = self.cache.lock().map_err(|_| TlsError::CachePoisoned)?;
            if let Some(config) = cache.get(&key) {
                return Ok((TlsAcceptor::from(config), true));
            }
        }

        let config = Arc::new(self.generate_server_config(&key)?);
        let mut cache = self.cache.lock().map_err(|_| TlsError::CachePoisoned)?;
        if let Some(existing) = cache.get(&key) {
            return Ok((TlsAcceptor::from(existing), true));
        }
        cache.insert(key, Arc::clone(&config));
        Ok((TlsAcceptor::from(config), false))
    }

    fn generate_server_config(&self, key: &LeafCacheKey) -> Result<ServerConfig, TlsError> {
        let leaf_key = KeyPair::generate().map_err(TlsError::LeafCertificate)?;
        let parameters =
            CertificateParams::new(vec![key.host.clone()]).map_err(TlsError::LeafCertificate)?;
        let certificate = parameters
            .signed_by(&leaf_key, &self.issuer)
            .map_err(TlsError::LeafCertificate)?;
        let mut chain = Vec::with_capacity(self.ca_chain.len().saturating_add(1));
        chain.push(certificate.der().clone());
        chain.extend(self.ca_chain.iter().cloned());
        let private_key = PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into();
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, private_key)
            .map_err(TlsError::ServerConfiguration)?;
        config.alpn_protocols = key.alpn.as_ref().map_or_else(
            || vec![ALPN_HTTP_2.to_vec(), ALPN_HTTP_1_1.to_vec()],
            |alpn| vec![alpn.clone()],
        );
        Ok(config)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LeafCacheKey {
    host: String,
    alpn: Option<Vec<u8>>,
}

#[derive(Debug)]
struct LeafCache {
    capacity: usize,
    entries: HashMap<LeafCacheKey, Arc<ServerConfig>>,
    recency: VecDeque<LeafCacheKey>,
}

impl LeafCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::new(),
            recency: VecDeque::new(),
        }
    }

    fn get(&mut self, key: &LeafCacheKey) -> Option<Arc<ServerConfig>> {
        let config = self.entries.get(key).cloned()?;
        self.recency.retain(|candidate| candidate != key);
        self.recency.push_back(key.clone());
        Some(config)
    }

    fn insert(&mut self, key: LeafCacheKey, value: Arc<ServerConfig>) {
        if self.capacity == 0 {
            return;
        }
        if self.entries.len() == self.capacity
            && let Some(oldest) = self.recency.pop_front()
        {
            self.entries.remove(&oldest);
        }
        self.recency.push_back(key.clone());
        self.entries.insert(key, value);
    }
}

#[derive(Debug, Clone, Copy)]
enum TlsInput {
    Certificate,
    PrivateKey,
}

impl fmt::Display for TlsInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certificate => formatter.write_str("CA certificate"),
            Self::PrivateKey => formatter.write_str("CA private key"),
        }
    }
}

/// TLS interception setup or handshake failure.
#[derive(Debug)]
pub enum TlsError {
    ReadInput {
        input: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    InsecurePrivateKeyPermissions {
        path: PathBuf,
        mode: u32,
    },
    CaPrivateKey(rcgen::Error),
    CaCertificate(rcgen::Error),
    CaCertificatePem(PemError),
    MissingCaCertificate,
    InvalidServerName {
        host: String,
    },
    UnsupportedApplicationProtocol {
        protocol: String,
    },
    ApplicationProtocolMismatch {
        downstream: Option<String>,
        upstream: Option<String>,
    },
    UpstreamHandshake {
        host: String,
        source: std::io::Error,
    },
    DownstreamHandshake(std::io::Error),
    DownstreamHandshakeTimedOut,
    LeafCertificate(rcgen::Error),
    ServerConfiguration(rustls::Error),
    CachePoisoned,
}

impl fmt::Display for TlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadInput { input, path, .. } => {
                write!(formatter, "failed to read {input} {}", path.display())
            }
            Self::InsecurePrivateKeyPermissions { path, mode } => write!(
                formatter,
                "CA private key {} has insecure permissions {mode:o}; group and other access must be disabled",
                path.display()
            ),
            Self::CaPrivateKey(_) => formatter.write_str("failed to parse the CA private key"),
            Self::CaCertificate(_) | Self::CaCertificatePem(_) => {
                formatter.write_str("failed to parse the CA certificate")
            }
            Self::MissingCaCertificate => {
                formatter.write_str("CA certificate input contains no certificate")
            }
            Self::InvalidServerName { host } => {
                write!(formatter, "invalid upstream TLS server name {host}")
            }
            Self::UnsupportedApplicationProtocol { protocol } => {
                write!(formatter, "unsupported intercepted TLS ALPN {protocol:?}")
            }
            Self::ApplicationProtocolMismatch {
                downstream,
                upstream,
            } => write!(
                formatter,
                "intercepted TLS ALPN mismatch: downstream {downstream:?}, upstream {upstream:?}"
            ),
            Self::UpstreamHandshake { host, .. } => {
                write!(formatter, "upstream TLS handshake failed for {host}")
            }
            Self::DownstreamHandshake(_) => formatter.write_str("downstream TLS handshake failed"),
            Self::DownstreamHandshakeTimedOut => {
                formatter.write_str("downstream TLS handshake timed out")
            }
            Self::LeafCertificate(_) => {
                formatter.write_str("failed to generate a TLS leaf certificate")
            }
            Self::ServerConfiguration(_) => {
                formatter.write_str("generated TLS server configuration is invalid")
            }
            Self::CachePoisoned => formatter.write_str("TLS leaf cache is unavailable"),
        }
    }
}

impl Error for TlsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ReadInput { source, .. }
            | Self::UpstreamHandshake { source, .. }
            | Self::DownstreamHandshake(source) => Some(source),
            Self::CaCertificatePem(source) => Some(source),
            Self::CaPrivateKey(source)
            | Self::CaCertificate(source)
            | Self::LeafCertificate(source) => Some(source),
            Self::ServerConfiguration(source) => Some(source),
            Self::InsecurePrivateKeyPermissions { .. }
            | Self::MissingCaCertificate
            | Self::InvalidServerName { .. }
            | Self::UnsupportedApplicationProtocol { .. }
            | Self::ApplicationProtocolMismatch { .. }
            | Self::DownstreamHandshakeTimedOut
            | Self::CachePoisoned => None,
        }
    }
}

fn read_text(path: &Path, input: TlsInput) -> Result<String, TlsError> {
    fs::read_to_string(path).map_err(|source| TlsError::ReadInput {
        input: match input {
            TlsInput::Certificate => "CA certificate",
            TlsInput::PrivateKey => "CA private key",
        },
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
fn validate_private_key_permissions(path: &Path) -> Result<(), TlsError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).map_err(|source| TlsError::ReadInput {
        input: "CA private key metadata",
        path: path.to_path_buf(),
        source,
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(TlsError::InsecurePrivateKeyPermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_key_permissions(_path: &Path) -> Result<(), TlsError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use freja_config::TlsConfig;
    use freja_domain::{HostName, SessionId, TargetHost};
    use freja_policy::HostPattern;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    use rustls::RootCertStore;

    use super::{ALPN_HTTP_1_1, TlsError, TlsInterceptor};

    fn test_interceptor(capacity: usize) -> TlsInterceptor {
        let key = KeyPair::generate().expect("generate CA key");
        let mut parameters = CertificateParams::default();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let certificate = parameters.self_signed(&key).expect("generate CA cert");
        TlsInterceptor::from_material(
            &certificate.pem(),
            &key.serialize_pem(),
            vec![HostPattern::Suffix(
                HostName::new("example.test").expect("valid host"),
            )],
            capacity,
            RootCertStore::empty(),
        )
        .expect("build interceptor")
    }

    #[test]
    fn allowlist_is_label_bounded_and_excludes_ip_literals() {
        let interceptor = test_interceptor(2);
        assert!(
            interceptor
                .should_intercept(&TargetHost::parse("api.example.test").expect("valid target"))
        );
        assert!(
            !interceptor
                .should_intercept(&TargetHost::parse("badexample.test").expect("valid target"))
        );
        assert!(
            !interceptor.should_intercept(&TargetHost::parse("127.0.0.1").expect("valid target"))
        );
    }

    #[test]
    fn leaf_cache_is_bounded_and_reports_hits() {
        let interceptor = test_interceptor(1);
        let first = TargetHost::parse("one.example.test").expect("valid target");
        let second = TargetHost::parse("two.example.test").expect("valid target");
        assert!(
            !interceptor
                .downstream_acceptor(&first, Some(ALPN_HTTP_1_1))
                .expect("generate first")
                .1
        );
        assert!(
            interceptor
                .downstream_acceptor(&first, Some(ALPN_HTTP_1_1))
                .expect("reuse first")
                .1
        );
        assert!(
            !interceptor
                .downstream_acceptor(&second, Some(ALPN_HTTP_1_1))
                .expect("generate second")
                .1
        );
        assert!(
            !interceptor
                .downstream_acceptor(&first, Some(ALPN_HTTP_1_1))
                .expect("first was evicted")
                .1
        );
    }

    #[cfg(unix)]
    #[test]
    fn group_readable_ca_private_key_is_rejected_before_parsing() {
        use std::{fs, os::unix::fs::PermissionsExt};

        let directory =
            std::env::temp_dir().join(format!("freja-insecure-ca-test-{}", SessionId::new()));
        fs::create_dir(&directory).expect("create test directory");
        let private_key = directory.join("ca-key.pem");
        fs::write(&private_key, "not-secret-test-material").expect("write test key");
        fs::set_permissions(&private_key, fs::Permissions::from_mode(0o640))
            .expect("set insecure permissions");
        let config = TlsConfig::Intercept {
            ca_certificate: directory.join("missing-ca.pem"),
            ca_private_key: private_key,
            intercept_hosts: vec![HostPattern::Exact(
                HostName::new("example.test").expect("valid host"),
            )],
            leaf_cache_entries: 1,
        };

        let error = TlsInterceptor::from_config(&config).expect_err("permissions must fail");
        assert!(matches!(
            error,
            TlsError::InsecurePrivateKeyPermissions { mode: 0o640, .. }
        ));
        fs::remove_dir_all(directory).expect("remove test directory");
    }
}
