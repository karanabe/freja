use std::{
    fmt,
    sync::{Arc, Mutex},
};

use freja_domain::TargetHost;
use freja_policy::HostPattern;
use rcgen::{CertificateParams, Issuer, KeyPair};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, pem::PemObject as _},
};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector, client::TlsStream as ClientTlsStream};

use crate::TlsInterceptionConfig;

use super::{
    ALPN_HTTP_1_1, ALPN_HTTP_2, TlsError,
    cache::{LeafCache, LeafCacheKey},
    error::TlsInput,
    material::{read_text, validate_private_key_permissions},
};

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
    /// Loads the configured CA and creates an interception engine.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] for unreadable or insecure CA inputs and invalid
    /// certificate/key material.
    pub fn from_config(config: &TlsInterceptionConfig) -> Result<Self, TlsError> {
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
        config: &TlsInterceptionConfig,
        roots: RootCertStore,
    ) -> Result<Self, TlsError> {
        validate_private_key_permissions(&config.ca_private_key)?;
        let ca_pem = read_text(&config.ca_certificate, TlsInput::Certificate)?;
        let key_pem = read_text(&config.ca_private_key, TlsInput::PrivateKey)?;
        Self::from_material(
            &ca_pem,
            &key_pem,
            config.intercept_hosts.clone(),
            config.leaf_cache_entries,
            roots,
        )
    }

    pub(super) fn from_material(
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
