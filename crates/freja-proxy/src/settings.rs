use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};

use freja_policy::HostPattern;

/// Invalid runtime input supplied directly to the data-plane API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxySettingsError {
    ZeroLimit { name: &'static str },
    EmptyInterceptionAllowlist,
}

impl fmt::Display for ProxySettingsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroLimit { name } => write!(formatter, "proxy limit {name} must be non-zero"),
            Self::EmptyInterceptionAllowlist => {
                formatter.write_str("TLS interception requires a non-empty host allowlist")
            }
        }
    }
}

impl Error for ProxySettingsError {}

/// Validated resource and timeout limits used by network forwarding tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyLimits {
    pub(crate) connections: usize,
    pub(crate) header_bytes: usize,
    pub(crate) body_prefix_bytes: usize,
    pub(crate) connect_timeout: Duration,
    pub(crate) read_timeout: Duration,
    pub(crate) idle_timeout: Duration,
}

impl ProxyLimits {
    /// Creates data-plane limits without UI, hook, or audit settings.
    ///
    /// # Errors
    ///
    /// Returns [`ProxySettingsError::ZeroLimit`] when any bound or timeout is
    /// zero.
    pub fn new(
        connections: usize,
        header_bytes: usize,
        body_prefix_bytes: usize,
        connect_timeout: Duration,
        read_timeout: Duration,
        idle_timeout: Duration,
    ) -> Result<Self, ProxySettingsError> {
        for (name, value) in [
            ("connections", connections),
            ("header_bytes", header_bytes),
            ("body_prefix_bytes", body_prefix_bytes),
        ] {
            if value == 0 {
                return Err(ProxySettingsError::ZeroLimit { name });
            }
        }
        for (name, value) in [
            ("connect_timeout", connect_timeout),
            ("read_timeout", read_timeout),
            ("idle_timeout", idle_timeout),
        ] {
            if value.is_zero() {
                return Err(ProxySettingsError::ZeroLimit { name });
            }
        }
        Ok(Self {
            connections,
            header_bytes,
            body_prefix_bytes,
            connect_timeout,
            read_timeout,
            idle_timeout,
        })
    }

    pub const fn connections(self) -> usize {
        self.connections
    }

    pub const fn header_bytes(self) -> usize {
        self.header_bytes
    }

    pub const fn body_prefix_bytes(self) -> usize {
        self.body_prefix_bytes
    }

    pub const fn connect_timeout(self) -> Duration {
        self.connect_timeout
    }

    pub const fn read_timeout(self) -> Duration {
        self.read_timeout
    }

    pub const fn idle_timeout(self) -> Duration {
        self.idle_timeout
    }

    /// Replaces the connection bound while preserving validation.
    ///
    /// # Errors
    ///
    /// Returns an error when `connections` is zero.
    pub fn with_connections(self, connections: usize) -> Result<Self, ProxySettingsError> {
        Self::new(
            connections,
            self.header_bytes,
            self.body_prefix_bytes,
            self.connect_timeout,
            self.read_timeout,
            self.idle_timeout,
        )
    }

    /// Replaces the HTTP header bound while preserving validation.
    ///
    /// # Errors
    ///
    /// Returns an error when `header_bytes` is zero.
    pub fn with_header_bytes(self, header_bytes: usize) -> Result<Self, ProxySettingsError> {
        Self::new(
            self.connections,
            header_bytes,
            self.body_prefix_bytes,
            self.connect_timeout,
            self.read_timeout,
            self.idle_timeout,
        )
    }

    /// Replaces the body inspection bound while preserving validation.
    ///
    /// # Errors
    ///
    /// Returns an error when `body_prefix_bytes` is zero.
    pub fn with_body_prefix_bytes(
        self,
        body_prefix_bytes: usize,
    ) -> Result<Self, ProxySettingsError> {
        Self::new(
            self.connections,
            self.header_bytes,
            body_prefix_bytes,
            self.connect_timeout,
            self.read_timeout,
            self.idle_timeout,
        )
    }

    /// Replaces the connect timeout while preserving validation.
    ///
    /// # Errors
    ///
    /// Returns an error when `connect_timeout` is zero.
    pub fn with_connect_timeout(
        self,
        connect_timeout: Duration,
    ) -> Result<Self, ProxySettingsError> {
        Self::new(
            self.connections,
            self.header_bytes,
            self.body_prefix_bytes,
            connect_timeout,
            self.read_timeout,
            self.idle_timeout,
        )
    }

    /// Replaces the read timeout while preserving validation.
    ///
    /// # Errors
    ///
    /// Returns an error when `read_timeout` is zero.
    pub fn with_read_timeout(self, read_timeout: Duration) -> Result<Self, ProxySettingsError> {
        Self::new(
            self.connections,
            self.header_bytes,
            self.body_prefix_bytes,
            self.connect_timeout,
            read_timeout,
            self.idle_timeout,
        )
    }

    /// Replaces the idle timeout while preserving validation.
    ///
    /// # Errors
    ///
    /// Returns an error when `idle_timeout` is zero.
    pub fn with_idle_timeout(self, idle_timeout: Duration) -> Result<Self, ProxySettingsError> {
        Self::new(
            self.connections,
            self.header_bytes,
            self.body_prefix_bytes,
            self.connect_timeout,
            self.read_timeout,
            idle_timeout,
        )
    }
}

/// Explicit metadata-only or bounded-prefix capture setting for the data plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CaptureSettings {
    maximum_prefix_bytes: Option<usize>,
}

impl CaptureSettings {
    /// Disables raw payload capture while retaining metadata and hashed evidence.
    pub const fn metadata_only() -> Self {
        Self {
            maximum_prefix_bytes: None,
        }
    }

    /// Enables bounded raw-prefix capture.
    ///
    /// # Errors
    ///
    /// Returns [`ProxySettingsError::ZeroLimit`] when `maximum_prefix_bytes` is
    /// zero.
    pub fn prefix(maximum_prefix_bytes: usize) -> Result<Self, ProxySettingsError> {
        if maximum_prefix_bytes == 0 {
            return Err(ProxySettingsError::ZeroLimit {
                name: "capture_prefix_bytes",
            });
        }
        Ok(Self {
            maximum_prefix_bytes: Some(maximum_prefix_bytes),
        })
    }

    pub const fn maximum_prefix_bytes(self) -> Option<usize> {
        self.maximum_prefix_bytes
    }
}

/// Validated inputs required to construct an opt-in TLS interception engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInterceptionConfig {
    pub(crate) ca_certificate: PathBuf,
    pub(crate) ca_private_key: PathBuf,
    pub(crate) intercept_hosts: Vec<HostPattern>,
    pub(crate) leaf_cache_entries: usize,
}

impl TlsInterceptionConfig {
    /// Creates TLS interception inputs independently of the file configuration
    /// representation.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty host allowlist or a zero cache bound.
    pub fn new(
        ca_certificate: PathBuf,
        ca_private_key: PathBuf,
        intercept_hosts: Vec<HostPattern>,
        leaf_cache_entries: usize,
    ) -> Result<Self, ProxySettingsError> {
        if intercept_hosts.is_empty() {
            return Err(ProxySettingsError::EmptyInterceptionAllowlist);
        }
        if leaf_cache_entries == 0 {
            return Err(ProxySettingsError::ZeroLimit {
                name: "tls_leaf_cache_entries",
            });
        }
        Ok(Self {
            ca_certificate,
            ca_private_key,
            intercept_hosts,
            leaf_cache_entries,
        })
    }

    pub fn ca_certificate(&self) -> &Path {
        &self.ca_certificate
    }

    pub fn ca_private_key(&self) -> &Path {
        &self.ca_private_key
    }

    pub fn intercept_hosts(&self) -> &[HostPattern] {
        &self.intercept_hosts
    }

    pub const fn leaf_cache_entries(&self) -> usize {
        self.leaf_cache_entries
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use super::{CaptureSettings, ProxyLimits, ProxySettingsError, TlsInterceptionConfig};

    #[test]
    fn direct_runtime_settings_reject_zero_bounds() {
        let error = ProxyLimits::new(
            0,
            1,
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(
            error,
            ProxySettingsError::ZeroLimit {
                name: "connections"
            }
        );
        assert!(CaptureSettings::prefix(0).is_err());
        assert!(
            TlsInterceptionConfig::new(
                PathBuf::from("ca.pem"),
                PathBuf::from("ca-key.pem"),
                Vec::new(),
                1,
            )
            .is_err()
        );
    }
}
