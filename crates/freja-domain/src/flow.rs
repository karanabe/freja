use std::{collections::BTreeMap, net::IpAddr};

use serde::{Deserialize, Deserializer, Serialize};

use crate::{Finding, Port, TargetHost};

/// Transport semantics relevant to destination policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Tcp,
    Http,
}

/// Connection facts available before DNS resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestedTargetFacts {
    source_ip: IpAddr,
    requested_host: TargetHost,
    destination_port: Port,
    protocol: Protocol,
}

impl RequestedTargetFacts {
    /// Creates pre-resolution target facts.
    pub const fn new(
        source_ip: IpAddr,
        requested_host: TargetHost,
        destination_port: Port,
        protocol: Protocol,
    ) -> Self {
        Self {
            source_ip,
            requested_host,
            destination_port,
            protocol,
        }
    }

    pub const fn source_ip(&self) -> IpAddr {
        self.source_ip
    }

    pub const fn requested_host(&self) -> &TargetHost {
        &self.requested_host
    }

    pub const fn destination_port(&self) -> Port {
        self.destination_port
    }

    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }
}

/// Destination facts for exactly one resolved address.
///
/// Callers must evaluate one value for every DNS answer before selecting an
/// address. Keeping one address per value prevents accidentally approving a
/// hostname because only its first answer was checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedTargetFacts {
    requested: RequestedTargetFacts,
    resolved_ip: IpAddr,
}

impl ResolvedTargetFacts {
    /// Adds one resolved IP address to pre-resolution facts.
    pub const fn new(requested: RequestedTargetFacts, resolved_ip: IpAddr) -> Self {
        Self {
            requested,
            resolved_ip,
        }
    }

    pub const fn requested(&self) -> &RequestedTargetFacts {
        &self.requested
    }

    pub const fn resolved_ip(&self) -> IpAddr {
        self.resolved_ip
    }
}

/// Lower-case HTTP header names and bounded wire values after framing validation.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(transparent)]
pub struct SanitizedHeaders(BTreeMap<String, Vec<Vec<u8>>>);

impl SanitizedHeaders {
    /// Creates a sanitized header map. Names are normalized to lower case.
    pub fn new(headers: impl IntoIterator<Item = (String, Vec<Vec<u8>>)>) -> Self {
        let mut normalized = BTreeMap::<String, Vec<Vec<u8>>>::new();
        for (name, mut values) in headers {
            normalized
                .entry(name.to_ascii_lowercase())
                .or_default()
                .append(&mut values);
        }
        Self(normalized)
    }

    /// Returns all values associated with a case-insensitive header name.
    pub fn values(&self, name: &str) -> Option<&[Vec<u8>]> {
        self.0.get(&name.to_ascii_lowercase()).map(Vec::as_slice)
    }

    /// Iterates over normalized header names and their values.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[Vec<u8>])> {
        self.0
            .iter()
            .map(|(name, values)| (name.as_str(), values.as_slice()))
    }
}

impl<'de> Deserialize<'de> for SanitizedHeaders {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        BTreeMap::<String, Vec<Vec<u8>>>::deserialize(deserializer).map(Self::new)
    }
}

/// HTTP request facts evaluated after target normalization and DNS policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequestFacts {
    target: ResolvedTargetFacts,
    method: String,
    path: String,
    headers: SanitizedHeaders,
}

impl HttpRequestFacts {
    /// Creates facts for an HTTP request with a normalized method and path.
    pub fn new(
        target: ResolvedTargetFacts,
        method: impl Into<String>,
        path: impl Into<String>,
        headers: SanitizedHeaders,
    ) -> Self {
        Self {
            target,
            method: method.into().to_ascii_uppercase(),
            path: path.into(),
            headers,
        }
    }

    pub const fn target(&self) -> &ResolvedTargetFacts {
        &self.target
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub const fn headers(&self) -> &SanitizedHeaders {
        &self.headers
    }
}

/// HTTP response facts evaluated before downstream response commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponseFacts {
    target: ResolvedTargetFacts,
    status: u16,
    headers: SanitizedHeaders,
}

/// Owned facts persisted for deterministic offline policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "stage", content = "facts", rename_all = "kebab-case")]
pub enum ReplayFacts {
    Requested(RequestedTargetFacts),
    Resolved(ResolvedTargetFacts),
    HttpRequest(HttpRequestFacts),
    HttpResponse(HttpResponseFacts),
    Finding {
        finding: Finding,
        protocol: Protocol,
    },
}

impl HttpResponseFacts {
    /// Creates response facts for one already-authorized upstream address.
    pub const fn new(target: ResolvedTargetFacts, status: u16, headers: SanitizedHeaders) -> Self {
        Self {
            target,
            status,
            headers,
        }
    }

    pub const fn target(&self) -> &ResolvedTargetFacts {
        &self.target
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub const fn headers(&self) -> &SanitizedHeaders {
        &self.headers
    }
}

#[cfg(test)]
mod tests {
    use super::SanitizedHeaders;

    #[test]
    fn differently_cased_header_names_are_merged() {
        let headers = SanitizedHeaders::new([
            ("X-Policy".to_owned(), vec![b"first".to_vec()]),
            ("x-policy".to_owned(), vec![b"second".to_vec()]),
        ]);

        assert_eq!(
            headers.values("X-POLICY").unwrap(),
            &[b"first".to_vec(), b"second".to_vec()]
        );
    }

    #[test]
    fn deserialization_restores_header_name_invariants() {
        let headers: SanitizedHeaders = serde_json::from_str(
            r#"{"X-Policy":[[102,105,114,115,116]],"x-policy":[[115,101,99,111,110,100]]}"#,
        )
        .unwrap();

        assert_eq!(headers.iter().count(), 1);
        assert_eq!(headers.values("x-policy").unwrap().len(), 2);
    }
}
