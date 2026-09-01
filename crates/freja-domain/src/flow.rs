use std::{collections::BTreeMap, net::IpAddr};

use serde::{Deserialize, Deserializer, Serialize};

use crate::{Finding, Port, TargetHost};

/// Transport semantics relevant to destination policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    /// Opaque byte-stream policy semantics.
    Tcp,
    /// HTTP request/response policy semantics.
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

    /// Returns the client IP observed by the accepting listener.
    pub const fn source_ip(&self) -> IpAddr {
        self.source_ip
    }

    /// Returns the destination named by the client before resolution.
    pub const fn requested_host(&self) -> &TargetHost {
        &self.requested_host
    }

    /// Returns the requested non-zero destination port.
    pub const fn destination_port(&self) -> Port {
        self.destination_port
    }

    /// Returns the protocol semantics used for policy action selection.
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

    /// Returns the pre-resolution facts from which this value was derived.
    pub const fn requested(&self) -> &RequestedTargetFacts {
        &self.requested
    }

    /// Returns the single address that must be evaluated before use.
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

    /// Returns the authorized destination associated with the request.
    pub const fn target(&self) -> &ResolvedTargetFacts {
        &self.target
    }

    /// Returns the upper-case HTTP method.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the normalized request path used for policy matching.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns framing-validated request headers.
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
    /// Facts captured before destination resolution.
    Requested(RequestedTargetFacts),
    /// Facts captured for one resolved destination address.
    Resolved(ResolvedTargetFacts),
    /// Normalized request facts captured before forwarding.
    HttpRequest(HttpRequestFacts),
    /// Response facts captured before downstream commitment.
    HttpResponse(HttpResponseFacts),
    /// A streaming detector finding and the protocol to which it applies.
    Finding {
        /// Immutable detector output; replay policy decides the action.
        finding: Finding,
        /// Protocol semantics of the original flow.
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

    /// Returns the authorized upstream associated with the response.
    pub const fn target(&self) -> &ResolvedTargetFacts {
        &self.target
    }

    /// Returns the upstream HTTP status code.
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns framing-validated response headers.
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
