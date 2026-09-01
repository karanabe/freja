use std::{collections::BTreeSet, net::IpAddr};

use freja_domain::{
    HostName, HttpRequestFacts, HttpResponseFacts, PolicyStage, Port, Protocol,
    RequestedTargetFacts, ResolvedTargetFacts, RuleId, SanitizedHeaders, TargetHost,
    UpstreamEndpoint,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::PolicyError;

/// Inclusive, non-zero destination port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PortRangeRepr", into = "PortRangeRepr")]
pub struct PortRange {
    start: Port,
    end: Port,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct PortRangeRepr {
    start: u16,
    end: u16,
}

impl PortRange {
    /// Creates an inclusive range with `start <= end`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidPortRange`] when `start` exceeds `end`.
    pub fn new(start: Port, end: Port) -> Result<Self, PolicyError> {
        if start.get() > end.get() {
            return Err(PolicyError::InvalidPortRange {
                start: start.get(),
                end: end.get(),
            });
        }
        Ok(Self { start, end })
    }

    /// Reports whether a port is inside the range.
    pub fn contains(self, port: Port) -> bool {
        (self.start.get()..=self.end.get()).contains(&port.get())
    }
}

impl TryFrom<PortRangeRepr> for PortRange {
    type Error = PolicyError;

    fn try_from(value: PortRangeRepr) -> Result<Self, Self::Error> {
        let start = Port::new(value.start).map_err(|_| PolicyError::InvalidPortRange {
            start: value.start,
            end: value.end,
        })?;
        let end = Port::new(value.end).map_err(|_| PolicyError::InvalidPortRange {
            start: value.start,
            end: value.end,
        })?;
        Self::new(start, end)
    }
}

impl From<PortRange> for PortRangeRepr {
    fn from(value: PortRange) -> Self {
        Self {
            start: value.start.get(),
            end: value.end.get(),
        }
    }
}

/// Exact or label-boundary suffix hostname matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum HostPattern {
    /// Match one normalized DNS hostname exactly.
    Exact(HostName),
    /// Match the hostname itself or a subdomain at a DNS label boundary.
    Suffix(HostName),
}

impl HostPattern {
    /// Reports whether a target matches this exact or label-boundary suffix pattern.
    pub fn matches_target(&self, target: &TargetHost) -> bool {
        let TargetHost::Name(candidate) = target else {
            return false;
        };
        match self {
            Self::Exact(expected) => candidate == expected,
            Self::Suffix(suffix) => {
                candidate == suffix
                    || candidate
                        .as_str()
                        .strip_suffix(suffix.as_str())
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
        }
    }
}

/// Case-insensitive header-name matcher with an optional value substring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpHeaderMatcher {
    /// Header name compared case-insensitively against sanitized names.
    pub name: String,
    #[serde(default)]
    /// Optional byte substring required in at least one value; `None` matches presence.
    pub value_contains: Option<String>,
}

/// Boolean ACL expression. Every matching leaf contributes a trace reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum MatchExpression {
    /// Match when every nested expression matches; empty lists are rejected.
    All(Vec<Self>),
    /// Match when any nested expression matches; empty lists are rejected.
    Any(Vec<Self>),
    /// Match only when the nested expression is available and does not match.
    Not(Box<Self>),
    /// Match the client address observed by the listener.
    SourceIp(IpNet),
    /// Match one post-resolution destination address.
    DestinationIp(IpNet),
    /// Match the client-requested hostname before or after resolution.
    DestinationHost(HostPattern),
    /// Match the requested destination port.
    DestinationPort(PortRange),
    /// Match HTTP or opaque TCP policy semantics.
    Protocol(Protocol),
    /// Match an HTTP method case-insensitively; unavailable before request parsing.
    HttpMethod(BTreeSet<String>),
    /// Match a normalized HTTP path prefix; unavailable before request parsing.
    HttpPathPrefix(String),
    /// Match a sanitized HTTP request or response header.
    HttpHeader(HttpHeaderMatcher),
}

/// Rule result before protocol-specific action selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleAction {
    /// Permit the flow at the evaluated stage.
    Allow,
    /// Select a protocol-appropriate HTTP rejection or TCP close.
    Deny,
    /// Replace a requested-stage TCP upstream before any relay begins.
    Detour(UpstreamEndpoint),
}

/// One ordered ACL rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AclRule {
    /// Stable identity recorded in the resulting decision trace.
    pub id: RuleId,
    /// Boolean expression evaluated at each applicable lifecycle stage.
    pub matcher: MatchExpression,
    /// Action selected when the expression matches.
    pub action: RuleAction,
}

/// Facts accepted by the ACL without a broad structure full of absent fields.
#[derive(Debug, Clone, Copy)]
pub enum PolicyFacts<'a> {
    /// Client request before DNS resolution.
    Requested(&'a RequestedTargetFacts),
    /// One concrete DNS result; callers evaluate every result separately.
    Resolved(&'a ResolvedTargetFacts),
    /// Normalized request before upstream forwarding.
    HttpRequest(&'a HttpRequestFacts),
    /// Upstream response before downstream commitment.
    HttpResponse(&'a HttpResponseFacts),
}

impl<'a> PolicyFacts<'a> {
    pub(super) fn stage(self) -> PolicyStage {
        match self {
            Self::Requested(_) => PolicyStage::RequestedDestination,
            Self::Resolved(_) => PolicyStage::ResolvedDestination,
            Self::HttpRequest(_) => PolicyStage::HttpRequest,
            Self::HttpResponse(_) => PolicyStage::HttpResponse,
        }
    }

    pub(super) fn requested(self) -> &'a RequestedTargetFacts {
        match self {
            Self::Requested(facts) => facts,
            Self::Resolved(facts) => facts.requested(),
            Self::HttpRequest(facts) => facts.target().requested(),
            Self::HttpResponse(facts) => facts.target().requested(),
        }
    }

    pub(super) fn resolved_ip(self) -> Option<IpAddr> {
        match self {
            Self::Requested(_) => None,
            Self::Resolved(facts) => Some(facts.resolved_ip()),
            Self::HttpRequest(facts) => Some(facts.target().resolved_ip()),
            Self::HttpResponse(facts) => Some(facts.target().resolved_ip()),
        }
    }

    pub(super) fn http(self) -> Option<&'a HttpRequestFacts> {
        match self {
            Self::HttpRequest(facts) => Some(facts),
            Self::Requested(_) | Self::Resolved(_) | Self::HttpResponse(_) => None,
        }
    }

    pub(super) fn http_headers(self) -> Option<&'a SanitizedHeaders> {
        match self {
            Self::HttpRequest(facts) => Some(facts.headers()),
            Self::HttpResponse(facts) => Some(facts.headers()),
            Self::Requested(_) | Self::Resolved(_) => None,
        }
    }
}
