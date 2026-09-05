#![allow(clippy::wildcard_imports)]

//! Externally observable HTTP forward-proxy and CONNECT integration tests.

use std::{
    convert::Infallible,
    fs,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use freja_audit::{AuditEnvelope, AuditEvent, AuditFailurePolicy, AuditPublisher};
use freja_domain::{
    Confidence, DetectorId, Direction, EnforcementMode, HookMode, HostName, HttpForwardListener,
    InspectionMode, ListenEndpoint, PolicyGeneration, Port, ProxyAuthentication,
    ProxyCredentialHash, ReplayFacts, RuleId, SessionId, Severity,
};
use freja_policy::{
    AclPolicy, AclRule, DestinationAccess, DestinationGuard, DestinationGuardSettings, HostPattern,
    HttpHeaderMatcher, InspectionPattern, InspectionProgram, MatchExpression, RuleAction,
    hook::{
        BodyMutationPlan, DecodedBody, HeadMutationPlan, HeaderMutation, HookFailurePolicy,
        HookFuture, HookRegistry, HookRunner, HttpRequestBodyHook, HttpRequestHead,
        HttpRequestHeadHook, HttpRequestMutationPlan, HttpRequestSnapshot, InteractiveBroker,
        InteractiveDecision, InterceptContext, InterceptTimeoutPolicy, RepeatOutcome,
        RepeatRequest, WireBody,
    },
};
use freja_proxy::{
    DataPlaneEvent, DataPlaneEventSink, DataPlaneServices, HttpForwardServer, HttpRepeatExecutor,
    ProxyLimits, TlsInterceptionConfig, TlsInterceptor, UiCaptureSettings, shutdown_channel,
};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{PrivatePkcs8KeyDer, ServerName},
};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[path = "http_forward/connect.rs"]
mod connect;
#[path = "http_forward/diagnostics.rs"]
mod diagnostics;
#[path = "http_forward/forwarding.rs"]
mod forwarding;
#[path = "http_forward/hooks.rs"]
mod hooks;
#[path = "http_forward/inspection.rs"]
mod inspection;
#[path = "http_forward/limits.rs"]
mod limits;
#[path = "http_forward/policy.rs"]
mod policy;
#[path = "http_forward/repeat.rs"]
mod repeat;
#[path = "http_forward/runtime.rs"]
mod runtime;
#[path = "http_forward/support.rs"]
mod support;
#[path = "http_forward/tui_capture.rs"]
mod tui_capture;

use support::*;
