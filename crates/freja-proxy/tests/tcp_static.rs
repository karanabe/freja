#![allow(clippy::wildcard_imports)]

//! Externally observable static TCP relay integration tests.

use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use freja_audit::{AuditEnvelope, AuditEvent, AuditFailurePolicy, AuditPublisher};
use freja_domain::{
    Confidence, DetectorId, Direction, EnforcementAction, EnforcementMode, HookMode, HostName,
    InspectionMode, ListenEndpoint, PolicyGeneration, Port, Protocol, RuleId, Severity, TargetHost,
    TcpStaticListener, UpstreamEndpoint,
};
use freja_policy::{
    AclPolicy, AclRule, DestinationAccess, DestinationGuard, DestinationGuardSettings, HostPattern,
    InspectionPattern, InspectionProgram, MatchExpression, PortRange, RuleAction,
    hook::{
        ChunkMutationPlan, HookFailurePolicy, HookFuture, HookRegistry, HookRunner,
        InteractiveBroker, InterceptTimeoutPolicy, TcpClientChunkHook,
    },
};
use freja_proxy::{
    DataPlaneEvent, DataPlaneEventSink, DataPlaneServices, ProxyLimits, StaticTcpServer,
    shutdown_channel,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::timeout,
};

#[path = "tcp_static/hooks.rs"]
mod hooks;
#[path = "tcp_static/inspection.rs"]
mod inspection;
#[path = "tcp_static/policy.rs"]
mod policy;
#[path = "tcp_static/relay.rs"]
mod relay;
#[path = "tcp_static/runtime.rs"]
mod runtime;
#[path = "tcp_static/support.rs"]
mod support;

use support::*;
