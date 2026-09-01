use std::net::SocketAddr;

use freja_audit::{AuditEnvelope, AuditEvent};
use freja_domain::{RuleId, SessionId, TransactionId};
use http::{Method, Request, Response};
use hyper::body::Incoming;
use tokio::{sync::mpsc, task::JoinHandle};

use super::{
    body::{BodyError, BodyFrame, CollectError, ProxyBody, channel, collect_bounded, full},
    headers,
    target::ForwardTarget,
    wire::RequestCaptureHandle,
};
use crate::{
    DataPlaneServices, ProxyError, ProxyLimits, ShutdownSignal,
    destination::{audit_context, authorize_and_resolve, connect_any, record_action},
    inspection::{BodyTransform, FlowInspector},
    tcp::relay::{RelayLimits, RelayStats, RelayTermination, relay},
};

mod body;
mod connect;
mod forward;
mod hooks;
mod intercept;
mod response;

use response::{authenticate_proxy_request, proxy_authentication_required, response_for_error};

pub(super) type ConnectionTaskHandle = JoinHandle<Result<(), ProxyError>>;

#[derive(Clone)]
pub(super) struct HttpService {
    peer: SocketAddr,
    session_id: SessionId,
    connect_port_rule: RuleId,
    connect_ports: freja_domain::HttpForwardListener,
    services: DataPlaneServices,
    limits: ProxyLimits,
    shutdown: ShutdownSignal,
    task_sender: mpsc::Sender<ConnectionTaskHandle>,
    request_capture: Option<RequestCaptureHandle>,
}

impl HttpService {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        peer: SocketAddr,
        session_id: SessionId,
        connect_port_rule: RuleId,
        connect_ports: freja_domain::HttpForwardListener,
        services: DataPlaneServices,
        limits: ProxyLimits,
        shutdown: ShutdownSignal,
        task_sender: mpsc::Sender<ConnectionTaskHandle>,
        request_capture: Option<RequestCaptureHandle>,
    ) -> Self {
        Self {
            peer,
            session_id,
            connect_port_rule,
            connect_ports,
            services,
            limits,
            shutdown,
            task_sender,
            request_capture,
        }
    }

    pub(super) async fn handle(
        &self,
        request: Request<Incoming>,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        let transaction_id = TransactionId::new();
        if let Some(capture) = &self.request_capture {
            capture.bind(transaction_id);
        }
        self.audit_request(transaction_id, &request).await?;
        if let Some(authentication) = self.connect_ports.authentication() {
            let authenticated = authenticate_proxy_request(request.headers(), authentication);
            self.services
                .publish(AuditEnvelope {
                    context: audit_context(self.session_id, Some(transaction_id), &self.services),
                    event: AuditEvent::ProxyAuthentication {
                        outcome: if authenticated {
                            "accepted"
                        } else {
                            "rejected"
                        }
                        .to_owned(),
                    },
                })
                .await?;
            if !authenticated {
                let response = proxy_authentication_required(authentication);
                let status = response.status().as_u16();
                let response_headers = headers::audit_headers(response.headers());
                self.audit_response(transaction_id, status, response_headers)
                    .await?;
                return Ok(response);
            }
        }
        let response = if request.method() == Method::CONNECT {
            self.connect(request, transaction_id).await
        } else {
            self.forward(request, transaction_id).await
        };
        let response = match response {
            Ok(response) => response,
            Err(error) => response_for_error(error)?,
        };
        let status = response.status().as_u16();
        let response_headers = headers::audit_headers(response.headers());
        if self.services.publishes_events() {
            self.services.publish_http_response_event(
                self.session_id,
                transaction_id,
                status,
                format!("{:?}", response.version()),
                headers::presentation_headers(response.headers()),
            );
        }
        self.audit_response(transaction_id, status, response_headers)
            .await?;
        Ok(response)
    }
    async fn audit_request(
        &self,
        transaction_id: TransactionId,
        request: &Request<Incoming>,
    ) -> Result<(), ProxyError> {
        let method = request.method().as_str().to_owned();
        let target = request.uri().to_string();
        if self.services.publishes_events() {
            self.services.publish_http_event(
                self.session_id,
                transaction_id,
                method.clone(),
                target.clone(),
                format!("{:?}", request.version()),
                headers::presentation_headers(request.headers()),
            );
        }
        self.services
            .publish(AuditEnvelope {
                context: audit_context(self.session_id, Some(transaction_id), &self.services),
                event: AuditEvent::HttpRequestObserved {
                    method,
                    target,
                    headers: headers::audit_headers(request.headers()),
                },
            })
            .await
    }

    async fn audit_response(
        &self,
        transaction_id: TransactionId,
        status: u16,
        headers: std::collections::BTreeMap<String, Vec<String>>,
    ) -> Result<(), ProxyError> {
        self.services
            .publish(AuditEnvelope {
                context: audit_context(self.session_id, Some(transaction_id), &self.services),
                event: AuditEvent::HttpResponseObserved { status, headers },
            })
            .await
    }

    async fn register_task(&self, handle: ConnectionTaskHandle) -> Result<(), ProxyError> {
        if let Err(error) = self.task_sender.send(handle).await {
            error.0.abort();
            return Err(ProxyError::TunnelRegistration);
        }
        Ok(())
    }
}
