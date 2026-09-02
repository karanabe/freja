//! In-process typed hooks and bounded interactive interception.
//!
//! Registries contain `Send + Sync` trait objects and can be cloned across
//! runtime tasks. Registration happens during bootstrap; runners consume an
//! immutable snapshot. Hooks return typed plans rather than arbitrary HTTP
//! wire bytes, allowing the proxy to preserve framing and protected headers.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//! use freja_policy::hook::{
//!     BodyMutationPlan, HookFuture, HookRegistry, HttpRequestBodyHook, WireBody,
//! };
//!
//! struct KeepBody;
//!
//! impl HttpRequestBodyHook for KeepBody {
//!     fn call<'a>(&'a self, _input: &'a WireBody) -> HookFuture<'a, BodyMutationPlan> {
//!         Box::pin(async { Ok(BodyMutationPlan::Keep) })
//!     }
//! }
//!
//! let mut registry = HookRegistry::default();
//! registry.register_request_body(Arc::new(KeepBody));
//! ```

mod contract;
mod interactive;
mod mutation;
mod repeat;
mod runner;

pub use contract::{
    BodyMutationPlan, ChunkMutationPlan, DecodedBody, HeadMutationPlan, HeaderMutation, HookError,
    HookFuture, HookRegistry, HttpRequestBodyHook, HttpRequestHead, HttpRequestHeadHook,
    HttpRequestMutationPlan, HttpResponseBodyHook, HttpResponseHead, HttpResponseHeadHook,
    TcpClientChunkHook, TcpUpstreamChunkHook, WireBody,
};
pub use interactive::{
    HttpRequestSnapshot, InteractiveBroker, InteractiveDecision, InterceptContext, InterceptError,
    InterceptRequest, InterceptTimeoutPolicy,
};
pub use mutation::{
    MutationError, apply_body_mutation, apply_head_mutation, apply_http_mutation,
    normalize_replaced_body_headers,
};
pub use repeat::{
    HttpResponseSnapshot, RepeatFailureCategory, RepeatOutcome, RepeatRequest, RepeatResult,
};
pub use runner::{HookFailurePolicy, HookRunError, HookRunner};

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use bytes::Bytes;
    use freja_domain::{HookMode, SessionId, TransactionId};
    use http::{HeaderMap, HeaderValue, header};

    use super::{
        BodyMutationPlan, DecodedBody, HeadMutationPlan, HeaderMutation, HookError,
        HookFailurePolicy, HookFuture, HookRegistry, HookRunError, HookRunner, HttpRequestBodyHook,
        HttpRequestSnapshot, InteractiveBroker, InterceptContext, InterceptError,
        InterceptTimeoutPolicy, MutationError, WireBody, apply_head_mutation, apply_http_mutation,
    };

    struct CountingHook(Arc<AtomicUsize>);

    impl HttpRequestBodyHook for CountingHook {
        fn call<'a>(&'a self, _input: &'a WireBody) -> HookFuture<'a, BodyMutationPlan> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(BodyMutationPlan::Keep) })
        }
    }

    struct PendingHook;

    impl HttpRequestBodyHook for PendingHook {
        fn call<'a>(&'a self, _input: &'a WireBody) -> HookFuture<'a, BodyMutationPlan> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test]
    async fn disabled_mode_does_not_invoke_registered_hook() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut registry = HookRegistry::default();
        registry.register_request_body(Arc::new(CountingHook(Arc::clone(&calls))));
        let runner = HookRunner::new(
            HookMode::Disabled,
            registry,
            Duration::from_millis(10),
            HookFailurePolicy::FailClosed,
        );

        let result = runner.request_body(&WireBody::new("body")).await.unwrap();

        assert_eq!(result, BodyMutationPlan::Keep);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn hook_timeout_obeys_fail_closed_policy() {
        let mut registry = HookRegistry::default();
        registry.register_request_body(Arc::new(PendingHook));
        let runner = HookRunner::new(
            HookMode::Automatic,
            registry,
            Duration::from_millis(1),
            HookFailurePolicy::FailClosed,
        );

        let result = runner.request_body(&WireBody::new("body")).await;

        assert!(matches!(result, Err(HookRunError::TimedOut)));
    }

    #[test]
    fn body_replacement_reconstructs_content_length() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("3"));
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        headers.insert(header::ETAG, HeaderValue::from_static("old-validator"));
        let output = apply_http_mutation(
            &mut headers,
            &WireBody::new("old"),
            &HeadMutationPlan::default(),
            &BodyMutationPlan::Replace(DecodedBody::new("longer")),
            64,
        )
        .unwrap();

        assert_eq!(output, Bytes::from_static(b"longer"));
        assert_eq!(headers[header::CONTENT_LENGTH], "6");
        assert!(!headers.contains_key(header::CONTENT_ENCODING));
        assert!(!headers.contains_key(header::ETAG));
    }

    #[test]
    fn oversized_body_replacement_is_rejected() {
        let mut headers = HeaderMap::new();
        let error = apply_http_mutation(
            &mut headers,
            &WireBody::new("old"),
            &HeadMutationPlan::default(),
            &BodyMutationPlan::Replace(DecodedBody::new("too-large")),
            4,
        )
        .unwrap_err();

        assert_eq!(
            error,
            MutationError::BodyTooLarge {
                actual: 9,
                maximum: 4,
            }
        );
    }

    #[test]
    fn head_hooks_cannot_override_body_framing() {
        let mut headers = HeaderMap::new();
        let name = header::CONTENT_LENGTH;
        let error = apply_head_mutation(
            &mut headers,
            &HeadMutationPlan {
                headers: vec![HeaderMutation::Set {
                    name: name.clone(),
                    value: HeaderValue::from_static("999"),
                }],
            },
        )
        .unwrap_err();

        assert_eq!(error, MutationError::ProtectedHeader { name });
    }

    #[test]
    fn append_mutation_preserves_repeated_end_to_end_headers() {
        let mut headers = HeaderMap::new();
        let name = http::header::HeaderName::from_static("x-review");
        headers.append(name.clone(), HeaderValue::from_static("first"));

        apply_head_mutation(
            &mut headers,
            &HeadMutationPlan {
                headers: vec![HeaderMutation::Append {
                    name: name.clone(),
                    value: HeaderValue::from_static("second"),
                }],
            },
        )
        .unwrap();

        assert_eq!(
            headers
                .get_all(name)
                .iter()
                .map(http::HeaderValue::as_bytes)
                .collect::<Vec<_>>(),
            vec![b"first".as_slice(), b"second".as_slice()]
        );
    }

    #[tokio::test]
    async fn paused_flow_limit_and_timeout_are_explicit() {
        let (broker, mut receiver) = InteractiveBroker::channel(
            1,
            1,
            Duration::from_millis(10),
            InterceptTimeoutPolicy::FailClosed,
        )
        .unwrap();
        let context = InterceptContext {
            session_id: SessionId::new(),
            transaction_id: TransactionId::new(),
            source_ip: "127.0.0.1".parse().unwrap(),
        };
        let first_broker = broker.clone();
        let first = tokio::spawn(async move {
            first_broker
                .intercept_http_request(context, interactive_request_snapshot())
                .await
        });
        let request = receiver.recv().await.unwrap();
        let second = broker
            .intercept_http_request(context, interactive_request_snapshot())
            .await;
        assert_eq!(second, Err(InterceptError::Saturated));
        drop(request);
        let first = first.await.unwrap();
        assert!(matches!(
            first,
            Err(InterceptError::ResponderDropped | InterceptError::TimedOut)
        ));
    }

    #[test]
    fn hook_error_message_is_concrete() {
        assert_eq!(HookError::new("failed").to_string(), "failed");
    }

    fn interactive_request_snapshot() -> HttpRequestSnapshot {
        HttpRequestSnapshot {
            method: http::Method::GET,
            uri: http::Uri::from_static("/"),
            version: http::Version::HTTP_11,
            headers: http::HeaderMap::new(),
            body: WireBody::new(Bytes::new()),
            maximum_head_bytes: 1_024,
            maximum_body_bytes: 1_024,
        }
    }
}
