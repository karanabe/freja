use std::collections::{BTreeMap, HashSet};

use freja_domain::{ReplayFacts, SanitizedHeaders};
use url::{Url, form_urlencoded};

use crate::AuditEvent;

/// Central secret redaction policy used before audit serialization.
#[derive(Debug, Clone)]
pub struct Redactor {
    query_parameters: HashSet<String>,
}

impl Redactor {
    /// Creates a redactor. Query parameter names are matched case-insensitively.
    pub fn new(parameters: impl IntoIterator<Item = String>) -> Self {
        Self {
            query_parameters: parameters
                .into_iter()
                .map(|parameter| parameter.to_ascii_lowercase())
                .collect(),
        }
    }

    /// Replaces standard credential-bearing header values.
    pub fn redact_headers(&self, headers: &mut BTreeMap<String, Vec<String>>) {
        for (name, values) in headers {
            if is_secret_header(name) {
                *values = vec!["[REDACTED]".to_owned()];
            }
        }
    }

    /// Redacts configured query parameter values in absolute or origin-form targets.
    pub fn redact_target(&self, target: &str) -> String {
        match Url::parse(target) {
            Ok(mut url) => {
                let has_userinfo = !url.username().is_empty() || url.password().is_some();
                if has_userinfo
                    && (url.set_username("[REDACTED]").is_err() || url.set_password(None).is_err())
                {
                    return "[REDACTED URL WITH USERINFO]".to_owned();
                }
                let pairs = url
                    .query_pairs()
                    .map(|(name, value)| (name.into_owned(), value.into_owned()))
                    .collect::<Vec<_>>();
                if pairs.is_empty() && !has_userinfo {
                    return target.to_owned();
                }
                if !pairs.is_empty() {
                    url.set_query(None);
                    let mut query = url.query_pairs_mut();
                    for (name, value) in pairs {
                        let value = if self.is_secret_parameter(&name) {
                            "[REDACTED]"
                        } else {
                            &value
                        };
                        query.append_pair(&name, value);
                    }
                }
                url.into()
            }
            Err(_) => self.redact_origin_form(target),
        }
    }

    /// Applies all event-specific redaction before hashing and persistence.
    pub fn redact_event(&self, event: &mut AuditEvent) {
        match event {
            AuditEvent::HttpRequestObserved {
                target, headers, ..
            } => {
                *target = self.redact_target(target);
                self.redact_headers(headers);
            }
            AuditEvent::HttpResponseObserved { headers, .. } => self.redact_headers(headers),
            AuditEvent::ReplayFactsObserved {
                facts: ReplayFacts::HttpRequest(facts),
            } => {
                *facts = freja_domain::HttpRequestFacts::new(
                    facts.target().clone(),
                    facts.method(),
                    self.redact_target(facts.path()),
                    redact_sanitized_headers(facts.headers()),
                );
            }
            AuditEvent::ReplayFactsObserved {
                facts: ReplayFacts::HttpResponse(facts),
            } => {
                *facts = freja_domain::HttpResponseFacts::new(
                    facts.target().clone(),
                    facts.status(),
                    redact_sanitized_headers(facts.headers()),
                );
            }
            _ => {}
        }
    }

    fn redact_origin_form(&self, target: &str) -> String {
        let (without_fragment, fragment) = target
            .split_once('#')
            .map_or((target, None), |(left, right)| (left, Some(right)));
        let Some((path, raw_query)) = without_fragment.split_once('?') else {
            return target.to_owned();
        };
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for (name, value) in form_urlencoded::parse(raw_query.as_bytes()) {
            let value = if self.is_secret_parameter(&name) {
                "[REDACTED]"
            } else {
                value.as_ref()
            };
            serializer.append_pair(&name, value);
        }
        let query = serializer.finish();
        fragment.map_or_else(
            || format!("{path}?{query}"),
            |fragment| format!("{path}?{query}#{fragment}"),
        )
    }

    fn is_secret_parameter(&self, name: &str) -> bool {
        self.query_parameters.contains(&name.to_ascii_lowercase())
    }
}

fn is_secret_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie"
    )
}

fn redact_sanitized_headers(headers: &SanitizedHeaders) -> SanitizedHeaders {
    SanitizedHeaders::new(headers.iter().map(|(name, values)| {
        let values = if is_secret_header(name) {
            vec![b"[REDACTED]".to_vec()]
        } else {
            values.to_vec()
        };
        (name.to_owned(), values)
    }))
}
