//! Identity-based selection and one immutable, bounded rule-detail view.

use std::sync::Arc;

use freja_domain::{DecisionTrace, EvaluationTarget, SessionId, TransactionId};
use freja_policy::evidence::RuleEvidence;

use super::{FocusPane, TraceSnapshot, TrafficRow, TuiModel};

const MAXIMUM_CONTEXT_BYTES: usize = 16 * 1024;
const MAXIMUM_REASONS: usize = 64;
const MAXIMUM_REASON_BYTES: usize = 1024;

type RowIdentity = (SessionId, Option<TransactionId>);

#[derive(Debug, Default)]
pub(super) struct EvidenceView {
    row: Option<RowIdentity>,
    pub(super) selected: Option<u64>,
    pub(super) anchor: Option<u64>,
    pub(super) scroll: i32,
    pub(super) detail: Option<RuleDetail>,
}

#[derive(Debug)]
pub(super) struct RuleDetail {
    pub(super) identity: RowIdentity,
    pub(super) request: String,
    pub(super) request_incomplete: bool,
    pub(super) snapshot: TraceSnapshot,
    pub(super) scroll: u16,
}

impl TraceSnapshot {
    pub(super) fn bounded(
        id: u64,
        mut trace: DecisionTrace,
        target: Option<EvaluationTarget>,
        evidence: Option<Arc<RuleEvidence>>,
    ) -> Self {
        let mut reasons_incomplete = trace.match_reasons.len() > MAXIMUM_REASONS;
        trace.match_reasons.truncate(MAXIMUM_REASONS);
        trace.match_reasons.shrink_to_fit();
        for reason in &mut trace.match_reasons {
            reasons_incomplete |= truncate(&mut reason.criterion, MAXIMUM_REASON_BYTES);
            reasons_incomplete |= truncate(&mut reason.observed, MAXIMUM_REASON_BYTES);
        }
        Self {
            id,
            evidence,
            reasons_incomplete,
            trace,
            target,
        }
    }
}

fn truncate(text: &mut String, limit: usize) -> bool {
    if text.len() <= limit {
        return false;
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.shrink_to_fit();
    true
}

impl TuiModel {
    pub(super) fn reset_evidence_view(&mut self) {
        self.evidence_view = EvidenceView {
            row: self
                .selected_row()
                .map(|row| (row.session_id, row.transaction_id)),
            selected: self
                .selected_row()
                .and_then(|row| row.traces.front().map(|trace| trace.id)),
            ..EvidenceView::default()
        };
        self.diagnostics_scroll = 0;
    }

    pub(super) fn select_first_arriving_evaluation(
        &mut self,
        session: SessionId,
        transaction: Option<TransactionId>,
        id: u64,
    ) {
        if self.page == super::TuiPage::Diagnostics && self.evidence_view.row.is_none() {
            self.evidence_view.row = Some((session, transaction));
        }
        if self.evidence_view.row == Some((session, transaction))
            && self.evidence_view.selected.is_none()
        {
            self.evidence_view.selected = Some(id);
        }
    }

    pub(super) fn evidence_row(&self) -> Option<&TrafficRow> {
        let identity = self.evidence_view.row?;
        self.rows
            .iter()
            .find(|row| (row.session_id, row.transaction_id) == identity)
    }

    pub(super) fn selected_evaluation(&self) -> Option<&TraceSnapshot> {
        let row = self.evidence_row()?;
        match self.evidence_view.selected {
            Some(id) => row.traces.iter().find(|trace| trace.id == id),
            None => row.traces.front(),
        }
    }

    pub(super) fn select_evaluation(&mut self, next: bool) {
        let Some(row) = self.evidence_row() else {
            return;
        };
        let current = self
            .evidence_view
            .selected
            .and_then(|id| row.traces.iter().position(|trace| trace.id == id));
        let index = current.map_or(0, |index| {
            if next {
                index
                    .saturating_add(1)
                    .min(row.traces.len().saturating_sub(1))
            } else {
                index.saturating_sub(1)
            }
        });
        let Some(id) = row.traces.get(index).map(|trace| trace.id) else {
            return;
        };
        self.evidence_view.selected = Some(id);
        self.evidence_view.anchor = Some(id);
        self.evidence_view.scroll = 0;
        self.diagnostics_scroll = 0;
    }

    pub(super) fn open_rule_detail(&mut self) {
        let Some(snapshot) = self.selected_evaluation().cloned() else {
            self.set_input_notice("No retained selected evaluation; j/k selects a retained decision. Findings are not decisions.".to_owned());
            return;
        };
        let Some(row) = self.evidence_row() else {
            return;
        };
        let identity = (row.session_id, row.transaction_id);
        let mut request = row
            .request
            .start_line
            .as_deref()
            .unwrap_or("Request unavailable (not retained); no URL inferred")
            .chars()
            .take(MAXIMUM_CONTEXT_BYTES)
            .collect::<String>();
        let mut request_incomplete = row
            .request
            .start_line
            .as_ref()
            .is_some_and(|line| line.len() > MAXIMUM_CONTEXT_BYTES);
        request_incomplete |= truncate(&mut request, MAXIMUM_CONTEXT_BYTES);
        // Origin-form needs the observed Host, not a guessed absolute URL.
        if (row.target.starts_with('/') || row.target == "*")
            && let Some((_, host)) = row
                .request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        {
            request.push_str(" | Host header: ");
            request.extend(
                String::from_utf8_lossy(&host[..host.len().min(MAXIMUM_CONTEXT_BYTES)]).chars(),
            );
            request_incomplete |= host.len() > MAXIMUM_CONTEXT_BYTES;
            request_incomplete |= truncate(&mut request, MAXIMUM_CONTEXT_BYTES);
        }
        request.shrink_to_fit();
        self.evidence_view.selected = Some(snapshot.id);
        self.evidence_view.detail = Some(RuleDetail {
            identity,
            request,
            request_incomplete,
            snapshot,
            scroll: 0,
        });
    }

    pub(super) fn detail_original_retained(&self) -> bool {
        self.evidence_view.detail.as_ref().is_some_and(|detail| {
            self.rows.iter().any(|row| {
                (row.session_id, row.transaction_id) == detail.identity
                    && row
                        .traces
                        .iter()
                        .any(|trace| trace.id == detail.snapshot.id)
            })
        })
    }

    pub(super) fn close_rule_detail(&mut self) {
        let retained = self.detail_original_retained();
        self.evidence_view.detail = None;
        if !retained {
            self.set_input_notice("Original evaluation was evicted by retention limits; no replacement selected. j/k explicitly selects a retained decision.".to_owned());
        }
    }

    pub(super) fn evidence_missing(&self) -> bool {
        self.evidence_view.row.is_some()
            && (self.evidence_row().is_none()
                || self.evidence_view.selected.is_some() && self.selected_evaluation().is_none())
    }

    pub(super) fn scroll_evidence(&mut self, amount: i32) -> bool {
        if self.focus == FocusPane::Evidence && self.evidence_view.anchor.is_some() {
            self.evidence_view.scroll = self
                .evidence_view
                .scroll
                .saturating_add(amount)
                .clamp(-65535, 65535);
            true
        } else {
            false
        }
    }
}
