#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Deterministic policy evaluation and typed hook contracts independent of
//! concrete server and networking runtime adapters.

/// Ordered access-control rules and explainable evaluation.
pub mod acl;
/// Post-resolution protection for sensitive destination address classes.
pub mod destination;
pub mod hook;
/// Bounded fixed-pattern streaming inspection.
pub mod inspection;

pub use acl::{
    AclPolicy, AclRule, HostPattern, HttpHeaderMatcher, MatchExpression, PolicyError, PolicyFacts,
    PortRange, RuleAction,
};
pub use destination::{DestinationAccess, DestinationGuard, DestinationGuardSettings};
pub use inspection::{InspectionError, InspectionPattern, InspectionProgram, StreamScanner};
