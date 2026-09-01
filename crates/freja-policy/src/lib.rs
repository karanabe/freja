#![forbid(unsafe_code)]

//! Deterministic policy evaluation and typed hook contracts independent of
//! concrete server and networking runtime adapters.

pub mod acl;
pub mod destination;
pub mod hook;
pub mod inspection;

pub use acl::{
    AclPolicy, AclRule, HostPattern, HttpHeaderMatcher, MatchExpression, PolicyError, PolicyFacts,
    PortRange, RuleAction,
};
pub use destination::{DestinationAccess, DestinationGuard, DestinationGuardSettings};
pub use inspection::{InspectionError, InspectionPattern, InspectionProgram, StreamScanner};
