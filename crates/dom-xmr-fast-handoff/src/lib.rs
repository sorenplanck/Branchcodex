//! Product-owned core for the DXF1 prepared-liquidity DOM/XMR handoff.
//!
//! The crate contains no wallet keys and no network client. It gives the
//! interoperability daemon one durable, fail-closed authority which orders
//! exact DOM and XMR daemon operations. Chain-specific adapters implement the
//! narrow ports in [`authority`].

#![forbid(unsafe_code)]

pub mod authority;
pub mod journal;
pub mod state;

pub use authority::{
    DomClaimAdmission, DomClaimCanonicalObservation, DomClaimFn, DomClaimObservation,
    DomClaimObservationFn, DomClaimObservationPort, DomClaimPort, DomClaimRecovery,
    FastHandoffAuthority, FastHandoffAuthorityError, PreparedXmrSubmission, XmrDaemonAdmission,
    XmrPaymentFn, XmrPaymentPort, XmrPreparedIdentity, XmrPreparedPayment, XmrSubmissionFn,
    XmrSubmissionPort,
};
pub use journal::{FastHandoffJournal, FastHandoffJournalError};
pub use state::{
    FastHandoff, FastHandoffBinding, FastHandoffError, FastHandoffPhase, FastHandoffPolicy,
    DXF1_PROTOCOL,
};
