//! Closed diagnostic projection for the Stage-11 F6 refusal. Names which step
//! of the stage refused, never a path, an input byte, a credential or the
//! original error's own text. Grants nothing and changes no classification.

/// One closed tag per fallible Stage-11 step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionF6StageFailureV25 {
    /// The pinned authority-bundle path was absent from the layout.
    BundlePath,
    /// The authority bundle file could not be read within its bound.
    BundleRead,
    /// The authority bundle failed its threshold/scope authentication.
    BundleDecode,
    /// The retained historical recovery could not be bound.
    HistoricalRecovery,
    /// A Stage-11 prefix could not be derived or prepared.
    Prefix,
    /// An activation path set could not be derived from the layout.
    ActivationPaths,
    /// The DOM actuator lease was refused.
    DomLease,
    /// A DOM session could not be bound to that lease.
    DomSession,
    /// The DOM funding inputs could not be prepared from the local wallet.
    DomFunding,
    /// A DOM payout face selection or its authority was refused, by class.
    DomPayouts(DomActuatorCauseV25),
    /// The per-leg DOM wallet authority itself was refused.
    DomAuthority,
    /// The payout value or its selection request was refused.
    DomRequest,
    /// A counterparty face refused its authenticated session.
    CounterpartyFace,
    /// The pair factory refused its bundle, inventory, terms or credentials.
    Factory,
    /// The authenticated final-claim plan could not be taken.
    ClaimPlan,
    /// The activated route store could not be handed to F6.
    RouteStore,
    /// The pair activation refused its materials.
    Activation,
}

impl ProductionF6StageFailureV25 {
    /// Frozen tag; the operator reads a step, never a value.
    pub const fn step_code(self) -> &'static str {
        match self {
            Self::BundlePath => "bundle_path",
            Self::BundleRead => "bundle_read",
            Self::BundleDecode => "bundle_decode",
            Self::HistoricalRecovery => "historical_recovery",
            Self::Prefix => "stage11_prefix",
            Self::ActivationPaths => "activation_paths",
            Self::DomLease => "dom_lease",
            Self::DomSession => "dom_session",
            Self::DomFunding => "dom_funding",
            Self::DomPayouts(_) => "dom_payouts",
            Self::DomAuthority => "dom_authority",
            Self::DomRequest => "dom_request",
            Self::CounterpartyFace => "counterparty_face",
            Self::Factory => "pair_factory",
            Self::ClaimPlan => "claim_plan",
            Self::RouteStore => "route_store",
            Self::Activation => "pair_activation",
        }
    }
}

impl core::fmt::Display for ProductionF6StageFailureV25 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "step={}", self.step_code())?;
        if let Self::DomPayouts(cause) = self {
            write!(formatter, " cause={}", cause.cause_code())?;
        }
        Ok(())
    }
}

/// Closed class of a DOM actuator refusal. Never its text, a commitment, a
/// value, a path or a credential: the operator learns the class, not the data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomActuatorCauseV25 {
    /// The store, its format, its process lock or its creation was refused.
    Storage,
    /// The participant lease was missing, held, stale or expired.
    Lease,
    /// A session or request binding disagreed.
    Binding,
    /// A capability did not match the retained one.
    Capability,
    /// The store stage contradicted the request.
    Stage,
    /// A retained output reservation contradicted the requested selection.
    Reservation,
    /// The wallet could not cover the requested value.
    Funds,
    /// The encrypted wallet itself was unavailable or bound to another chain.
    Wallet,
    /// Any other closed refusal of that actuator.
    Other,
}

impl DomActuatorCauseV25 {
    /// Frozen class tag.
    pub const fn cause_code(self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::Lease => "lease",
            Self::Binding => "binding",
            Self::Capability => "capability",
            Self::Stage => "stage",
            Self::Reservation => "output_reservation",
            Self::Funds => "insufficient_funds",
            Self::Wallet => "wallet",
            Self::Other => "other",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_stage_tag_is_distinct_and_lowercase_v25() {
        let all = [
            ProductionF6StageFailureV25::BundlePath,
            ProductionF6StageFailureV25::BundleRead,
            ProductionF6StageFailureV25::BundleDecode,
            ProductionF6StageFailureV25::HistoricalRecovery,
            ProductionF6StageFailureV25::Prefix,
            ProductionF6StageFailureV25::ActivationPaths,
            ProductionF6StageFailureV25::DomLease,
            ProductionF6StageFailureV25::DomSession,
            ProductionF6StageFailureV25::DomFunding,
            ProductionF6StageFailureV25::DomPayouts(DomActuatorCauseV25::Other),
            ProductionF6StageFailureV25::DomAuthority,
            ProductionF6StageFailureV25::DomRequest,
            ProductionF6StageFailureV25::CounterpartyFace,
            ProductionF6StageFailureV25::Factory,
            ProductionF6StageFailureV25::ClaimPlan,
            ProductionF6StageFailureV25::RouteStore,
            ProductionF6StageFailureV25::Activation,
        ];
        let mut codes: Vec<&str> = all.iter().map(|step| step.step_code()).collect();
        codes.sort_unstable();
        let total = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), total);
        assert!(codes.iter().all(|code| {
            !code.is_empty()
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        }));
        assert_eq!(
            ProductionF6StageFailureV25::Factory.to_string(),
            "step=pair_factory"
        );
        assert_eq!(
            ProductionF6StageFailureV25::DomPayouts(DomActuatorCauseV25::Funds).to_string(),
            "step=dom_payouts cause=insufficient_funds"
        );
    }
}
