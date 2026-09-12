//! Activation access through the sole retained Stage-12 Contracts owner.
use super::*;
use crate::production_contracts::ProductionBootstrapRuntimeErrorV16 as Error;
use crate::production_xmr_graph_setup_v22::ProductionXmrGraphSetupV22;
use crate::production_xmr_sweep::{ActivatedXmrResourcesV23, ProductionXmrEnrolledResourcesV23};

impl ProductionRelayStage12OwnerV1 {
    /// Reauthenticate the native origin before projecting an executable
    /// refund face. No legacy fallback and no returned secret or Store handle.
    pub(crate) fn bound_xmr_setup_v23(
        &self,
        leg: LegIdV1,
    ) -> Result<&ProductionXmrGraphSetupV22, Error> {
        let setup = self.xmr_custody_setup_v23(leg)?;
        let authority = setup.native_refund_binding_v23()?;
        let owner = match leg {
            LegIdV1::Upstream => &self.upstream,
            LegIdV1::Downstream => &self.downstream,
        };
        if authority.trusted_chain_id() != owner.trusted_chain_id {
            return Err(Error::Binding);
        }
        owner
            .contracts
            .revalidate_xmr_refund_template_binding_v23(authority)
            .map_err(|_| Error::Binding)?;
        Ok(setup)
    }

    /// Transfer already-open enrolled resources to bound sweep/custody
    /// owners. The two borrows come from this same Stage-12 object, never from
    /// independently opened or copied Contracts stores.
    pub(crate) fn activate_enrolled_xmr_resources_v23(
        &self,
        leg: LegIdV1,
        enrolled: ProductionXmrEnrolledResourcesV23,
    ) -> Result<ActivatedXmrResourcesV23, Error> {
        let setup = self.bound_xmr_setup_v23(leg)?;
        let owner = match leg {
            LegIdV1::Upstream => &self.upstream,
            LegIdV1::Downstream => &self.downstream,
        };
        enrolled
            .activate(setup, &owner.contracts)
            .map_err(|_| Error::Binding)
    }
}
