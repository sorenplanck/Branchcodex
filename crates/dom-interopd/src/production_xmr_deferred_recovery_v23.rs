//! Frozen admission scope, not recovery or funding authority.
use crate::production_xmr_graph_setup_v22::ProductionXmrGraphSetupV22;
use crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12;
use settlement_coordinator::ChildAuthorityRefusalV1 as Refusal;
use std::{cell::RefCell, rc::Rc};

pub(crate) struct ProductionXmrDeferredRecoveryV23 {
    session: [u8; 32],
    chain: [u8; 32],
    terms: [u8; 32],
    template: [u8; 32],
    point: [u8; 33],
    minimum: u32,
    max_reorg: u32,
    driver: RefCell<Option<Rc<ProductionXmrRecoveryDriverV12>>>,
}

impl ProductionXmrDeferredRecoveryV23 {
    pub(crate) fn from_setup(setup: &ProductionXmrGraphSetupV22) -> Result<Self, Refusal> {
        let binding = setup.binding();
        let terms = setup.terms();
        let digest = terms.terms_hash().map_err(|_| Refusal::Conflict)?;
        let refund = setup.refund_bundle_v23().map_err(|_| Refusal::Conflict)?;
        if binding.session_id() != terms.session_id.0
            || binding.chain_id() != terms.dom_leg.chain_id.0
            || binding.terms_digest() != digest
            || setup.setup().terms_hash() != digest
            || setup.setup().settlement_id() != terms.settlement_id.0
            || refund.template_hash
                != setup
                    .admitted_refund_template()
                    .map_err(|_| Refusal::Conflict)?
            || refund.adaptor_point_sec1 != setup.refund_point()
            || refund.adaptor_point_sec1 == terms.adaptor_point_sec1
            || terms.dom_leg.finality.min_confirmations == 0
            || terms.dom_leg.finality.max_reorg_depth < terms.dom_leg.finality.min_confirmations
        {
            return Err(Refusal::Conflict);
        }
        Ok(Self {
            session: binding.session_id(),
            chain: binding.chain_id(),
            terms: digest,
            template: refund.template_hash,
            point: refund.adaptor_point_sec1,
            minimum: terms.dom_leg.finality.min_confirmations,
            max_reorg: terms.dom_leg.finality.max_reorg_depth,
            driver: RefCell::new(None),
        })
    }

    pub(super) fn require_binding(
        &self,
        session: [u8; 32],
        chain: [u8; 32],
        template: [u8; 32],
        point: [u8; 33],
        minimum: u32,
        max_reorg: u32,
    ) -> Result<(), Refusal> {
        if (
            self.session,
            self.chain,
            self.template,
            self.point,
            self.minimum,
            self.max_reorg,
        ) != (session, chain, template, point, minimum, max_reorg)
        {
            return Err(Refusal::Conflict);
        }
        Ok(())
    }

    pub(crate) fn require_terms(&self, terms: [u8; 32]) -> Result<(), Refusal> {
        if self.terms != terms {
            return Err(Refusal::Conflict);
        }
        Ok(())
    }

    pub(crate) fn require_sweep(
        &self,
        sweep: &super::ProductionXmrSweepAuthorityV10,
    ) -> Result<(), Refusal> {
        self.require_terms(
            sweep
                .funding_terms_v22
                .terms_hash()
                .map_err(|_| Refusal::Conflict)?,
        )?;
        self.require_binding(
            sweep.binding.session_id,
            sweep.binding.dom_chain_id,
            sweep.binding.refund_template,
            sweep.binding.refund_claim.secp_compressed,
            sweep.funding_terms_v22.dom_leg.finality.min_confirmations,
            sweep.funding_terms_v22.dom_leg.finality.max_reorg_depth,
        )
    }

    fn authenticate_driver(&self, driver: &ProductionXmrRecoveryDriverV12) -> Result<(), Refusal> {
        driver.require_attachment(self.terms)?;
        driver.require_refund_binding(
            self.session,
            self.chain,
            self.template,
            self.point,
            self.minimum,
            self.max_reorg,
        )
    }

    pub(crate) fn install(
        &self,
        driver: Rc<ProductionXmrRecoveryDriverV12>,
    ) -> Result<(), Refusal> {
        let mut slot = self
            .driver
            .try_borrow_mut()
            .map_err(|_| Refusal::Unavailable)?;
        if slot.is_some() {
            return Err(Refusal::Conflict);
        }
        self.authenticate_driver(&driver)?;
        *slot = Some(driver);
        Ok(())
    }

    pub(crate) fn require_driver(&self) -> Result<Rc<ProductionXmrRecoveryDriverV12>, Refusal> {
        let driver = self
            .driver
            .try_borrow()
            .map_err(|_| Refusal::Unavailable)?
            .as_ref()
            .cloned()
            .ok_or(Refusal::Unavailable)?;
        self.authenticate_driver(&driver)?;
        Ok(driver)
    }
}
