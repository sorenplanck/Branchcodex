//! Authenticated two-leg topology for every BTC/EVM/SOL/XMR combination.
//! A topology proves identity, not operational readiness or refund safety.

use crate::production_inputs::AuthenticatedProductionInputsV1;
use route_executor::LegIdV1;
use settlement_coordinator::{ChildAuthorityRefusalV1, SettlementFaceV1, SettlementLegV1};

type Digest = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProductionLegTopologyV4 {
    pub(crate) settlement_id: Digest,
    pub(crate) face: SettlementFaceV1,
    pub(crate) chain_id: Digest,
    pub(crate) profile_digest: Digest,
    pub(crate) deployment_digest: Digest,
}

/// Both settlements and the mandatory common DOM chain, frozen by admission.
/// Distinct settlements remain distinct even on the same chain/deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProductionRouteTopologyV4 {
    pub(crate) route_id: Digest,
    pub(crate) composition_digest: Digest,
    pub(crate) dom_chain_id: Digest,
    pub(crate) terms_digest: Digest,
    pub(crate) registry_digest: Digest,
    pub(crate) dom_profile_digest: Digest,
    pub(crate) dom_deployment_digest: Digest,
    pub(crate) legs: [ProductionLegTopologyV4; 2],
}

pub(crate) const fn leg_index_v4(leg: SettlementLegV1) -> usize {
    match leg {
        SettlementLegV1::Upstream => 0,
        SettlementLegV1::Downstream => 1,
    }
}

impl ProductionRouteTopologyV4 {
    pub(crate) fn authenticate(
        inputs: &AuthenticatedProductionInputsV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        let composition = inputs.composition();
        let admission = inputs.admission();
        let dom = admission
            .dom_deployment_capability()
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        let legs = [
            Self::authenticate_leg(inputs, LegIdV1::Upstream)?,
            Self::authenticate_leg(inputs, LegIdV1::Downstream)?,
        ];
        let result = Self {
            route_id: inputs.admission().route_id(),
            composition_digest: composition.binding_digest(),
            dom_chain_id: composition.upstream().dom_leg.chain_id.0,
            terms_digest: admission.frozen_bindings().terms_digest,
            registry_digest: admission.registry_digest(),
            dom_profile_digest: admission.dom_profile_digest(),
            dom_deployment_digest: dom.registry_digest(),
            legs,
        };
        if result.dom_chain_id != composition.downstream().dom_leg.chain_id.0
            || result.dom_chain_id != dom.deployment().chain_id.0
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        result.validate()?;
        Ok(result)
    }

    fn authenticate_leg(
        inputs: &AuthenticatedProductionInputsV1,
        leg: LegIdV1,
    ) -> Result<ProductionLegTopologyV4, ChildAuthorityRefusalV1> {
        let admission = inputs.admission();
        let terms = match leg {
            LegIdV1::Upstream => inputs.composition().upstream(),
            LegIdV1::Downstream => inputs.composition().downstream(),
        };
        let count = [
            inputs.evm_session(leg).is_some(),
            inputs.bitcoin_session(leg).is_some(),
            inputs.solana_session(leg).is_some(),
            inputs.monero_session(leg).is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if count != 1 {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let (face, profile_digest, deployment_digest) =
            if let Some(session) = inputs.evm_session(leg) {
                let d = admission
                    .evm_deployment_capability(leg, session)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                (
                    SettlementFaceV1::Evm,
                    d.profile_digest(),
                    d.deployment().deployment_digest,
                )
            } else if inputs.bitcoin_session(leg).is_some() {
                let d = admission
                    .bitcoin_deployment_capability(leg)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                (
                    SettlementFaceV1::Bitcoin,
                    d.profile_digest(),
                    btc_actuator::resolved_bitcoin_deployment_digest_v1(&d)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                )
            } else if inputs.solana_session(leg).is_some() {
                let d = admission
                    .solana_deployment_capability(leg)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                (
                    SettlementFaceV1::Solana,
                    d.profile_digest(),
                    crate::production_child_solana::resolved_solana_deployment_digest_v1(&d)?,
                )
            } else {
                let d = admission
                    .monero_deployment_capability(leg)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                (
                    SettlementFaceV1::Monero,
                    d.profile_digest(),
                    crate::production_child_xmr::resolved_monero_deployment_digest_v1(&d)?,
                )
            };
        // The registry chain-profile digest and a SOL/XMR adapter-profile
        // hash commit different objects. Admission authenticates the former;
        // session authentication already checks the latter against terms.
        let admitted_profile = match leg {
            LegIdV1::Upstream => admission.upstream_profile_digest(),
            LegIdV1::Downstream => admission.downstream_profile_digest(),
        };
        if profile_digest != admitted_profile {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(ProductionLegTopologyV4 {
            settlement_id: terms.settlement_id.0,
            face,
            chain_id: terms.counterparty_leg.chain_id.0,
            profile_digest,
            deployment_digest,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ChildAuthorityRefusalV1> {
        if [
            self.route_id,
            self.composition_digest,
            self.dom_chain_id,
            self.terms_digest,
            self.registry_digest,
            self.dom_profile_digest,
            self.dom_deployment_digest,
        ]
        .contains(&[0; 32])
            || self.legs[0].settlement_id == self.legs[1].settlement_id
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        for leg in self.legs {
            if leg.face == SettlementFaceV1::Dom
                || leg.chain_id == self.dom_chain_id
                || [
                    leg.settlement_id,
                    leg.chain_id,
                    leg.profile_digest,
                    leg.deployment_digest,
                ]
                .contains(&[0; 32])
            {
                return Err(ChildAuthorityRefusalV1::Conflict);
            }
        }
        if self.legs[0].chain_id == self.legs[1].chain_id && self.legs[0].face != self.legs[1].face
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }

    pub(crate) fn require_request(
        &self,
        face: SettlementFaceV1,
        leg: SettlementLegV1,
        route_id: Digest,
        settlement_id: Digest,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let expected = self.legs[leg_index_v4(leg)];
        if route_id != self.route_id
            || settlement_id != expected.settlement_id
            || (face != SettlementFaceV1::Dom && face != expected.face)
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }

    pub(crate) fn require_chain_binding(
        &self,
        face: SettlementFaceV1,
        leg: SettlementLegV1,
        chain_id: Digest,
        profile_digest: Digest,
        deployment_digest: Digest,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        if face == SettlementFaceV1::Dom {
            if chain_id != self.dom_chain_id
                || profile_digest != self.dom_profile_digest
                || deployment_digest != self.dom_deployment_digest
            {
                return Err(ChildAuthorityRefusalV1::Conflict);
            }
        } else {
            let expected = self.legs[leg_index_v4(leg)];
            if face != expected.face
                || chain_id != expected.chain_id
                || profile_digest != expected.profile_digest
                || deployment_digest != expected.deployment_digest
            {
                return Err(ChildAuthorityRefusalV1::Conflict);
            }
        }
        Ok(())
    }

    pub(crate) fn require_admission_scope(
        &self,
        terms: Digest,
        registry: Digest,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        if terms != self.terms_digest || registry != self.registry_digest {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }
}

#[cfg(test)]
mod route_matrix_v22_tests {
    use super::*;

    const FACES: [SettlementFaceV1; 4] = [
        SettlementFaceV1::Bitcoin,
        SettlementFaceV1::Evm,
        SettlementFaceV1::Solana,
        SettlementFaceV1::Monero,
    ];

    /// Distinct non-zero digests keyed by a byte, so a test never accidentally
    /// satisfies a check by sharing a value with an unrelated field.
    const fn digest(tag: u8) -> Digest {
        [tag; 32]
    }

    fn topology(
        upstream: SettlementFaceV1,
        downstream: SettlementFaceV1,
        upstream_chain: u8,
        downstream_chain: u8,
    ) -> ProductionRouteTopologyV4 {
        ProductionRouteTopologyV4 {
            route_id: digest(0x01),
            composition_digest: digest(0x02),
            dom_chain_id: digest(0x03),
            terms_digest: digest(0x04),
            registry_digest: digest(0x05),
            dom_profile_digest: digest(0x06),
            dom_deployment_digest: digest(0x07),
            legs: [
                ProductionLegTopologyV4 {
                    settlement_id: digest(0x11),
                    face: upstream,
                    chain_id: digest(upstream_chain),
                    profile_digest: digest(0x13),
                    deployment_digest: digest(0x14),
                },
                ProductionLegTopologyV4 {
                    settlement_id: digest(0x21),
                    face: downstream,
                    chain_id: digest(downstream_chain),
                    profile_digest: digest(0x23),
                    deployment_digest: digest(0x24),
                },
            ],
        }
    }

    #[test]
    fn all_sixteen_face_pairs_validate_including_same_family_routes() {
        let mut checked = 0;
        for (upstream_index, upstream) in FACES.into_iter().enumerate() {
            for (downstream_index, downstream) in FACES.into_iter().enumerate() {
                // Distinct external networks per position: the same chain on
                // both legs is only coherent when the faces agree, and that
                // case is covered separately below.
                let topology = topology(
                    upstream,
                    downstream,
                    0x40 + upstream_index as u8,
                    0x50 + downstream_index as u8,
                );
                assert_eq!(
                    topology.validate(),
                    Ok(()),
                    "pair {upstream:?} -> {downstream:?} must validate"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 16, "the matrix must enumerate every ordered pair");
    }

    #[test]
    fn a_same_family_pair_on_one_network_validates_when_settlements_differ() {
        // Two positions of the same family may share an external network as
        // long as they settle distinct settlements — the router still keeps
        // one port per position.
        for face in FACES {
            assert_eq!(topology(face, face, 0x41, 0x41).validate(), Ok(()));
        }
    }

    #[test]
    fn one_network_with_disagreeing_faces_is_refused() {
        assert_eq!(
            topology(SettlementFaceV1::Evm, SettlementFaceV1::Solana, 0x41, 0x41).validate(),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
    }

    #[test]
    fn a_dom_face_or_the_dom_network_on_a_counterparty_leg_is_refused() {
        let mut dom_face = topology(SettlementFaceV1::Evm, SettlementFaceV1::Bitcoin, 0x41, 0x42);
        dom_face.legs[0].face = SettlementFaceV1::Dom;
        assert_eq!(
            dom_face.validate(),
            Err(ChildAuthorityRefusalV1::Conflict),
            "DOM is the centre, never a counterparty position"
        );

        let mut dom_network =
            topology(SettlementFaceV1::Evm, SettlementFaceV1::Bitcoin, 0x41, 0x42);
        dom_network.legs[1].chain_id = dom_network.dom_chain_id;
        assert_eq!(
            dom_network.validate(),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
    }

    #[test]
    fn both_positions_settling_the_same_settlement_is_refused() {
        let mut same = topology(SettlementFaceV1::Evm, SettlementFaceV1::Bitcoin, 0x41, 0x42);
        same.legs[1].settlement_id = same.legs[0].settlement_id;
        assert_eq!(same.validate(), Err(ChildAuthorityRefusalV1::Conflict));
    }
}
