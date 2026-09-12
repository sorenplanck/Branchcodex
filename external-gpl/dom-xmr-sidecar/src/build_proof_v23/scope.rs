//! Internal common construction scope. A local origin never impersonates an
//! accepted remote request; only transaction/proof construction is shared.
use super::*;
use xmr_key_image_proof::{
    LocalRefundBuildRequestV24, LocalRefundBuildResponseV24, LocalRefundLoadRequestV24,
    LocalRefundReadyScopeV24,
};

pub(super) type RemoteRequest = BuildSweepRequestV23<BuildSweepRequestV2>;
pub(super) type RemoteResponse = BuildSweepResponseV23<BuildSweepResponseV2>;
pub(super) type LocalRequest = LocalRefundBuildRequestV24<BuildSweepRequestV2>;
pub(super) type LocalResponse = LocalRefundBuildResponseV24<BuildSweepResponseV2>;

pub(super) fn local_public_scope(r: &LocalRequest) -> LocalRefundReadyScopeV24 {
    LocalRefundReadyScopeV24 {
        request: LocalRefundLoadRequestV24 {
            api_version: 24,
            request_nonce: r.build.request_nonce,
            network_genesis: r.network_genesis,
            route: r.route,
            session: r.session,
            terms: r.terms,
            effect_id: r.effect_id,
            fencing_epoch: r.fencing_epoch,
            semantic_digest: r.semantic_digest,
            dom_refund_tx_hash: r.dom_refund_tx_hash,
            graph_digest: r.graph_digest,
            settlement_id: r.build.settlement_id,
            funding_tx_hash: r.build.funding_tx_hash,
            funded_amount: r.build.expected_amount_piconero,
            destination: r.build.destination.clone(),
            expected_spend_public_key: r.build.expected_spend_public_key,
            max_fee: r.max_fee,
            auth_tag: [0; 32],
        },
        local_authorization_digest: r.local_authorization_digest,
        output_index: r.output_index,
        funding_height: r.funding_height,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Origin {
    AcceptedRemote {
        authorization_digest: [u8; 32],
        request_message_digest: [u8; 32],
    },
    LocalRefund {
        authorization_digest: [u8; 32],
        effect_id: [u8; 32],
        fencing_epoch: u64,
        semantic_digest: [u8; 32],
        dom_refund_tx_hash: [u8; 32],
        graph_digest: [u8; 32],
    },
}
#[derive(Clone, Copy)]
enum Source<'a> {
    Remote(&'a RemoteRequest),
    Local(&'a LocalRequest),
}

pub(super) struct Request<'a> {
    source: Source<'a>,
    pub(super) origin: Origin,
    pub(super) build: &'a BuildSweepRequestV2,
    pub(super) network_genesis: [u8; 32],
    pub(super) route: [u8; 32],
    pub(super) session: [u8; 32],
    pub(super) terms: [u8; 32],
    pub(super) output_index: u64,
    pub(super) funding_height: u64,
    pub(super) max_fee: u64,
}
impl<'a> Request<'a> {
    pub(super) fn remote(r: &'a RemoteRequest) -> Self {
        Self {
            source: Source::Remote(r),
            origin: Origin::AcceptedRemote {
                authorization_digest: r.authorization_digest,
                request_message_digest: r.request_message_digest,
            },
            build: &r.build,
            network_genesis: r.network_genesis,
            route: r.route,
            session: r.session,
            terms: r.terms,
            output_index: r.output_index,
            funding_height: r.funding_height,
            max_fee: r.max_fee,
        }
    }
    pub(super) fn local(r: &'a LocalRequest) -> Self {
        Self {
            source: Source::Local(r),
            origin: Origin::LocalRefund {
                authorization_digest: r.local_authorization_digest,
                effect_id: r.effect_id,
                fencing_epoch: r.fencing_epoch,
                semantic_digest: r.semantic_digest,
                dom_refund_tx_hash: r.dom_refund_tx_hash,
                graph_digest: r.graph_digest,
            },
            build: &r.build,
            network_genesis: r.network_genesis,
            route: r.route,
            session: r.session,
            terms: r.terms,
            output_index: r.output_index,
            funding_height: r.funding_height,
            max_fee: r.max_fee,
        }
    }
    pub(super) fn validate_scope(
        &self,
    ) -> Result<
        xmr_key_image_proof::InputSpendActionV23,
        xmr_key_image_proof::InputSpendProofErrorV23,
    > {
        match self.source {
            Source::Remote(r) => r.validate_scope(),
            Source::Local(r) => r.validate_scope(),
        }
    }
    pub(super) fn canonical_auth_bytes(
        &self,
        build: &[u8],
    ) -> Result<Vec<u8>, xmr_key_image_proof::InputSpendProofErrorV23> {
        match self.source {
            Source::Remote(r) => r.canonical_auth_bytes(build),
            Source::Local(r) => r.canonical_auth_bytes(build),
        }
    }
    pub(super) fn verify_auth(&self, config: &Config) -> Result<(), SidecarOperationError> {
        match self.source {
            Source::Remote(r) => config.auth.verify_build_proof_v23(r),
            Source::Local(r) => config.auth.verify_local_refund_build_v24(r),
        }
        .map_err(|_| rejected())
    }

    pub(super) fn local_public_scope(&self) -> Option<LocalRefundReadyScopeV24> {
        match self.source {
            Source::Local(r) => Some(local_public_scope(r)),
            Source::Remote(_) => None,
        }
    }
}

pub(super) struct Response {
    pub(super) origin: Origin,
    pub(super) cache_request_hash: [u8; 32],
    pub(super) public_scope: Option<LocalRefundReadyScopeV24>,
    pub(super) sweep: BuildSweepResponseV2,
    pub(super) context: Vec<u8>,
    pub(super) input_proof: Vec<u8>,
    pub(super) tx_key_proofs: Vec<Vec<u8>>,
    pub(super) ring_members: Vec<BuiltRingMemberV23>,
}
impl Response {
    pub(super) fn from_remote(r: RemoteResponse) -> Result<Self, SidecarOperationError> {
        r.validate_framing().map_err(|_| rejected())?;
        Ok(Self {
            cache_request_hash: [0; 32],
            public_scope: None,
            origin: Origin::AcceptedRemote {
                authorization_digest: r.authorization_digest,
                request_message_digest: r.request_message_digest,
            },
            sweep: r.sweep,
            context: r.context,
            input_proof: r.input_proof,
            tx_key_proofs: r.tx_key_proofs,
            ring_members: r.ring_members,
        })
    }
    pub(super) fn from_local(r: LocalResponse) -> Result<Self, SidecarOperationError> {
        r.validate_framing().map_err(|_| rejected())?;
        Ok(Self {
            cache_request_hash: r.cache_request_hash,
            public_scope: Some(r.public_scope),
            origin: Origin::LocalRefund {
                authorization_digest: r.local_authorization_digest,
                effect_id: r.effect_id,
                fencing_epoch: r.fencing_epoch,
                semantic_digest: r.semantic_digest,
                dom_refund_tx_hash: r.dom_refund_tx_hash,
                graph_digest: r.graph_digest,
            },
            sweep: r.sweep,
            context: r.context,
            input_proof: r.input_proof,
            tx_key_proofs: r.tx_key_proofs,
            ring_members: r.ring_members,
        })
    }
    pub(super) fn into_remote(self) -> Result<RemoteResponse, SidecarOperationError> {
        let Origin::AcceptedRemote {
            authorization_digest,
            request_message_digest,
        } = self.origin
        else {
            return Err(rejected());
        };
        Ok(RemoteResponse {
            api_version: 23,
            authorization_digest,
            request_message_digest,
            sweep: self.sweep,
            context: self.context,
            input_proof: self.input_proof,
            tx_key_proofs: self.tx_key_proofs,
            ring_members: self.ring_members,
        })
    }
    pub(super) fn into_local(self) -> Result<LocalResponse, SidecarOperationError> {
        let Origin::LocalRefund {
            authorization_digest,
            effect_id,
            fencing_epoch,
            semantic_digest,
            dom_refund_tx_hash,
            graph_digest,
        } = self.origin
        else {
            return Err(rejected());
        };
        Ok(LocalResponse {
            api_version: 24,
            cache_request_hash: self.cache_request_hash,
            public_scope: self.public_scope.ok_or_else(rejected)?,
            local_authorization_digest: authorization_digest,
            effect_id,
            fencing_epoch,
            semantic_digest,
            dom_refund_tx_hash,
            graph_digest,
            sweep: self.sweep,
            context: self.context,
            input_proof: self.input_proof,
            tx_key_proofs: self.tx_key_proofs,
            ring_members: self.ring_members,
        })
    }
    pub(super) fn validate_framing(&self) -> Result<InputSpendContextV23, SidecarOperationError> {
        if self.ring_members.len() != 16
            || self.tx_key_proofs.is_empty()
            || self.tx_key_proofs.len() > 17
        {
            return Err(rejected());
        }
        xmr_key_image_proof::InputSpendProofV23::decode(&self.input_proof)
            .map_err(|_| rejected())?;
        for proof in &self.tx_key_proofs {
            xmr_key_image_proof::TxKeyDerivationProofV23::decode(proof).map_err(|_| rejected())?;
        }
        let context = InputSpendContextV23::decode(&self.context).map_err(|_| rejected())?;
        if matches!(self.origin, Origin::LocalRefund { .. })
            && context.action != xmr_key_image_proof::InputSpendActionV23::Refund
        {
            return Err(rejected());
        }
        Ok(context)
    }
}
