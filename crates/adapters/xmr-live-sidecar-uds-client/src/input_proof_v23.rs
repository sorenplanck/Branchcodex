//! Authenticated proof-only extension; no fallback to the V2 build operation.
use super::*;
use xmr_live_sidecar_api::{CachedInputProofRequestV23, InputSpendEnvelopeV23};

impl BlockingUdsSidecarPort {
    /// Request a public input-link proof for an exact sweep already cached by
    /// the sidecar. The returned envelope is NOT verified economic evidence;
    /// the caller must run the raw funding/sweep verifier and a separate payout
    /// verifier before assigning any operational meaning to it.
    pub fn prove_cached_input_v23(
        &mut self,
        mut request: CachedInputProofRequestV23<BuildSweepRequestV2>,
    ) -> Result<InputSpendEnvelopeV23, SpendPortError> {
        let expected = request
            .decoded_context()
            .map_err(|_| SpendPortError::Rejected)?;
        let nonce = request.build.request_nonce;
        self.auth_key
            .sign_input_proof_v23(&mut request)
            .map_err(|_| SpendPortError::Rejected)?;
        match self.call(&SidecarRequestV2::ProveInputV23(request))? {
            SidecarResponseV2::InputProofV23(response) => response
                .decode_for(nonce, &expected)
                .map_err(|_| SpendPortError::Rejected),
            SidecarResponseV2::Error(error) => Err(Self::classify_error(error)),
            _ => Err(SpendPortError::Rejected),
        }
    }
}
