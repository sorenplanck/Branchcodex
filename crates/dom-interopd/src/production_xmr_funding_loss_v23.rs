//! Loss of a previously final external funding observation must invalidate
//! coordinator finality, not merely leave the old final child as Pending.
use super::*;

const DOMAIN: &[u8] = b"DOM-INTEROP/INTEROPD/XMR-CHILD/FUNDING-FINALITY-LOSS/V23\0";

fn loss_digest(
    tx_hash: Digest32,
    minimum: u64,
    observed: Option<xmr_actuator::XmrTxInclusionV1>,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    if tx_hash == ZERO_DIGEST || minimum == 0 {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    match observed {
        Some(inclusion) => {
            if inclusion.block_hash == ZERO_DIGEST
                || inclusion.confirmations == 0
                || inclusion.confirmations >= minimum
            {
                return Err(ChildAuthorityRefusalV1::Conflict);
            }
            digest_parts(
                DOMAIN,
                &[
                    &tx_hash,
                    &minimum.to_be_bytes(),
                    &[1],
                    &inclusion.height.to_be_bytes(),
                    &inclusion.block_hash,
                    &inclusion.confirmations.to_be_bytes(),
                ],
            )
        }
        None => digest_parts(DOMAIN, &[&tx_hash, &minimum.to_be_bytes(), &[0]]),
    }
}

pub(super) fn pending_or_invalidated(
    binding: &ChildObservationEvidenceBindingV1,
    prior: Option<Digest32>,
    tx_hash: Digest32,
    minimum: u64,
    observed: Option<xmr_actuator::XmrTxInclusionV1>,
) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
    let invalidation = loss_digest(tx_hash, minimum, observed)?;
    match prior {
        Some(prior) => Ok(ChildObservationOutcomeV1::FinalityInvalidated {
            prior_finality_evidence_digest: prior,
            reorg_evidence_digest: observation_reorg_evidence_v1(binding, prior, invalidation)
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
        }),
        None => Ok(ChildObservationOutcomeV1::Pending {
            evidence_digest: observation_pending_evidence_v1(binding)
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loss_is_scoped_and_cannot_be_fabricated_from_a_final_inclusion() {
        let shallow = xmr_actuator::XmrTxInclusionV1 {
            height: 100,
            block_hash: [2; 32],
            confirmations: 9,
        };
        assert_ne!(
            loss_digest([1; 32], 10, None),
            loss_digest([1; 32], 10, Some(shallow))
        );
        assert_ne!(
            loss_digest([1; 32], 10, None),
            loss_digest([3; 32], 10, None)
        );
        assert_ne!(
            loss_digest([1; 32], 10, None),
            loss_digest([1; 32], 11, None)
        );
        assert!(loss_digest(
            [1; 32],
            10,
            Some(xmr_actuator::XmrTxInclusionV1 {
                confirmations: 10,
                ..shallow
            })
        )
        .is_err());
        assert!(loss_digest(
            [1; 32],
            10,
            Some(xmr_actuator::XmrTxInclusionV1 {
                block_hash: [0; 32],
                ..shallow
            })
        )
        .is_err());
        assert!(loss_digest([1; 32], 0, None).is_err());
        assert!(loss_digest([0; 32], 10, None).is_err());
    }
}
