//! Per-edge public key selection for native recovery signing. This does not
//! create a Store session, authorize a nonce, or replace bilateral agreement.
use super::*;

/// Require the *individual* keys of the selected edge, not merely their sum.
/// Store acceptance still supplies identity authentication and durable history.
pub(crate) fn require_roster(
    keys: &XmrGraphSigningKeysV22,
    templates: &XmrRecoveryGraphTemplatesV12,
    trusted: &TrustedChainIdV1,
    roster: &ParticipantRosterV1,
    kind: ProductionXmrRecoveryRoundKindV12,
) -> Result<()> {
    keys.require_graph(templates)
        .map_err(|_| ProductionXmrRoundErrorV12::Scope)?;
    let entries = roster.entries();
    if entries.len() != 2 {
        return Err(ProductionXmrRoundErrorV12::Scope);
    }
    keys.require_scope(
        trusted,
        templates.binding().session_id,
        templates.binding().terms_hash,
        [*entries[0].participant_id(), *entries[1].participant_id()],
        [entries[0].direction(), entries[1].direction()],
    )
    .map_err(|_| ProductionXmrRoundErrorV12::Scope)?;
    let stage = stage(kind);
    let hash = keys.template_hash(stage);
    require_selected_keys(roster, |participant| {
        keys.key(stage, participant, hash)
            .cloned()
            .map_err(|_| ProductionXmrRoundErrorV12::Scope)
    })
}

fn stage(kind: ProductionXmrRecoveryRoundKindV12) -> XmrGraphSigningStageV22 {
    match kind {
        ProductionXmrRecoveryRoundKindV12::Cancel => XmrGraphSigningStageV22::Cancel,
        ProductionXmrRecoveryRoundKindV12::RefundAdaptor => XmrGraphSigningStageV22::Refund,
        ProductionXmrRecoveryRoundKindV12::Compensation => XmrGraphSigningStageV22::Compensation,
    }
}

fn require_selected_keys(
    roster: &ParticipantRosterV1,
    mut key: impl FnMut([u8; 32]) -> Result<PublicKey>,
) -> Result<()> {
    if roster.entries().len() != 2 {
        return Err(ProductionXmrRoundErrorV12::Scope);
    }
    for participant in roster.entries() {
        if participant.signing_public_key() != &key(*participant.participant_id())? {
            return Err(ProductionXmrRoundErrorV12::Scope);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_adaptor::{DirectionV1, ParticipantIdentityV1};
    use dom_crypto::SecretKey;

    // This fixture tests public selection only; it grants no signing authority
    // and deliberately creates neither Store journals nor signatures/nonces.
    #[test]
    fn recovery_roster_rejects_cross_edge_and_cross_participant_keys(
    ) -> core::result::Result<(), Box<dyn std::error::Error>> {
        let chain = TrustedChainIdV1::from_authenticated_genesis(
            0x4455_6677,
            &dom_core::Hash256::from_bytes([0x91; 32]),
        );
        let identities =
            [61u8, 62].map(|byte| SecretKey::from_bytes(&[byte; 32]).unwrap().public_key());
        let keys = [0u8, 1].map(|participant| {
            [0u8, 1, 2].map(|edge| {
                SecretKey::from_bytes(&[10 + participant * 10 + edge; 32])
                    .unwrap()
                    .public_key()
            })
        });
        for selected in 0..3 {
            let mut entries = (0..2)
                .map(|index| {
                    ParticipantIdentityV1::new(
                        &chain,
                        identities[index].clone(),
                        keys[index][selected].clone(),
                        if index == 0 {
                            DirectionV1::Initiator
                        } else {
                            DirectionV1::Responder
                        },
                    )
                })
                .collect::<core::result::Result<Vec<_>, _>>()?;
            let ids = [*entries[0].participant_id(), *entries[1].participant_id()];
            entries.sort_by_key(|entry| *entry.participant_id());
            let roster = ParticipantRosterV1::new(entries)?;
            for offered in 0..3 {
                let result = require_selected_keys(&roster, |id| {
                    let participant = ids
                        .iter()
                        .position(|expected| *expected == id)
                        .ok_or(ProductionXmrRoundErrorV12::Scope)?;
                    Ok(keys[participant][offered].clone())
                });
                assert_eq!(result.is_ok(), selected == offered);
            }
            assert!(require_selected_keys(&roster, |id| {
                let participant = ids
                    .iter()
                    .position(|expected| *expected == id)
                    .ok_or(ProductionXmrRoundErrorV12::Scope)?;
                Ok(keys[participant ^ 1][selected].clone())
            })
            .is_err());
            assert!(
                require_selected_keys(&roster, |_| Err(ProductionXmrRoundErrorV12::Scope)).is_err()
            );
        }
        assert_eq!(
            stage(ProductionXmrRecoveryRoundKindV12::Cancel),
            XmrGraphSigningStageV22::Cancel
        );
        assert_eq!(
            stage(ProductionXmrRecoveryRoundKindV12::RefundAdaptor),
            XmrGraphSigningStageV22::Refund
        );
        assert_eq!(
            stage(ProductionXmrRecoveryRoundKindV12::Compensation),
            XmrGraphSigningStageV22::Compensation
        );
        Ok(())
    }
}
