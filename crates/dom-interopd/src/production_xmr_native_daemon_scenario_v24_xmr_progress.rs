//! Pure planning for the fixture's real, canonically linked synthetic blocks.
//! A plan grants no funding/claim authority and never marks a transaction final.
use super::*;

// GPL build_proof_v23 requires funding_height + 9 <= tip (10 confirmations).
// The unchanged fixture ledger/get_outs additionally keeps ordinary outputs
// locked until funding_height + 10. Respect BOTH, including the one-block
// difference; do not lower either rule or confuse height with confirmations.
const FUNDING_UNLOCK_OFFSET_V24: u64 = 10;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ProgressV24 {
    pub(super) target: u64,
    pub(super) include: Vec<[u8; 32]>,
}

pub(super) fn plan(
    tip: u64,
    confirmations: u64,
    pool: &[[u8; 32]],
    retained: &[([u8; 32], u64)],
    expected: &[(ActionKindV1, NativeActionV23)],
) -> Result<Option<ProgressV24>> {
    if confirmations == 0 || confirmations > 4096 {
        return Err("scenario XMR finality bound".into());
    }
    if pool.len() > 32
        || pool.iter().any(|hash| *hash == [0; 32])
        || pool.iter().copied().collect::<BTreeSet<_>>().len() != pool.len()
    {
        return Err("scenario XMR pool bound or duplicate identity".into());
    }
    let scope = |hash| {
        let mut funding = None;
        for (kind, action) in expected {
            if action.xmr_dispatched && action.matches_xmr(hash) {
                funding = Some(funding.unwrap_or(false) || *kind == ActionKindV1::Funding);
            }
        }
        funding
    };
    let required_tip = |inclusion: u64, funding: bool| -> Result<u64> {
        let finality = inclusion
            .checked_add(confirmations - 1)
            .ok_or("scenario XMR finality height overflow")?;
        Ok(if funding {
            finality.max(
                inclusion
                    .checked_add(FUNDING_UNLOCK_OFFSET_V24)
                    .ok_or("scenario XMR maturity height overflow")?,
            )
        } else {
            finality
        })
    };
    let mut target = tip;
    let mut include = Vec::new();
    for hash in pool {
        if let Some(funding) = scope(*hash) {
            // advance() places selected candidates in the FIRST new block,
            // not the current tip nor the final block of the requested span.
            let inclusion = tip.checked_add(1).ok_or("scenario XMR height overflow")?;
            target = target.max(required_tip(inclusion, funding)?);
            include.push(*hash);
        }
    }
    for (hash, inclusion) in retained {
        if let Some(funding) = scope(*hash) {
            if *inclusion == 0 || *inclusion > tip || pool.contains(hash) {
                return Err("scenario XMR retained inclusion contradiction".into());
            }
            target = target.max(required_tip(*inclusion, funding)?);
        }
    }
    Ok((target > tip).then_some(ProgressV24 { target, include }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dispatched(hash: [u8; 32], kind: ActionKindV1) -> (ActionKindV1, NativeActionV23) {
        (
            kind,
            NativeActionV23 {
                aggregate_id: [1; 32],
                xmr_id: super::super::super::coordinator::xmr_child_identity(hash),
                dom_id: [2; 32],
                xmr_dispatched: true,
                xmr_externalized: false,
                xmr_final: false,
            },
        )
    }

    #[test]
    fn scoped_funding_respects_negotiated_finality_and_native_unlock_v24() -> Result<()> {
        let hash = [7; 32];
        let expected = [dispatched(hash, ActionKindV1::Funding)];
        for (confirmations, target) in [(2, 211), (10, 211), (11, 211), (12, 212), (4096, 4296)] {
            assert_eq!(
                plan(200, confirmations, &[hash], &[], &expected)?,
                Some(ProgressV24 {
                    target,
                    include: vec![hash]
                })
            );
        }
        Ok(())
    }

    #[test]
    fn retained_funding_matures_with_empty_pool_at_exact_height_v24() -> Result<()> {
        let hash = [7; 32];
        let expected = [dispatched(hash, ActionKindV1::Funding)];
        // h=201: 10 confirmations at210 passes BUILD, but get_outs is locked.
        for tip in [202, 210] {
            assert_eq!(
                plan(tip, 2, &[], &[(hash, 201)], &expected)?,
                Some(ProgressV24 {
                    target: 211,
                    include: vec![]
                })
            );
        }
        assert_eq!(plan(211, 2, &[], &[(hash, 201)], &expected)?, None);
        assert_eq!(plan(212, 2, &[], &[(hash, 201)], &expected)?, None);
        Ok(())
    }

    #[test]
    fn unrelated_or_undispatched_pool_never_drives_inclusion_or_maturity_v24() -> Result<()> {
        let hash = [7; 32];
        assert_eq!(plan(200, 2, &[hash], &[], &[])?, None);
        assert_eq!(plan(202, 2, &[], &[(hash, 201)], &[])?, None);
        let mut undispatched = dispatched(hash, ActionKindV1::Funding);
        undispatched.1.xmr_dispatched = false;
        assert_eq!(plan(200, 2, &[hash], &[], &[undispatched])?, None);
        let expected = [dispatched(hash, ActionKindV1::Funding)];
        assert_eq!(
            plan(210, 2, &[[8; 32]], &[(hash, 201)], &expected)?,
            Some(ProgressV24 {
                target: 211,
                include: vec![]
            })
        );
        Ok(())
    }

    #[test]
    fn terminal_spends_use_finality_and_multiple_fundings_use_latest_maturity_v24() -> Result<()> {
        let a = [7; 32];
        let b = [8; 32];
        for kind in [ActionKindV1::Claim, ActionKindV1::Refund] {
            assert_eq!(
                plan(200, 2, &[a], &[], &[dispatched(a, kind)])?,
                Some(ProgressV24 {
                    target: 202,
                    include: vec![a]
                })
            );
        }
        let expected = [
            dispatched(a, ActionKindV1::Funding),
            dispatched(b, ActionKindV1::Funding),
        ];
        assert_eq!(
            plan(205, 2, &[], &[(a, 201), (b, 204)], &expected)?,
            Some(ProgressV24 {
                target: 214,
                include: vec![]
            })
        );
        assert_eq!(
            plan(205, 2, &[b], &[(a, 201)], &expected)?,
            Some(ProgressV24 {
                target: 216,
                include: vec![b]
            })
        );
        Ok(())
    }

    #[test]
    fn planner_refuses_overflow_invalid_finality_and_inconsistent_history_v24() {
        let hash = [7; 32];
        let expected = [dispatched(hash, ActionKindV1::Funding)];
        for confirmations in [0, 4097] {
            assert!(plan(200, confirmations, &[hash], &[], &expected).is_err());
        }
        for tip in [u64::MAX, u64::MAX - 1, u64::MAX - 10] {
            assert!(plan(tip, 2, &[hash], &[], &expected).is_err());
        }
        assert!(plan(u64::MAX - 1, 2, &[], &[(hash, u64::MAX - 2)], &expected).is_err());
        assert!(plan(200, 2, &[], &[(hash, 0)], &expected).is_err());
        assert!(plan(200, 2, &[], &[(hash, 201)], &expected).is_err());
        assert!(plan(200, 2, &[hash], &[(hash, 199)], &expected).is_err());
        assert!(plan(200, 2, &[hash, hash], &[], &expected).is_err());
        assert!(plan(200, 2, &[[0; 32]], &[], &expected).is_err());
        assert!(plan(200, 2, &[[8; 32]; 33], &[], &expected).is_err());
        let claim = [dispatched(hash, ActionKindV1::Claim)];
        assert!(plan(u64::MAX - 1, 2, &[hash], &[], &claim).is_err());
    }
}
