//! Order-independent bounded quorum over corroborated per-daemon observations.
//! Endpoints are configured trust assumptions, not cryptographic independence.
use xmr_actuator::{XmrActuatorErrorV1, XmrTxInclusionV1};
use xmr_rpc_broadcast_blocking::MoneroTransactionObservationV5 as Vote;
use xmr_spend_port::SpendPortError;

#[cfg(test)]
#[path = "tests/xmr_quorum_v8.rs"]
mod transport_tests;

/// Preserve a hard contradiction through the quorum boundary. A malformed
/// or substituted response is never a missing vote, even with a majority.
pub(crate) fn collect_checked_votes_v8<T>(
    votes: Vec<Result<T, SpendPortError>>,
) -> Result<Vec<Option<T>>, XmrActuatorErrorV1> {
    votes
        .into_iter()
        .map(|vote| match vote {
            Ok(value) => Ok(Some(value)),
            Err(SpendPortError::Retryable) => Ok(None),
            Err(SpendPortError::Rejected) => Err(XmrActuatorErrorV1::Conflict),
        })
        .collect()
}

pub(crate) fn valid_quorum_v5(nodes: usize, quorum: usize) -> bool {
    nodes > 0 && nodes <= 16 && quorum > nodes / 2 && quorum <= nodes
}

/// Every configured node contributes one slot, including failed observations.
/// Unavailable nodes never lower the denominator or become absence votes.
pub(crate) fn decide_inclusion_v5(
    votes: &[Option<Vote>],
    quorum: usize,
) -> Result<Option<XmrTxInclusionV1>, XmrActuatorErrorV1> {
    if !valid_quorum_v5(votes.len(), quorum) {
        return Err(XmrActuatorErrorV1::ObservationUnavailable);
    }
    let absent = votes
        .iter()
        .filter(|vote| matches!(vote, Some(Vote::Absent)))
        .count();
    if absent >= quorum {
        return Ok(None);
    }
    let mut groups: Vec<(u64, [u8; 32], u64, usize)> = Vec::new();
    for vote in votes {
        if let Some(Vote::Included {
            height,
            block_hash,
            chain_length,
        }) = vote
        {
            if *block_hash == [0; 32] || chain_length <= height {
                continue;
            }
            if let Some(group) = groups
                .iter_mut()
                .find(|g| g.0 == *height && g.1 == *block_hash)
            {
                group.2 = group.2.min(*chain_length);
                group.3 += 1;
            } else {
                groups.push((*height, *block_hash, *chain_length, 1));
            }
        }
    }
    let winners: Vec<_> = groups.iter().filter(|group| group.3 >= quorum).collect();
    match winners.as_slice() {
        [winner] => Ok(Some(XmrTxInclusionV1 {
            height: winner.0,
            block_hash: winner.1,
            // get_height is a block count; height is zero-based. A tx in the
            // tip has exactly one confirmation, not two.
            confirmations: winner.2 - winner.0,
        })),
        _ => Err(XmrActuatorErrorV1::ObservationUnavailable),
    }
}

pub(crate) fn decide_key_image_v5(
    votes: &[Option<bool>],
    quorum: usize,
) -> Result<bool, XmrActuatorErrorV1> {
    if !valid_quorum_v5(votes.len(), quorum) {
        return Err(XmrActuatorErrorV1::ObservationUnavailable);
    }
    if votes.contains(&Some(true)) {
        return Ok(true);
    }
    if votes.iter().filter(|vote| **vote == Some(false)).count() >= quorum {
        return Ok(false);
    }
    Err(XmrActuatorErrorV1::ObservationUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn v8_hard_rejection_cannot_be_hidden_by_absence_majority() {
        for index in 0..3 {
            let mut votes = vec![Ok(Vote::Absent), Ok(Vote::Absent), Ok(Vote::Absent)];
            votes[index] = Err(SpendPortError::Rejected);
            assert!(matches!(
                collect_checked_votes_v8(votes),
                Err(XmrActuatorErrorV1::Conflict)
            ));
        }
    }
    #[test]
    fn v8_timeout_stays_missing_and_legitimate_absence_stays_absent() {
        let votes = collect_checked_votes_v8(vec![
            Ok(Vote::Absent),
            Err(SpendPortError::Retryable),
            Ok(Vote::Absent),
        ])
        .unwrap();
        assert!(matches!(decide_inclusion_v5(&votes, 2), Ok(None)));
        let votes = collect_checked_votes_v8(vec![
            Ok(Vote::Absent),
            Err(SpendPortError::Retryable),
            Err(SpendPortError::Retryable),
        ])
        .unwrap();
        assert!(matches!(
            decide_inclusion_v5(&votes, 2),
            Err(XmrActuatorErrorV1::ObservationUnavailable)
        ));
    }
    #[test]
    fn v8_rejected_key_image_response_is_not_unspent() {
        assert!(matches!(
            collect_checked_votes_v8(vec![Ok(false), Err(SpendPortError::Rejected), Ok(false)]),
            Err(XmrActuatorErrorV1::Conflict)
        ));
    }
    fn included(hash: u8, length: u64) -> Option<Vote> {
        Some(Vote::Included {
            height: 100,
            block_hash: [hash; 32],
            chain_length: length,
        })
    }
    #[test]
    fn every_outlier_position_accepts_the_agreeing_majority() {
        for first in 0..3 {
            let mut votes = [included(1, 105), included(1, 105), included(1, 105)];
            votes[first] = included(2, 999);
            let result = decide_inclusion_v5(&votes, 2)
                .expect("majority")
                .expect("included");
            assert_eq!(
                (result.height, result.block_hash, result.confirmations),
                (100, [1; 32], 5)
            );
        }
    }
    #[test]
    fn tip_has_one_confirmation_and_slow_agreeing_voter_limits_depth() {
        let result = decide_inclusion_v5(&[included(1, 110), included(1, 101), None], 2)
            .expect("majority")
            .expect("inclusion");
        assert_eq!(result.confirmations, 1);
    }
    #[test]
    fn absences_pool_errors_and_forks_remain_distinct() {
        assert!(matches!(
            decide_inclusion_v5(&[Some(Vote::Absent), None, Some(Vote::Absent)], 2),
            Ok(None)
        ));
        for votes in [
            [Some(Vote::InPool), Some(Vote::InPool), None],
            [Some(Vote::Absent), None, None],
            [included(1, 101), included(2, 101), None],
            [included(0, 101), included(0, 101), None],
            [included(1, 100), included(1, 100), None],
        ] {
            assert!(decide_inclusion_v5(&votes, 2).is_err());
        }
    }
    #[test]
    fn neither_failure_nor_quorum_configuration_can_create_a_smaller_majority() {
        for (nodes, quorum) in [(0, 0), (3, 1), (4, 2), (2, 3), (17, 9)] {
            assert!(!valid_quorum_v5(nodes, quorum));
        }
        assert!(decide_inclusion_v5(&[included(1, 101), None, None], 2).is_err());
        assert!(decide_inclusion_v5(&[included(1, 101), included(2, 101)], 1).is_err());
    }
    #[test]
    fn any_verified_spent_vetoes_unspent_and_errors_are_not_unspent() {
        assert_eq!(
            decide_key_image_v5(&[Some(false), Some(true), Some(false)], 2).expect("spent"),
            true
        );
        assert_eq!(
            decide_key_image_v5(&[Some(false), None, Some(false)], 2).expect("unspent"),
            false
        );
        assert!(decide_key_image_v5(&[Some(false), None, None], 2).is_err());
    }
}
