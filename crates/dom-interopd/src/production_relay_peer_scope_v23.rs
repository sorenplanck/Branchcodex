//! Authenticated scope gate for the explicit V23 shared-remote-Relay mode.
//!
//! A Relay database is not a participant identity or the delivery scope: V3
//! delivery and Noise frames bind the recipient, route and session separately.
//! Two legs may therefore use one remote database only when the retained
//! Contracts owners authenticate the same local and remote identities and two
//! distinct sessions. This gate does not authenticate a live peer: each Noise
//! handshake must still prove possession of its pinned key and database ID.
//!
//! Legacy V1 network configuration and V10 manifests remain strict. The
//! composition root must require the explicit V23 opt-in in both V11 manifest
//! and V2 network sidecar before using this authorization, and apply it before
//! constructing either network session. No remote ID is generated here.

use dom_scriptless_store::SessionTransportIdentityReferenceV1;
use relay::production::RelayDatabaseIdV1;
use route_executor::LegIdV1;
use route_transport::RouteWireContextV1;

use crate::production_relay_stage12::ProductionRelayStage12OwnerV1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProductionRelayPeerScopeErrorV23 {
    #[error("shared Relay peer does not match the authenticated route scopes")]
    InvalidBinding,
}

#[derive(Clone, Eq, PartialEq)]
struct RetainedLegScopeV23 {
    chain_id: [u8; 32],
    wire: RouteWireContextV1,
    identities: [SessionTransportIdentityReferenceV1; 2],
}

impl RetainedLegScopeV23 {
    fn capture(owner: &ProductionRelayStage12OwnerV1, leg: LegIdV1) -> Self {
        let leg = owner.leg(leg);
        Self {
            chain_id: *leg.trusted_chain_id().as_bytes(),
            wire: leg.wire(),
            identities: leg.noise_identity_references().clone(),
        }
    }

    fn valid(&self) -> bool {
        let [local, remote] = &self.identities;
        self.chain_id != [0; 32]
            && self.wire.network_id != [0; 32]
            && self.wire.route_id != [0; 32]
            && self.wire.session_id != [0; 32]
            && self.wire.roster_snapshot != [0; 32]
            && self.wire.policy_version != 0
            && local.participant_id() != remote.participant_id()
            && local.key_reference() != remote.key_reference()
            && local.noise_public_key() != remote.noise_public_key()
    }
}

/// Process-local authorization derived only from the actual Stage-12 owner.
///
/// There is no public constructor from raw references, codec, Clone or Debug.
/// Identity references contain participant, key reference, Noise and Schnorr
/// public keys, but no session ID, so exact equality across sessions is both
/// possible and required. Keeping the complete per-leg context additionally
/// prevents transplanting authorization to a new session, roster or policy.
/// Reopening identical authenticated durable facts is valid; raw pointer
/// identity is deliberately not treated as an authentication boundary.
#[must_use]
pub(crate) struct ProductionSharedRelayPeerScopeV23 {
    local_database: RelayDatabaseIdV1,
    remote_databases: [RelayDatabaseIdV1; 2],
    scopes: [RetainedLegScopeV23; 2],
}

impl ProductionSharedRelayPeerScopeV23 {
    pub(crate) fn authenticate(
        owner: &ProductionRelayStage12OwnerV1,
        remote_databases: [RelayDatabaseIdV1; 2],
    ) -> Result<Self, ProductionRelayPeerScopeErrorV23> {
        let local_database = owner.relay().database_id();
        let scopes = [
            RetainedLegScopeV23::capture(owner, LegIdV1::Upstream),
            RetainedLegScopeV23::capture(owner, LegIdV1::Downstream),
        ];
        validate_scopes(local_database, remote_databases, &scopes)?;
        Ok(Self {
            local_database,
            remote_databases,
            scopes,
        })
    }

    /// Revalidate immediately against the owner used to derive Noise sessions.
    pub(crate) fn validate_owner(
        &self,
        owner: &ProductionRelayStage12OwnerV1,
        remote_databases: [RelayDatabaseIdV1; 2],
    ) -> Result<(), ProductionRelayPeerScopeErrorV23> {
        let scopes = [
            RetainedLegScopeV23::capture(owner, LegIdV1::Upstream),
            RetainedLegScopeV23::capture(owner, LegIdV1::Downstream),
        ];
        self.validate_retained(owner.relay().database_id(), remote_databases, &scopes)
    }

    fn validate_retained(
        &self,
        local_database: RelayDatabaseIdV1,
        remote_databases: [RelayDatabaseIdV1; 2],
        scopes: &[RetainedLegScopeV23; 2],
    ) -> Result<(), ProductionRelayPeerScopeErrorV23> {
        if self.local_database != local_database
            || self.remote_databases != remote_databases
            || &self.scopes != scopes
        {
            return Err(ProductionRelayPeerScopeErrorV23::InvalidBinding);
        }
        validate_scopes(local_database, remote_databases, scopes)
    }
}

fn validate_scopes(
    local_database: RelayDatabaseIdV1,
    remote_databases: [RelayDatabaseIdV1; 2],
    scopes: &[RetainedLegScopeV23; 2],
) -> Result<(), ProductionRelayPeerScopeErrorV23> {
    let [upstream, downstream] = scopes;
    if remote_databases[0] != remote_databases[1]
        || local_database == remote_databases[0]
        || !upstream.valid()
        || !downstream.valid()
        || upstream.chain_id != downstream.chain_id
        || upstream.wire.network_id != downstream.wire.network_id
        || upstream.wire.route_id != downstream.wire.route_id
        || upstream.wire.session_id == downstream.wire.session_id
        || upstream.identities != downstream.identities
    {
        return Err(ProductionRelayPeerScopeErrorV23::InvalidBinding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_crypto::SecretKey;

    fn database(value: u8) -> RelayDatabaseIdV1 {
        RelayDatabaseIdV1::new([value; 32]).expect("nonzero database")
    }

    fn identity(values: [u8; 4]) -> SessionTransportIdentityReferenceV1 {
        SessionTransportIdentityReferenceV1::new(
            [values[0]; 32],
            [values[1]; 32],
            [values[2]; 32],
            SecretKey::from_bytes(&[values[3]; 32])
                .expect("test signing key")
                .public_key(),
        )
        .expect("nonzero identity")
    }

    fn scopes() -> [RetainedLegScopeV23; 2] {
        let upstream = RetainedLegScopeV23 {
            chain_id: [1; 32],
            wire: RouteWireContextV1 {
                network_id: [2; 32],
                session_id: [3; 32],
                route_id: [4; 32],
                roster_snapshot: [5; 32],
                policy_version: 1,
            },
            identities: [identity([11, 12, 13, 14]), identity([21, 22, 23, 24])],
        };
        let mut downstream = upstream.clone();
        downstream.wire.session_id = [6; 32];
        downstream.wire.roster_snapshot = [7; 32];
        [upstream, downstream]
    }

    #[test]
    fn shared_peer_requires_two_distinct_authenticated_scopes() {
        let scopes = scopes();
        assert!(validate_scopes(database(1), [database(2); 2], &scopes).is_ok());
        assert!(validate_scopes(database(1), [database(1); 2], &scopes).is_err());
        assert!(validate_scopes(database(1), [database(2), database(3)], &scopes).is_err());
        let mut aliased = scopes.clone();
        aliased[1].wire.session_id = aliased[0].wire.session_id;
        assert!(validate_scopes(database(1), [database(2); 2], &aliased).is_err());
        for component in 0..3 {
            let mut changed = scopes.clone();
            match component {
                0 => changed[1].chain_id = [99; 32],
                1 => changed[1].wire.network_id = [99; 32],
                _ => changed[1].wire.route_id = [99; 32],
            }
            assert!(validate_scopes(database(1), [database(2); 2], &changed).is_err());
        }
    }

    #[test]
    fn every_local_and_remote_identity_component_must_match_across_legs() {
        for identity_index in 0..2 {
            for component in 0..4 {
                let mut scopes = scopes();
                let mut values = if identity_index == 0 {
                    [11, 12, 13, 14]
                } else {
                    [21, 22, 23, 24]
                };
                values[component] = 31;
                scopes[1].identities[identity_index] = identity(values);
                assert!(validate_scopes(database(1), [database(2); 2], &scopes).is_err());
            }
        }
        let mut scopes = scopes();
        for scope in &mut scopes {
            scope.identities[1] = scope.identities[0].clone();
        }
        assert!(validate_scopes(database(1), [database(2); 2], &scopes).is_err());
    }

    #[test]
    fn shared_peer_refuses_zero_wire_bindings() {
        for leg in 0..2 {
            for component in 0..6 {
                let mut scopes = scopes();
                match component {
                    0 => scopes[leg].chain_id = [0; 32],
                    1 => scopes[leg].wire.network_id = [0; 32],
                    2 => scopes[leg].wire.route_id = [0; 32],
                    3 => scopes[leg].wire.session_id = [0; 32],
                    4 => scopes[leg].wire.roster_snapshot = [0; 32],
                    _ => scopes[leg].wire.policy_version = 0,
                }
                assert!(validate_scopes(database(1), [database(2); 2], &scopes).is_err());
            }
        }
    }

    #[test]
    fn retained_authorization_cannot_be_transplanted_to_another_binding() {
        let scopes = scopes();
        // Only this private regression can construct raw retained facts; the
        // production constructor accepts the authenticated Stage-12 owner.
        let authorization = ProductionSharedRelayPeerScopeV23 {
            local_database: database(1),
            remote_databases: [database(2); 2],
            scopes: scopes.clone(),
        };
        assert!(authorization
            .validate_retained(database(1), [database(2); 2], &scopes)
            .is_ok());
        assert!(authorization
            .validate_retained(database(3), [database(2); 2], &scopes)
            .is_err());
        assert!(authorization
            .validate_retained(database(1), [database(3); 2], &scopes)
            .is_err());
        for component in 0..3 {
            let mut changed = scopes.clone();
            match component {
                0 => changed[1].wire.session_id = [99; 32],
                1 => changed[1].wire.roster_snapshot = [99; 32],
                _ => changed[1].wire.policy_version = 2,
            }
            // A separately authorized route with these facts would be valid,
            // but this authorization must not be reusable for it.
            assert!(validate_scopes(database(1), [database(2); 2], &changed).is_ok());
            assert!(authorization
                .validate_retained(database(1), [database(2); 2], &changed)
                .is_err());
        }
    }
}
