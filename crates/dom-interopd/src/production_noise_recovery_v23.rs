//! Bounded readiness negotiation for the two authenticated recovery sessions.
use super::*;

impl ProductionNoiseRelaySessionV1 {
    /// Callers obtain these children only from the Store-authenticated Stage12
    /// auxiliary owners. Network negotiation never creates signing authority.
    pub(crate) fn with_xmr_recovery_v23(
        mut self,
        children: [Self; 2],
    ) -> Result<Self, ProductionNoiseRelayErrorV1> {
        let cancelled = self
            .cancelled_v22
            .as_ref()
            .ok_or(ProductionNoiseRelayErrorV1::InvalidConfiguration)?;
        if self.graph_v22.is_none()
            || self.recovery_v23.is_some()
            || children[0].session_id == children[1].session_id
        {
            return Err(ProductionNoiseRelayErrorV1::InvalidConfiguration);
        }
        for child in &children {
            if child.session_id == self.session_id
                || child.session_id == cancelled.session_id
                || child.cancelled_v22.is_some()
                || child.graph_v22.is_some()
                || child.recovery_v23.is_some()
                || child.role != self.role
                || child.chain_id != self.chain_id
                || child.network_id != self.network_id
                || child.route_id != self.route_id
                || child.local_reference != self.local_reference
                || child.remote_reference != self.remote_reference
                || child.expected_local_relay != self.expected_local_relay
                || child.expected_remote_relay != self.expected_remote_relay
                || child.exchange_timeout != self.exchange_timeout
            {
                return Err(ProductionNoiseRelayErrorV1::InvalidConfiguration);
            }
        }
        self.recovery_v23 = Some(Box::new(children));
        Ok(self)
    }

    pub(super) fn exchange_recovery_scopes_v23(
        &self,
        transport: &mut EncryptedTransportV1<DeadlineTcpStreamV1>,
    ) -> Result<bool, ProductionNoiseRelayErrorV1> {
        let mut local = [0u8; 64];
        if let Some(children) = &self.recovery_v23 {
            local[..32].copy_from_slice(&children[0].session_id);
            local[32..].copy_from_slice(&children[1].session_id);
        }
        let receive = |transport: &mut EncryptedTransportV1<DeadlineTcpStreamV1>| {
            let bytes = self.receive_frame_bytes(transport)?;
            let frame = self.decode_remote_frame(&bytes)?;
            if frame.kind == FrameKindV1::Refused {
                return Err(ProductionNoiseRelayErrorV1::PeerRefused);
            }
            if frame.kind != FrameKindV1::RecoveryScopesV23 {
                return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
            }
            negotiate_recovery_scopes_v23(&local, frame.body)
        };
        match self.role {
            NoiseRoleV1::Initiator => {
                self.send_frame(transport, FrameKindV1::RecoveryScopesV23, &local)?;
                receive(transport)
            }
            NoiseRoleV1::Responder => {
                let ready = receive(transport)?;
                self.send_frame(transport, FrameKindV1::RecoveryScopesV23, &local)?;
                Ok(ready)
            }
        }
    }
}

fn negotiate_recovery_scopes_v23(
    local: &[u8; 64],
    remote: &[u8],
) -> Result<bool, ProductionNoiseRelayErrorV1> {
    if remote.len() != 64 {
        return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
    }
    let absent = |pair: &[u8]| pair.iter().all(|byte| *byte == 0);
    let valid = |pair: &[u8]| {
        absent(pair) || (!absent(&pair[..32]) && !absent(&pair[32..]) && pair[..32] != pair[32..])
    };
    if !valid(local) || !valid(remote) {
        return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
    }
    // An unready side never accepts the advertised scope as authority. It
    // continues C/D progress and derives its own sessions before comparison.
    if absent(local) || absent(remote) {
        return Ok(false);
    }
    if local != remote {
        return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_never_authorizes_foreign_or_partial_scopes() {
        let mut pair = [3u8; 64];
        pair[32..].fill(7);
        assert_eq!(negotiate_recovery_scopes_v23(&pair, &pair), Ok(true));
        assert_eq!(negotiate_recovery_scopes_v23(&pair, &[0; 64]), Ok(false));
        assert_eq!(negotiate_recovery_scopes_v23(&[0; 64], &pair), Ok(false));
        for length in 0..64 {
            assert!(negotiate_recovery_scopes_v23(&pair, &pair[..length]).is_err());
        }
        for index in 0..64 {
            let mut foreign = pair;
            foreign[index] ^= 1;
            assert!(negotiate_recovery_scopes_v23(&pair, &foreign).is_err());
        }
        let mut partial = pair;
        partial[..32].fill(0);
        assert!(negotiate_recovery_scopes_v23(&[0; 64], &partial).is_err());
        assert!(negotiate_recovery_scopes_v23(&[0; 64], &[3; 64]).is_err());
        assert!(negotiate_recovery_scopes_v23(&pair, &[3; 65]).is_err());
    }
}
