//! Exact capability negotiation before any graph offer or durable Relay page.
use super::*;

pub(super) fn hello_body_v22(
    cancelled: Option<&[u8; 32]>,
    graph: bool,
) -> Result<Vec<u8>, ProductionNoiseRelayErrorV1> {
    if graph && cancelled.is_none() {
        return Err(ProductionNoiseRelayErrorV1::InvalidConfiguration);
    }
    let mut body = Vec::with_capacity(HELLO_BODY_LEN_V1 + 36);
    body.extend_from_slice(&NETWORK_PAGE_MAX_ITEMS_V1.to_be_bytes());
    body.extend_from_slice(&NETWORK_PAGE_MAX_BYTES_V1.to_be_bytes());
    body.extend_from_slice(&NETWORK_MAX_PAGES_PER_DIRECTION_V1.to_be_bytes());
    if let Some(scope) = cancelled {
        body.extend_from_slice(scope);
    }
    if graph {
        body.extend_from_slice(b"XGO2");
    }
    Ok(body)
}

pub(super) fn verify_hello_body_v22(
    body: &[u8],
    cancelled: Option<&[u8; 32]>,
    graph: bool,
) -> Result<(), ProductionNoiseRelayErrorV1> {
    // All negotiated parameters are fixed and canonical. Exact comparison
    // rejects missing/extra capabilities, foreign D scopes and altered limits.
    if body != hello_body_v22(cancelled, graph)? {
        return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_v22_requires_exact_capabilities_scope_and_limits() {
        let d = [0x73; 32];
        let modes = [(None, false), (Some(&d), false), (Some(&d), true)];
        for (sender, &(scope, graph)) in modes.iter().enumerate() {
            let body = hello_body_v22(scope, graph).unwrap();
            assert_eq!(body.len(), [8, 40, 44][sender]);
            for (receiver, &(expected_scope, expected_graph)) in modes.iter().enumerate() {
                assert_eq!(
                    verify_hello_body_v22(&body, expected_scope, expected_graph).is_ok(),
                    sender == receiver,
                    "capability mismatch must never downgrade"
                );
            }
            for index in 0..body.len() {
                let mut mutated = body.clone();
                mutated[index] ^= 1;
                assert_eq!(
                    verify_hello_body_v22(&mutated, scope, graph),
                    Err(ProductionNoiseRelayErrorV1::ProtocolRefused)
                );
            }
            for length in 0..body.len() {
                assert!(verify_hello_body_v22(&body[..length], scope, graph).is_err());
            }
            let mut trailing = body;
            trailing.push(0);
            assert!(verify_hello_body_v22(&trailing, scope, graph).is_err());
        }
        assert_eq!(
            hello_body_v22(None, true),
            Err(ProductionNoiseRelayErrorV1::InvalidConfiguration)
        );
        let foreign = [0x74; 32];
        let body = hello_body_v22(Some(&d), true).unwrap();
        assert!(verify_hello_body_v22(&body, Some(&foreign), true).is_err());
    }
}
