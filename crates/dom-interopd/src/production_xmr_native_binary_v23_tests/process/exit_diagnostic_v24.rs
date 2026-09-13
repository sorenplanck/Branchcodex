//! Test-process diagnostics, never authority or a raw output forwarding path.
//! Only complete, exact public ProductionRunErrorV1 display lines are known.
//! Dynamic configuration detail, user strings and partial matches stay unknown.
const PUBLIC: &[(&str, &str)] = &[
    ("production artifact is not operational", "artifact"),
    ("production signal authority unavailable", "signal"),
    ("production secrets unavailable", "secrets_unavailable"),
    ("production configuration refused", "configuration"),
    (
        "production Relay network configuration refused",
        "relay_configuration",
    ),
    ("production inputs refused", "inputs"),
    (
        "production route journal violates external-custody-only policy",
        "route_journal_policy",
    ),
    (
        "production state directory capability unavailable",
        "state_directory",
    ),
    (
        "production route-secret vault unavailable",
        "route_secret_vault",
    ),
    (
        "production settlement coordinator unavailable",
        "coordinator",
    ),
    ("production DOM actuator store unavailable", "dom_actuator"),
    ("production EVM actuator store unavailable", "evm_actuator"),
    (
        "production Bitcoin actuator store unavailable",
        "bitcoin_actuator",
    ),
    (
        "production chain signer authorities unavailable",
        "chain_signers",
    ),
    (
        "production local EVM signer authority unavailable",
        "evm_signer",
    ),
    ("production DOM node authority unavailable", "dom_node"),
    (
        "production counterparty chain services unavailable",
        "chain_services",
    ),
    (
        "production route admitted but execution authority graph is incomplete",
        "execution_graph",
    ),
    (
        "production XMR compensated funding authority unavailable",
        "xmr_funding",
    ),
    (
        "production EVM escrow codehash diverges from the registry",
        "evm_codehash",
    ),
    (
        "production solver inventory store unavailable",
        "solver_inventory",
    ),
    ("production Contracts stores unavailable", "contracts"),
    ("production F6 authorities unavailable", "f6"),
    (
        "production Relay/Contracts authorities unavailable",
        "relay_contracts",
    ),
    (
        "production refund-arming authority unavailable",
        "refund_arming",
    ),
    (
        "production deadline timer authority unavailable",
        "deadline_timer",
    ),
    (
        "production settlement child authority unavailable",
        "settlement_child",
    ),
    (
        "production provisioning journal unavailable",
        "provisioning",
    ),
    ("production host clock is unusable", "host_clock"),
    (
        "production Bitcoin child authority unavailable",
        "bitcoin_child",
    ),
    (
        "production settlement plan source unavailable",
        "plan_source",
    ),
    ("production composite relay loop failed", "composite_loop"),
    (
        "production route supervisor unavailable",
        "route_supervisor",
    ),
    ("production route runtime failed", "route_runtime"),
];

fn composite_line_v25(line: &[u8]) -> Option<crate::production_run::ProductionCompositeFailureV25> {
    let detail = line.strip_prefix(b"production composite relay loop failed: ")?;
    crate::production_run::ProductionCompositeFailureV25::classify_exact_display_v25(detail)
}

pub(super) fn classify(bytes: &[u8]) -> &'static str {
    if bytes.len() > super::MAX_CAPTURE {
        return "unknown";
    }
    let mut found = None;
    for line in bytes.split(|byte| *byte == b'\n') {
        if composite_line_v25(line).is_some() {
            if found.is_some() {
                return "multiple_public_errors";
            }
            found = Some("composite_loop");
        }
        for (message, code) in PUBLIC {
            if line == message.as_bytes() {
                if found.is_some() {
                    return "multiple_public_errors";
                }
                found = Some(*code);
            }
        }
    }
    found.unwrap_or("unknown")
}

/// Return only a closed typed diagnostic from a unique recognized error line.
/// The source buffer, dynamic errors and partial matches never leave this module.
pub(super) fn composite_detail_v25(
    bytes: &[u8],
) -> Option<crate::production_run::ProductionCompositeFailureV25> {
    if classify(bytes) != "composite_loop" {
        return None;
    }
    bytes
        .split(|byte| *byte == b'\n')
        .find_map(composite_line_v25)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn composite_message_v25() -> String {
        let failure =
            crate::production_composite_loop::ProductionCompositeLoopErrorV1::InvalidConfiguration
                .failure_v25();
        crate::production_run::ProductionRunErrorV1::CompositeLoopDetail(failure).to_string()
    }

    #[test]
    fn composite_detail_uses_exact_typed_production_display_v25() {
        let message = composite_message_v25();
        let expected =
            crate::production_composite_loop::ProductionCompositeLoopErrorV1::InvalidConfiguration
                .failure_v25();
        assert_eq!(classify(message.as_bytes()), "composite_loop");
        assert_eq!(composite_detail_v25(message.as_bytes()), Some(expected));
        assert_eq!(
            composite_detail_v25(format!("{message}\n").as_bytes()),
            Some(expected)
        );
        for decorated in [
            format!("prefix {message}"),
            format!(" {message}"),
            format!("{message}\r"),
            format!("{message}: private material"),
            "production composite relay loop failed: unknown/secret".to_owned(),
        ] {
            assert_eq!(classify(decorated.as_bytes()), "unknown");
            assert!(composite_detail_v25(decorated.as_bytes()).is_none());
        }
    }

    #[test]
    fn composite_detail_refuses_ambiguous_and_oversized_capture_v25() {
        let message = composite_message_v25();
        for mixed in [
            format!("{message}\n{message}"),
            format!("{message}\nproduction composite relay loop failed"),
            format!("production inputs refused\n{message}"),
        ] {
            assert_eq!(classify(mixed.as_bytes()), "multiple_public_errors");
            assert!(composite_detail_v25(mixed.as_bytes()).is_none());
        }
        let mut oversized = vec![b'\n'; super::super::MAX_CAPTURE];
        oversized.extend_from_slice(message.as_bytes());
        assert_eq!(classify(&oversized), "unknown");
        assert!(composite_detail_v25(&oversized).is_none());
        assert!(composite_detail_v25(b"production composite relay loop failed").is_none());
        assert!(composite_detail_v25(b"\xff\x00private").is_none());
    }

    #[test]
    fn exact_public_messages_map_only_to_fixed_codes_v24() {
        for (message, code) in PUBLIC {
            assert_eq!(classify(message.as_bytes()), *code);
            assert_eq!(classify(format!("{message}\n").as_bytes()), *code);
            for decorated in [
                format!("prefix {message}"),
                format!("{message}: secret"),
                format!(" {message}"),
                format!("{message}\r"),
            ] {
                assert_eq!(classify(decorated.as_bytes()), "unknown");
            }
        }
    }

    #[test]
    fn secret_bytes_and_unknown_diagnostics_are_never_returned_v24() {
        for input in [
            b"private_scalar=abcdef0123456789".as_slice(),
            b"\xff\x00secret",
            b"production configuration refused: secret",
            b"",
            b"panic at /private/key",
        ] {
            assert_eq!(classify(input), "unknown");
        }
        assert_eq!(
            classify(b"private_scalar=abcdef0123456789\nproduction route runtime failed\n"),
            "route_runtime"
        );
        // No allocation/slicing of the input can become the public result:
        // all allowed output values are literal &'static str from this table.
        for (_, code) in PUBLIC {
            assert!(code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_' || byte.is_ascii_digit()));
            assert!(!code.contains("abcdef"));
        }
    }

    #[test]
    fn multiple_exact_errors_are_ambiguous_without_echoing_input_v24() {
        assert_eq!(
            classify(b"production route runtime failed\nproduction F6 authorities unavailable\n"),
            "multiple_public_errors"
        );
        assert_eq!(
            classify(b"production inputs refused\nproduction inputs refused"),
            "multiple_public_errors"
        );
    }

    #[test]
    fn diagnostic_respects_capture_bound_and_never_truncates_into_match_v24() {
        let message = b"production inputs refused\n";
        let mut input = vec![b'\n'; super::super::MAX_CAPTURE - message.len()];
        input.extend_from_slice(message);
        assert_eq!(classify(&input), "inputs");
        input.push(b'\n');
        assert_eq!(classify(&input), "unknown");
    }

    #[test]
    fn allowlist_is_pinned_to_literal_production_errors_v24() {
        let source = include_str!("../../production_run.rs");
        let source = source
            .split("pub enum ProductionRunErrorV1 {")
            .nth(1)
            .unwrap()
            .split("\n}")
            .next()
            .unwrap();
        for (message, _) in PUBLIC {
            assert!(source.contains(&format!("#[error(\"{message}\")]")));
        }
    }

    #[test]
    fn stderr_capture_timeout_and_repeat_preserve_the_single_owned_result_v24() {
        use super::super::{retain_stderr_once_v24, Duration, Zeroizing};
        let (send, receive) = std::sync::mpsc::channel();
        let mut retained = None;
        retain_stderr_once_v24(&receive, &mut retained, Duration::ZERO);
        assert!(
            retained.is_none(),
            "timeout cannot manufacture a consumed capture"
        );
        send.send(Ok(Zeroizing::new(b"production inputs refused".to_vec())))
            .unwrap();
        retain_stderr_once_v24(&receive, &mut retained, Duration::ZERO);
        send.send(Ok(Zeroizing::new(
            b"second capture must remain unread".to_vec(),
        )))
        .unwrap();
        retain_stderr_once_v24(&receive, &mut retained, Duration::ZERO);
        assert_eq!(
            classify(retained.as_ref().unwrap().as_ref().unwrap()),
            "inputs"
        );
        assert!(
            receive.try_recv().is_ok(),
            "repeat must not receive another capture"
        );
        // finish takes the original owned result, including a capture error;
        // the diagnostic path never converts that error into successful EOF.
        assert_eq!(
            retained.take().unwrap().unwrap().as_slice(),
            b"production inputs refused"
        );
        send.send(Err(std::io::Error::other("bounded capture refused")))
            .unwrap();
        retain_stderr_once_v24(&receive, &mut retained, Duration::ZERO);
        assert!(retained.take().unwrap().is_err());
    }
}
