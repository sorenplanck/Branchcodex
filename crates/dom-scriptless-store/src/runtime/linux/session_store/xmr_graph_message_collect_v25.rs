//! Fresh physical collection for native graph and bounded funding prefix audits.
//! Decoded records are NOT identity authentication or a signing capability.
use super::*;

/// The caller owns the Store operation lock and still authenticates every
/// returned record, durable successor and complete revision-ordered prefix.
/// Only read-only graph and bounded funding collectors use this helper. Global transport,
/// roster and sequence audits continue through their original paths.
pub(in super::super) fn collect_untrusted_messages_v25(
    messages: &RetainedDirectory,
    session: [u8; 32],
) -> Result<Vec<(String, TransportMessageRecordV1)>, LinuxCapabilityError> {
    let prefix = format!("{}-", hex_lower(&session));
    let mut retained = Vec::new();
    messages.scan_unordered_readonly_with_exclusions_v25(|name, node| {
        // Keep these checks BEFORE the session/suffix filter, including foreign
        // registered entries and unexcluded staging files.
        if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        if !name.starts_with(&prefix) || !name.ends_with(".message") {
            return Ok(());
        }
        let bytes = messages.read_bounded_file(
            &ValidatedComponent::registered(name)?,
            TRANSPORT_MESSAGE_MAX_LEN,
        )?;
        let record = TransportMessageRecordV1::from_bytes(&bytes)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        retained.push((name.to_owned(), record));
        Ok(())
    })?;
    // Authentication previously followed lexical filenames, not revision order.
    // Preserve that order before either caller runs its unchanged authenticator
    // and its later independent revision sort. Never deduplicate records here.
    retained.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    Ok(retained)
}

#[cfg(test)]
#[path = "xmr_graph_message_collect_v25_tests.rs"]
mod tests;
