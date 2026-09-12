//! Exact unsigned proposal for future identity-signed graph agreement.
//! Comparing these bytes proves equality only, not participant authentication.
use super::*;

/// Canonical proposal derived only from a bound native graph and verified offers.
/// There is deliberately no constructor accepting purported peer bytes.
pub struct XmrGraphProposalV22 {
    bytes: [u8; Self::ENCODED_LEN],
}

impl XmrGraphProposalV22 {
    /// Fixed encoding: header, scope, roster, directions, offers, templates,
    /// six graph points, six recovery parameters, compensation-policy hash.
    pub const ENCODED_LEN: usize = 704;

    /// Public proposal bytes, not a signed message or a signing authorization.
    pub const fn as_bytes(&self) -> &[u8; Self::ENCODED_LEN] {
        &self.bytes
    }

    /// Domain-separated identity of the complete proposal, including T and U.
    pub fn digest(&self) -> [u8; 32] {
        digest(b"DOM:XMR:graph-proposal:v22\0", &self.bytes)
    }

    /// A peer's purported proposal must equal locally reconstructed bytes.
    /// Identity signatures and replay/provenance checks remain separate.
    pub fn require_matches(&self, bytes: &[u8]) -> Result<(), Error> {
        if bytes != self.bytes.as_slice() {
            return Err(Error::GraphMismatch);
        }
        Ok(())
    }
}

impl XmrGraphSigningKeysV22 {
    /// Freeze all public agreement inputs without selecting or consuming a nonce.
    /// Graph points include both adaptors: transaction hashes alone omit them.
    pub fn proposal(&self) -> Result<XmrGraphProposalV22, Error> {
        let material = &self.material;
        let graph = &self.binding;
        let mut bytes = Vec::with_capacity(XmrGraphProposalV22::ENCODED_LEN);
        bytes.extend_from_slice(b"DXGP22\0\x01");
        for field in [
            material.chain,
            material.route,
            material.session,
            material.terms,
        ] {
            bytes.extend_from_slice(&field);
        }
        for participant in material.participants {
            bytes.extend_from_slice(&participant);
        }
        for direction in material.directions {
            bytes.push(direction.to_byte());
        }
        for packet in material.packets() {
            bytes.extend_from_slice(&digest(b"DOM:XMR:graph-proposal-offer:v22\0", packet));
        }
        for template in self.templates {
            bytes.extend_from_slice(&template);
        }
        for point in [
            graph.funding_commitment,
            graph.cancelled_commitment,
            graph.refund_recipient_commitment,
            graph.punish_recipient_commitment,
            graph.claim_adaptor_point,
            graph.refund_adaptor_point,
        ] {
            bytes.extend_from_slice(&point);
        }
        for value in [
            graph.cancel_height,
            graph.punish_height,
            graph.reveal_safety_blocks,
            graph.cancel_fee,
            graph.refund_fee,
            graph.punish_fee,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&material.policy_hash);
        Ok(XmrGraphProposalV22 {
            bytes: bytes.try_into().map_err(|_| Error::NonCanonical)?,
        })
    }
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut framed = Vec::with_capacity(domain.len() + bytes.len());
    framed.extend_from_slice(domain);
    framed.extend_from_slice(bytes);
    *dom_crypto::blake2b_256(&framed).as_bytes()
}
