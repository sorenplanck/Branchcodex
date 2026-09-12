//! Public proof envelope, distinct from all legacy V2 sidecar response formats.
use super::{
    InputSpendActionV23, InputSpendContextV23, InputSpendProofErrorV23, InputSpendProofV23,
};

const MAGIC: &[u8; 8] = b"XMRISP23";
/// Exact envelope size: magic, canonical context, and public CP proof.
pub const INPUT_SPEND_ENVELOPE_BYTES_V23: usize = 8 + 249 + 96;

impl InputSpendContextV23 {
    /// Decode one complete canonical context. Unknown actions and trailing bytes fail.
    pub fn decode(bytes: &[u8]) -> Result<Self, InputSpendProofErrorV23> {
        if bytes.len() != 249 {
            return Err(InputSpendProofErrorV23::Encoding);
        }
        let mut at = 0;
        // Every field is inside the exact length checked above.
        fn field<const N: usize>(bytes: &[u8], at: &mut usize) -> [u8; N] {
            let mut value = [0; N];
            for (offset, slot) in value.iter_mut().enumerate() {
                *slot = bytes[*at + offset];
            }
            *at += N;
            value
        }
        let context = Self {
            network_genesis: field(bytes, &mut at),
            route: field(bytes, &mut at),
            session: field(bytes, &mut at),
            terms: field(bytes, &mut at),
            funding_tx: field(bytes, &mut at),
            output_index: u64::from_le_bytes(field(bytes, &mut at)),
            sweep_tx: field(bytes, &mut at),
            destination: field(bytes, &mut at),
            funded_amount: u64::from_le_bytes(field(bytes, &mut at)),
            fee: u64::from_le_bytes(field(bytes, &mut at)),
            action: InputSpendActionV23::from_wire(bytes[at])?,
        };
        if context.canonical_bytes()?.as_slice() != bytes {
            return Err(InputSpendProofErrorV23::Encoding);
        }
        Ok(context)
    }
}

/// Public wire data, NOT a verified capability. Decode does not verify equations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputSpendEnvelopeV23 {
    /// Context must additionally match the caller's authenticated request.
    pub context: InputSpendContextV23,
    /// Public DLEQ proof, to be verified against actual transaction bytes.
    pub proof: InputSpendProofV23,
}
impl InputSpendEnvelopeV23 {
    /// Encode a new explicit version; does not reinterpret or mutate V2 wire.
    pub fn encode(&self) -> Result<Vec<u8>, InputSpendProofErrorV23> {
        let mut bytes = Vec::with_capacity(INPUT_SPEND_ENVELOPE_BYTES_V23);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.context.canonical_bytes()?);
        bytes.extend_from_slice(self.proof.as_bytes());
        Ok(bytes)
    }
    /// Strict public framing/point/scalar decoding, not a signing authorization.
    pub fn decode(bytes: &[u8]) -> Result<Self, InputSpendProofErrorV23> {
        if bytes.len() != INPUT_SPEND_ENVELOPE_BYTES_V23 || &bytes[..8] != MAGIC {
            return Err(InputSpendProofErrorV23::Encoding);
        }
        Ok(Self {
            context: InputSpendContextV23::decode(&bytes[8..257])?,
            proof: InputSpendProofV23::decode(&bytes[257..])?,
        })
    }
}
