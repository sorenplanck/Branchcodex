//! Participant-to-Solana-account authority for DOM interoperability.
//!
//! Settlement terms name participants by 32-byte protocol identities, which
//! are Blake2b digests of a chain id and a secp256k1 key. A Solana escrow pays
//! to 32-byte Ed25519 accounts. The two namespaces have the same width and are
//! still not interchangeable: no Ed25519 key exists for a participant digest,
//! so an escrow that pays the participant id pays an address nobody controls.
//!
//! The same bounded statement is therefore signed by the Solana account
//! (Ed25519, strict verification) and by the participant's roster BIP340 key
//! before [`bind_solana_session_v25`] produces the accounts a setup may use.
//! The refund goes to the funding account, as it does on EVM: the funder's
//! proof authorizes both the account that funds and the one that is refunded.

use btc_crypto::SecpContext;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use kaystra_core::{
    terms::SettlementTermsV1,
    types::{Digest32, ParticipantId},
};
use sha3::{Digest, Sha3_256};

const STATEMENT_DOMAIN_V25: &[u8] = b"DOM-INTEROP/SOLANA-ACCOUNT-BINDING/V25\0";
const PROOF_MAGIC_V25: &[u8; 8] = b"DOMSOLP1";
const PROOF_VERSION_V25: u16 = 1;
const VERIFICATION_CONTEXT_SEED_V25: [u8; 32] = [0xA8; 32];

/// Ed25519 account signature length.
pub const SOLANA_ACCOUNT_SIGNATURE_BYTES_V25: usize = 64;
/// Exact size of one canonical dual-signed Solana account-binding proof.
pub const SOLANA_ACCOUNT_BINDING_PROOF_BYTES_V25: usize = 8 + 2 + 2 // magic, version, reserved
    + 32 * 7                  // network, registry, route, settlement, session, terms, roster
    + 32 + 32 + 32            // participant id, participant key, account
    + 1 + 1                   // position, role
    + 8 + 8                   // issued_at, valid_until
    + 32 + 32                 // genesis hash, escrow program
    + SOLANA_ACCOUNT_SIGNATURE_BYTES_V25
    + crate::PARTICIPANT_SIGNATURE_BYTES_V1;

/// The economic Solana role whose account ownership is being authorized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SolanaBindingRoleV25 {
    /// Account that initializes and funds the escrow and receives its refund.
    Funder,
    /// Account the escrow pays when the route scalar is revealed.
    Beneficiary,
}

impl SolanaBindingRoleV25 {
    const fn tag(self) -> u8 {
        match self {
            Self::Funder => 1,
            Self::Beneficiary => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, SolanaAccountBindingErrorV25> {
        match tag {
            1 => Ok(Self::Funder),
            2 => Ok(Self::Beneficiary),
            _ => Err(SolanaAccountBindingErrorV25::NonCanonicalEncoding),
        }
    }
}

/// Position of the settlement inside the composed `X -> DOM -> Y` route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SolanaSettlementPositionV25 {
    /// Counterparty funding enters the DOM hub.
    Upstream,
    /// Counterparty claim exits the DOM hub.
    Downstream,
}

impl SolanaSettlementPositionV25 {
    const fn tag(self) -> u8 {
        match self {
            Self::Upstream => 1,
            Self::Downstream => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, SolanaAccountBindingErrorV25> {
        match tag {
            1 => Ok(Self::Upstream),
            2 => Ok(Self::Downstream),
            _ => Err(SolanaAccountBindingErrorV25::NonCanonicalEncoding),
        }
    }
}

/// One bounded Solana account-link statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SolanaAccountBindingStatementV25 {
    /// DOM interoperability network identity.
    pub network_id: Digest32,
    /// Threshold-authenticated deployment registry digest.
    pub registry_digest: Digest32,
    /// Composed route identity.
    pub route_id: Digest32,
    /// Exact settlement whose Solana leg uses the account.
    pub settlement_id: Digest32,
    /// Exact scriptless session identity.
    pub session_id: Digest32,
    /// Frozen route terms digest.
    pub terms_digest: Digest32,
    /// Frozen Relay roster snapshot that authenticates the participant key.
    pub roster_snapshot: Digest32,
    /// Protocol participant identity from the ordered settlement roster.
    pub participant_id: ParticipantId,
    /// BIP340 transport key registered for the participant at that snapshot.
    pub participant_xonly_key: [u8; 32],
    /// Ed25519 Solana account being linked to that participant and role.
    pub account: [u8; 32],
    /// Signed settlement position.
    pub position: SolanaSettlementPositionV25,
    /// Economic role authorized for the account.
    pub role: SolanaBindingRoleV25,
    /// First Unix second at which this statement may be accepted.
    pub issued_at: u64,
    /// Last Unix second at which a new session authority may accept it.
    pub valid_until: u64,
    /// Genesis hash of the cluster the registry selected.
    pub genesis_hash: Digest32,
    /// Escrow program the registry pinned for that cluster.
    pub escrow_program: [u8; 32],
}

/// The exact dual proof over a Solana account-link statement.
#[derive(Clone, Eq, PartialEq)]
pub struct SolanaAccountBindingProofV25 {
    statement: SolanaAccountBindingStatementV25,
    account_signature: [u8; SOLANA_ACCOUNT_SIGNATURE_BYTES_V25],
    participant_signature: [u8; crate::PARTICIPANT_SIGNATURE_BYTES_V1],
}

impl core::fmt::Debug for SolanaAccountBindingProofV25 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SolanaAccountBindingProofV25")
            .field("statement", &self.statement)
            .finish_non_exhaustive()
    }
}

impl SolanaAccountBindingProofV25 {
    /// Constructs an unverified proof for boundary ingestion.
    pub const fn new(
        statement: SolanaAccountBindingStatementV25,
        account_signature: [u8; SOLANA_ACCOUNT_SIGNATURE_BYTES_V25],
        participant_signature: [u8; crate::PARTICIPANT_SIGNATURE_BYTES_V1],
    ) -> Self {
        Self {
            statement,
            account_signature,
            participant_signature,
        }
    }

    /// Statement signed by both authorities.
    pub const fn statement(&self) -> SolanaAccountBindingStatementV25 {
        self.statement
    }

    /// Exact bounded binary representation used by production input bundles.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SolanaAccountBindingErrorV25> {
        validate_statement(&self.statement)?;
        let mut bytes = Vec::with_capacity(SOLANA_ACCOUNT_BINDING_PROOF_BYTES_V25);
        bytes.extend_from_slice(PROOF_MAGIC_V25);
        bytes.extend_from_slice(&PROOF_VERSION_V25.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        push_statement(&mut bytes, &self.statement);
        bytes.extend_from_slice(&self.account_signature);
        bytes.extend_from_slice(&self.participant_signature);
        if bytes.len() != SOLANA_ACCOUNT_BINDING_PROOF_BYTES_V25 {
            return Err(SolanaAccountBindingErrorV25::NonCanonicalEncoding);
        }
        Ok(bytes)
    }

    /// Strictly decodes one proof and rejects alternate or trailing bytes.
    /// Cryptographic authentication still requires
    /// [`verify_solana_account_binding_v25`].
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, SolanaAccountBindingErrorV25> {
        if bytes.len() != SOLANA_ACCOUNT_BINDING_PROOF_BYTES_V25 {
            return Err(SolanaAccountBindingErrorV25::NonCanonicalEncoding);
        }
        let mut cursor = CursorV25 { bytes, position: 0 };
        if cursor.take::<8>()? != *PROOF_MAGIC_V25
            || u16::from_be_bytes(cursor.take::<2>()?) != PROOF_VERSION_V25
            || u16::from_be_bytes(cursor.take::<2>()?) != 0
        {
            return Err(SolanaAccountBindingErrorV25::NonCanonicalEncoding);
        }
        let statement = SolanaAccountBindingStatementV25 {
            network_id: cursor.take::<32>()?,
            registry_digest: cursor.take::<32>()?,
            route_id: cursor.take::<32>()?,
            settlement_id: cursor.take::<32>()?,
            session_id: cursor.take::<32>()?,
            terms_digest: cursor.take::<32>()?,
            roster_snapshot: cursor.take::<32>()?,
            participant_id: ParticipantId(cursor.take::<32>()?),
            participant_xonly_key: cursor.take::<32>()?,
            account: cursor.take::<32>()?,
            position: SolanaSettlementPositionV25::from_tag(cursor.take::<1>()?[0])?,
            role: SolanaBindingRoleV25::from_tag(cursor.take::<1>()?[0])?,
            issued_at: u64::from_be_bytes(cursor.take::<8>()?),
            valid_until: u64::from_be_bytes(cursor.take::<8>()?),
            genesis_hash: cursor.take::<32>()?,
            escrow_program: cursor.take::<32>()?,
        };
        let value = Self::new(
            statement,
            cursor.take::<SOLANA_ACCOUNT_SIGNATURE_BYTES_V25>()?,
            cursor.take::<{ crate::PARTICIPANT_SIGNATURE_BYTES_V1 }>()?,
        );
        if cursor.position != bytes.len() || value.canonical_bytes()?.as_slice() != bytes {
            return Err(SolanaAccountBindingErrorV25::NonCanonicalEncoding);
        }
        Ok(value)
    }
}

/// Verified, route-scoped link between one participant and one Solana account.
#[derive(Debug, Eq, PartialEq)]
pub struct AuthenticatedSolanaAccountBindingV25 {
    statement: SolanaAccountBindingStatementV25,
    binding_digest: Digest32,
}

impl AuthenticatedSolanaAccountBindingV25 {
    /// Verified statement.
    pub const fn statement(&self) -> SolanaAccountBindingStatementV25 {
        self.statement
    }

    /// Digest signed by both identities.
    pub const fn binding_digest(&self) -> Digest32 {
        self.binding_digest
    }
}

/// The escrow accounts of one settlement, constructed only from two verified
/// account links matched to the settlement roles.
#[derive(Debug, Eq, PartialEq)]
pub struct AuthenticatedSolanaSessionAccountsV25 {
    funder: [u8; 32],
    recipient: [u8; 32],
    refund_recipient: [u8; 32],
    route_id: Digest32,
    settlement_id: Digest32,
    roster_snapshot: Digest32,
    genesis_hash: Digest32,
    escrow_program: [u8; 32],
    funder_binding_digest: Digest32,
    beneficiary_binding_digest: Digest32,
}

impl AuthenticatedSolanaSessionAccountsV25 {
    /// Account that initializes and funds the escrow.
    pub const fn funder(&self) -> [u8; 32] {
        self.funder
    }

    /// Account the escrow pays on claim.
    pub const fn recipient(&self) -> [u8; 32] {
        self.recipient
    }

    /// Account the escrow pays on refund: the funding account.
    pub const fn refund_recipient(&self) -> [u8; 32] {
        self.refund_recipient
    }

    /// Composed route authenticated by both proofs.
    pub const fn route_id(&self) -> Digest32 {
        self.route_id
    }

    /// Settlement authenticated by both proofs.
    pub const fn settlement_id(&self) -> Digest32 {
        self.settlement_id
    }

    /// Relay roster snapshot shared by both participant proofs.
    pub const fn roster_snapshot(&self) -> Digest32 {
        self.roster_snapshot
    }

    /// Cluster genesis hash authenticated by both proofs.
    pub const fn genesis_hash(&self) -> Digest32 {
        self.genesis_hash
    }

    /// Escrow program authenticated by both proofs.
    pub const fn escrow_program(&self) -> [u8; 32] {
        self.escrow_program
    }

    /// Dual-signed proof digest for the funding account.
    pub const fn funder_binding_digest(&self) -> Digest32 {
        self.funder_binding_digest
    }

    /// Dual-signed proof digest for the beneficiary account.
    pub const fn beneficiary_binding_digest(&self) -> Digest32 {
        self.beneficiary_binding_digest
    }
}

/// Fail-closed Solana account/session binding refusals.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SolanaAccountBindingErrorV25 {
    /// A proof artifact was truncated, alternate or had trailing bytes.
    #[error("non-canonical Solana account binding encoding")]
    NonCanonicalEncoding,
    /// A required identity, account or time field is invalid.
    #[error("invalid Solana account binding statement")]
    InvalidStatement,
    /// The account is not a valid Ed25519 point, or is a weak key.
    #[error("invalid Solana account key")]
    InvalidAccountKey,
    /// The Ed25519 signature does not verify strictly under the account.
    #[error("invalid Solana account signature")]
    InvalidAccountSignature,
    /// The BIP340 signature does not verify under the roster key.
    #[error("invalid participant roster signature")]
    InvalidParticipantSignature,
    /// A verified proof does not match the requested route/session authority.
    #[error("Solana account binding scope mismatch")]
    ScopeMismatch,
    /// Funder and beneficiary proofs do not match the settlement roles.
    #[error("Solana account roles do not match settlement terms")]
    RoleMismatch,
}

/// Computes the domain-separated digest both identities sign.
pub fn solana_account_binding_digest_v25(
    statement: &SolanaAccountBindingStatementV25,
) -> Result<Digest32, SolanaAccountBindingErrorV25> {
    validate_statement(statement)?;
    let mut encoded = Vec::with_capacity(STATEMENT_DOMAIN_V25.len() + 480);
    encoded.extend_from_slice(STATEMENT_DOMAIN_V25);
    push_statement(&mut encoded, statement);
    let mut hasher = Sha3_256::new();
    hasher.update(&encoded);
    Ok(hasher.finalize().into())
}

/// Verifies both the Solana account and participant-roster signatures.
///
/// The account signs the 32-byte digest itself. A Solana transaction message
/// is always longer than 32 bytes, so this signature can never double as a
/// transaction signature, and the domain keeps it apart from any other DOM
/// statement.
pub fn verify_solana_account_binding_v25(
    proof: &SolanaAccountBindingProofV25,
    expected_participant_xonly_key: [u8; 32],
    expected_roster_snapshot: Digest32,
    expected_network_id: Digest32,
    expected_registry_digest: Digest32,
    now_seconds: u64,
) -> Result<AuthenticatedSolanaAccountBindingV25, SolanaAccountBindingErrorV25> {
    let statement = proof.statement;
    validate_statement(&statement)?;
    if expected_participant_xonly_key == [0; 32]
        || expected_roster_snapshot == [0; 32]
        || expected_network_id == [0; 32]
        || expected_registry_digest == [0; 32]
        || statement.network_id != expected_network_id
        || statement.registry_digest != expected_registry_digest
        || statement.roster_snapshot != expected_roster_snapshot
        || statement.participant_xonly_key != expected_participant_xonly_key
        || now_seconds < statement.issued_at
        || now_seconds > statement.valid_until
    {
        return Err(SolanaAccountBindingErrorV25::ScopeMismatch);
    }
    let digest = solana_account_binding_digest_v25(&statement)?;
    let account = Ed25519VerifyingKey::from_bytes(&statement.account)
        .map_err(|_| SolanaAccountBindingErrorV25::InvalidAccountKey)?;
    if account.is_weak() {
        return Err(SolanaAccountBindingErrorV25::InvalidAccountKey);
    }
    account
        .verify_strict(
            &digest,
            &Ed25519Signature::from_bytes(&proof.account_signature),
        )
        .map_err(|_| SolanaAccountBindingErrorV25::InvalidAccountSignature)?;
    let secp = SecpContext::new(&VERIFICATION_CONTEXT_SEED_V25);
    secp.verify_bip340(
        &expected_participant_xonly_key,
        &digest,
        &proof.participant_signature,
    )
    .map_err(|_| SolanaAccountBindingErrorV25::InvalidParticipantSignature)?;
    Ok(AuthenticatedSolanaAccountBindingV25 {
        statement,
        binding_digest: digest,
    })
}

/// Produces the escrow accounts of one settlement after matching both verified
/// account links to the settlement roster, roles and registry deployment.
#[allow(clippy::too_many_arguments)]
pub fn bind_solana_session_v25(
    terms: &SettlementTermsV1,
    route_id: Digest32,
    frozen_terms_digest: Digest32,
    expected_position: SolanaSettlementPositionV25,
    genesis_hash: Digest32,
    escrow_program: [u8; 32],
    network_id: Digest32,
    registry_digest: Digest32,
    now_seconds: u64,
    funder: &AuthenticatedSolanaAccountBindingV25,
    beneficiary: &AuthenticatedSolanaAccountBindingV25,
) -> Result<AuthenticatedSolanaSessionAccountsV25, SolanaAccountBindingErrorV25> {
    terms
        .validate()
        .map_err(|_| SolanaAccountBindingErrorV25::ScopeMismatch)?;
    if terms.roster[0].0 == [0; 32] || terms.roster[0] >= terms.roster[1] {
        return Err(SolanaAccountBindingErrorV25::ScopeMismatch);
    }
    if route_id == [0; 32]
        || frozen_terms_digest == [0; 32]
        || genesis_hash == [0; 32]
        || escrow_program == [0; 32]
        || network_id == [0; 32]
        || registry_digest == [0; 32]
    {
        return Err(SolanaAccountBindingErrorV25::ScopeMismatch);
    }
    let expected_common = |binding: &AuthenticatedSolanaAccountBindingV25| {
        let statement = binding.statement;
        statement.network_id == network_id
            && statement.registry_digest == registry_digest
            && statement.route_id == route_id
            && statement.settlement_id == terms.settlement_id.0
            && statement.session_id == terms.session_id.0
            && statement.terms_digest == frozen_terms_digest
            && statement.position == expected_position
            && statement.genesis_hash == genesis_hash
            && statement.escrow_program == escrow_program
            && now_seconds >= statement.issued_at
            && now_seconds <= statement.valid_until
            && terms.roster.contains(&statement.participant_id)
    };
    if !expected_common(funder) || !expected_common(beneficiary) {
        return Err(SolanaAccountBindingErrorV25::ScopeMismatch);
    }
    if funder.statement.role != SolanaBindingRoleV25::Funder
        || beneficiary.statement.role != SolanaBindingRoleV25::Beneficiary
        || funder.statement.roster_snapshot != beneficiary.statement.roster_snapshot
        || funder.statement.participant_id != terms.counterparty_leg.refund_to
        || beneficiary.statement.participant_id != terms.counterparty_leg.beneficiary
        || funder.statement.participant_id == beneficiary.statement.participant_id
        || funder.statement.participant_xonly_key == beneficiary.statement.participant_xonly_key
        || funder.statement.account == beneficiary.statement.account
    {
        return Err(SolanaAccountBindingErrorV25::RoleMismatch);
    }
    Ok(AuthenticatedSolanaSessionAccountsV25 {
        funder: funder.statement.account,
        recipient: beneficiary.statement.account,
        refund_recipient: funder.statement.account,
        route_id,
        settlement_id: terms.settlement_id.0,
        roster_snapshot: funder.statement.roster_snapshot,
        genesis_hash,
        escrow_program,
        funder_binding_digest: funder.binding_digest,
        beneficiary_binding_digest: beneficiary.binding_digest,
    })
}

fn validate_statement(
    statement: &SolanaAccountBindingStatementV25,
) -> Result<(), SolanaAccountBindingErrorV25> {
    if statement.network_id == [0; 32]
        || statement.registry_digest == [0; 32]
        || statement.route_id == [0; 32]
        || statement.settlement_id == [0; 32]
        || statement.session_id == [0; 32]
        || statement.terms_digest == [0; 32]
        || statement.roster_snapshot == [0; 32]
        || statement.participant_id.0 == [0; 32]
        || statement.participant_xonly_key == [0; 32]
        || statement.account == [0; 32]
        || statement.issued_at == 0
        || statement.issued_at > statement.valid_until
        || statement.genesis_hash == [0; 32]
        || statement.escrow_program == [0; 32]
    {
        return Err(SolanaAccountBindingErrorV25::InvalidStatement);
    }
    Ok(())
}

fn push_statement(output: &mut Vec<u8>, statement: &SolanaAccountBindingStatementV25) {
    output.extend_from_slice(&statement.network_id);
    output.extend_from_slice(&statement.registry_digest);
    output.extend_from_slice(&statement.route_id);
    output.extend_from_slice(&statement.settlement_id);
    output.extend_from_slice(&statement.session_id);
    output.extend_from_slice(&statement.terms_digest);
    output.extend_from_slice(&statement.roster_snapshot);
    output.extend_from_slice(&statement.participant_id.0);
    output.extend_from_slice(&statement.participant_xonly_key);
    output.extend_from_slice(&statement.account);
    output.push(statement.position.tag());
    output.push(statement.role.tag());
    output.extend_from_slice(&statement.issued_at.to_be_bytes());
    output.extend_from_slice(&statement.valid_until.to_be_bytes());
    output.extend_from_slice(&statement.genesis_hash);
    output.extend_from_slice(&statement.escrow_program);
}

struct CursorV25<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl CursorV25<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], SolanaAccountBindingErrorV25> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(SolanaAccountBindingErrorV25::NonCanonicalEncoding)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(SolanaAccountBindingErrorV25::NonCanonicalEncoding)?;
        self.position = end;
        value
            .try_into()
            .map_err(|_| SolanaAccountBindingErrorV25::NonCanonicalEncoding)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
    use kaystra_core::types::{
        AssetId, ChainId, FeeLimitV1, FinalityPolicyV1, IntentHash, LegRole, LegTermsV1,
        LockMechanism, RecoveryPolicyV1, SessionId, SettlementId, SolverId, TimelockSpec,
    };

    const NETWORK: Digest32 = [0x11; 32];
    const REGISTRY: Digest32 = [0x12; 32];
    const ROUTE: Digest32 = [0x13; 32];
    const FROZEN_TERMS: Digest32 = [0x14; 32];
    const ROSTER_SNAPSHOT: Digest32 = [0x15; 32];
    const GENESIS: Digest32 = [0x16; 32];
    const PROGRAM: [u8; 32] = [0x17; 32];
    const NOW: u64 = 1_900_000_000;
    const FUNDER_SEED: [u8; 32] = [0x61; 32];
    const BENEFICIARY_SEED: [u8; 32] = [0x62; 32];
    const FUNDER_SECRET: [u8; 32] = [0x71; 32];
    const BENEFICIARY_SECRET: [u8; 32] = [0x72; 32];

    struct SignedFixture {
        proof: SolanaAccountBindingProofV25,
        xonly: [u8; 32],
    }

    fn terms() -> SettlementTermsV1 {
        let funder = ParticipantId([0x21; 32]);
        let beneficiary = ParticipantId([0x31; 32]);
        SettlementTermsV1 {
            settlement_id: SettlementId([0x41; 32]),
            session_id: SessionId([0x42; 32]),
            intent_hash: IntentHash([0x43; 32]),
            solver_id: SolverId([0x44; 32]),
            roster: [funder, beneficiary],
            dom_leg: LegTermsV1 {
                role: LegRole::Dom,
                chain_id: ChainId([0x45; 32]),
                asset_id: AssetId([0x46; 32]),
                amount: 100,
                beneficiary,
                refund_to: funder,
                mechanism: LockMechanism::DomAdaptor2of2,
                deadline: TimelockSpec::BlockHeight { value: 1_000 },
                finality: FinalityPolicyV1 {
                    min_confirmations: 6,
                    max_reorg_depth: 12,
                },
                adapter_profile_hash: [0x47; 32],
            },
            counterparty_leg: LegTermsV1 {
                role: LegRole::Counterparty,
                chain_id: ChainId([0x48; 32]),
                asset_id: AssetId([0x49; 32]),
                amount: 200,
                beneficiary,
                refund_to: funder,
                mechanism: LockMechanism::CrossCurveConditionLock,
                deadline: TimelockSpec::TimestampSeconds {
                    value: NOW + 10_000,
                },
                finality: FinalityPolicyV1 {
                    min_confirmations: 1,
                    max_reorg_depth: 32,
                },
                adapter_profile_hash: [0x4A; 32],
            },
            adaptor_point_sec1: {
                let mut point = [0x4B; 33];
                point[0] = 0x02;
                point
            },
            fee_limit: FeeLimitV1 {
                dom_max: 10,
                counterparty_max: 10,
            },
            recovery: RecoveryPolicyV1 {
                refund_before_funding: true,
                evidence_retention_blocks: 20,
            },
            assurance_policy_hash: None,
            policy_version: 1,
            metadata: Vec::new(),
        }
    }

    fn signed(
        participant_id: ParticipantId,
        role: SolanaBindingRoleV25,
        account_seed: [u8; 32],
        participant_secret: [u8; 32],
    ) -> SignedFixture {
        let settlement = terms();
        let secp = SecpContext::new(&[0x51; 32]);
        let (_, xonly) = secp
            .sign_bip340(&participant_secret, &[0x53; 32], &[0x54; 32])
            .expect("participant public key");
        let account = Ed25519SigningKey::from_bytes(&account_seed);
        let statement = SolanaAccountBindingStatementV25 {
            network_id: NETWORK,
            registry_digest: REGISTRY,
            route_id: ROUTE,
            settlement_id: settlement.settlement_id.0,
            session_id: settlement.session_id.0,
            terms_digest: FROZEN_TERMS,
            roster_snapshot: ROSTER_SNAPSHOT,
            participant_id,
            participant_xonly_key: xonly,
            account: account.verifying_key().to_bytes(),
            position: SolanaSettlementPositionV25::Downstream,
            role,
            issued_at: NOW - 100,
            valid_until: NOW + 100,
            genesis_hash: GENESIS,
            escrow_program: PROGRAM,
        };
        let digest = solana_account_binding_digest_v25(&statement).expect("digest");
        let account_signature = account.sign(&digest).to_bytes();
        let (participant_signature, signed_xonly) = secp
            .sign_bip340(&participant_secret, &digest, &[0x52; 32])
            .expect("participant signature");
        assert_eq!(signed_xonly, xonly);
        SignedFixture {
            proof: SolanaAccountBindingProofV25::new(
                statement,
                account_signature,
                participant_signature,
            ),
            xonly,
        }
    }

    fn funder() -> SignedFixture {
        signed(
            ParticipantId([0x21; 32]),
            SolanaBindingRoleV25::Funder,
            FUNDER_SEED,
            FUNDER_SECRET,
        )
    }

    fn beneficiary() -> SignedFixture {
        signed(
            ParticipantId([0x31; 32]),
            SolanaBindingRoleV25::Beneficiary,
            BENEFICIARY_SEED,
            BENEFICIARY_SECRET,
        )
    }

    fn authenticate(
        fixture: &SignedFixture,
    ) -> Result<AuthenticatedSolanaAccountBindingV25, SolanaAccountBindingErrorV25> {
        verify_solana_account_binding_v25(
            &fixture.proof,
            fixture.xonly,
            ROSTER_SNAPSHOT,
            NETWORK,
            REGISTRY,
            NOW,
        )
    }

    fn bind(
        funder: &AuthenticatedSolanaAccountBindingV25,
        beneficiary: &AuthenticatedSolanaAccountBindingV25,
    ) -> Result<AuthenticatedSolanaSessionAccountsV25, SolanaAccountBindingErrorV25> {
        bind_solana_session_v25(
            &terms(),
            ROUTE,
            FROZEN_TERMS,
            SolanaSettlementPositionV25::Downstream,
            GENESIS,
            PROGRAM,
            NETWORK,
            REGISTRY,
            NOW,
            funder,
            beneficiary,
        )
    }

    #[test]
    fn dual_signed_accounts_produce_real_escrow_accounts() {
        let funder_fixture = funder();
        let beneficiary_fixture = beneficiary();
        let accounts = bind(
            &authenticate(&funder_fixture).expect("funder proof"),
            &authenticate(&beneficiary_fixture).expect("beneficiary proof"),
        )
        .expect("session accounts");
        let funder_key = Ed25519SigningKey::from_bytes(&FUNDER_SEED)
            .verifying_key()
            .to_bytes();
        let recipient_key = Ed25519SigningKey::from_bytes(&BENEFICIARY_SEED)
            .verifying_key()
            .to_bytes();
        assert_eq!(accounts.funder(), funder_key);
        assert_eq!(accounts.recipient(), recipient_key);
        assert_eq!(accounts.refund_recipient(), funder_key);
        // The whole point: the escrow no longer pays a participant digest.
        assert_ne!(accounts.recipient(), terms().counterparty_leg.beneficiary.0);
        assert_ne!(accounts.refund_recipient(), terms().counterparty_leg.refund_to.0);
        assert_ne!(
            accounts.funder_binding_digest(),
            accounts.beneficiary_binding_digest()
        );
    }

    #[test]
    fn proof_bytes_round_trip_and_refuse_every_alternate_spelling() {
        let proof = funder().proof;
        let bytes = proof.canonical_bytes().expect("encode");
        assert_eq!(bytes.len(), SOLANA_ACCOUNT_BINDING_PROOF_BYTES_V25);
        assert_eq!(
            SolanaAccountBindingProofV25::decode_canonical(&bytes).expect("decode"),
            proof
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(SolanaAccountBindingProofV25::decode_canonical(&trailing).is_err());
        assert!(SolanaAccountBindingProofV25::decode_canonical(&bytes[..bytes.len() - 1]).is_err());
        for (index, value) in [(0, b'X'), (9, 2), (11, 1)] {
            let mut altered = bytes.clone();
            altered[index] = value;
            assert!(SolanaAccountBindingProofV25::decode_canonical(&altered).is_err());
        }
        // Position and role tags outside their closed sets.
        let tags = 12 + 32 * 10;
        for offset in [tags, tags + 1] {
            let mut altered = bytes.clone();
            altered[offset] = 3;
            assert!(SolanaAccountBindingProofV25::decode_canonical(&altered).is_err());
        }
    }

    #[test]
    fn either_signature_alone_authenticates_nothing() {
        let fixture = funder();
        let bytes = fixture.proof.canonical_bytes().expect("encode");
        let account_signature = SOLANA_ACCOUNT_BINDING_PROOF_BYTES_V25
            - crate::PARTICIPANT_SIGNATURE_BYTES_V1
            - SOLANA_ACCOUNT_SIGNATURE_BYTES_V25;
        let participant_signature =
            SOLANA_ACCOUNT_BINDING_PROOF_BYTES_V25 - crate::PARTICIPANT_SIGNATURE_BYTES_V1;
        for (offset, expected) in [
            (
                account_signature,
                SolanaAccountBindingErrorV25::InvalidAccountSignature,
            ),
            (
                participant_signature,
                SolanaAccountBindingErrorV25::InvalidParticipantSignature,
            ),
        ] {
            let mut altered = bytes.clone();
            altered[offset] ^= 0x01;
            let proof = SolanaAccountBindingProofV25::decode_canonical(&altered).expect("decode");
            assert_eq!(
                authenticate(&SignedFixture {
                    proof,
                    xonly: fixture.xonly
                }),
                Err(expected)
            );
        }
        // A roster key other than the one the participant signed with.
        let other = beneficiary();
        assert_eq!(
            verify_solana_account_binding_v25(
                &fixture.proof,
                other.xonly,
                ROSTER_SNAPSHOT,
                NETWORK,
                REGISTRY,
                NOW,
            ),
            Err(SolanaAccountBindingErrorV25::ScopeMismatch)
        );
    }

    #[test]
    fn verification_is_bounded_in_time_and_scope() {
        let fixture = funder();
        for (snapshot, network, registry, now) in [
            ([0x99; 32], NETWORK, REGISTRY, NOW),
            (ROSTER_SNAPSHOT, [0x99; 32], REGISTRY, NOW),
            (ROSTER_SNAPSHOT, NETWORK, [0x99; 32], NOW),
            (ROSTER_SNAPSHOT, NETWORK, REGISTRY, NOW - 101),
            (ROSTER_SNAPSHOT, NETWORK, REGISTRY, NOW + 101),
        ] {
            assert_eq!(
                verify_solana_account_binding_v25(
                    &fixture.proof,
                    fixture.xonly,
                    snapshot,
                    network,
                    registry,
                    now,
                ),
                Err(SolanaAccountBindingErrorV25::ScopeMismatch)
            );
        }
    }

    #[test]
    fn session_binding_refuses_swapped_roles_and_foreign_deployments() {
        let funder = authenticate(&funder()).expect("funder");
        let beneficiary = authenticate(&beneficiary()).expect("beneficiary");
        assert_eq!(
            bind(&beneficiary, &funder),
            Err(SolanaAccountBindingErrorV25::RoleMismatch)
        );
        assert_eq!(
            bind(&funder, &funder),
            Err(SolanaAccountBindingErrorV25::RoleMismatch)
        );
        for (genesis, program, position) in [
            ([0x99; 32], PROGRAM, SolanaSettlementPositionV25::Downstream),
            (GENESIS, [0x99; 32], SolanaSettlementPositionV25::Downstream),
            (GENESIS, PROGRAM, SolanaSettlementPositionV25::Upstream),
        ] {
            assert_eq!(
                bind_solana_session_v25(
                    &terms(),
                    ROUTE,
                    FROZEN_TERMS,
                    position,
                    genesis,
                    program,
                    NETWORK,
                    REGISTRY,
                    NOW,
                    &funder,
                    &beneficiary,
                ),
                Err(SolanaAccountBindingErrorV25::ScopeMismatch)
            );
        }
        // The same Solana account may not serve both roles.
        let shared = authenticate(&signed(
            ParticipantId([0x31; 32]),
            SolanaBindingRoleV25::Beneficiary,
            FUNDER_SEED,
            BENEFICIARY_SECRET,
        ))
        .expect("shared-account beneficiary");
        assert_eq!(
            bind(&funder, &shared),
            Err(SolanaAccountBindingErrorV25::RoleMismatch)
        );
    }
}
