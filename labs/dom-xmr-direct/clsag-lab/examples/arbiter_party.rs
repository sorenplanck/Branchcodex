//! Isolated share holder used by the funded DXA1 integration experiment.
//!
//! The process generates one cross-curve share and never returns it. It emits
//! only its public DLEQ proof, completes the DOM path assigned to its role, and
//! signs an already constructed Monero transaction after verifying the peer's
//! opening. Requests and responses are newline-delimited JSON on stdio.

use std::io::{self, BufRead, BufReader, Write};

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
};
use dom_consensus::{SwapArbiterContract, SwapArbiterPath, ValidationContext};
use dom_core::{BlockHeight, Timestamp, SWAP_ARBITER_CONTRACT_SIZE};
use dom_scriptless_primitives::SecretScalar;
use dom_serialization::DomSerialize;
use dxp1_clsag_lab::{claim_resume::digest, native_dom::DomClaimOffer};
use monero_wallet::{ed25519::Scalar as MoneroScalar, send::SignableTransaction};
use rand_core::OsRng;
use serde_json::{json, Value};
use xmr_dleq_sigma::{
    prove_bound, revealed_dom_secret_to_xmr_scalar, verify_bound, BoundCrossCurveProofV1,
    CrossCurvePublicClaim, CrossCurveSecret252, ROLE_XMR_REFUND_SHARE, ROLE_XMR_SHARED_SPEND,
};
use zeroize::Zeroizing;

const MAX_LINE_BYTES: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    DomOwner,
    XmrOwner,
}

impl Role {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "dom-owner" => Ok(Self::DomOwner),
            "xmr-owner" => Ok(Self::XmrOwner),
            _ => Err("role must be dom-owner or xmr-owner".into()),
        }
    }

    fn proof_role(self) -> u8 {
        match self {
            Self::DomOwner => ROLE_XMR_REFUND_SHARE,
            Self::XmrOwner => ROLE_XMR_SHARED_SPEND,
        }
    }

    fn peer_proof_role(self) -> u8 {
        match self {
            Self::DomOwner => ROLE_XMR_SHARED_SPEND,
            Self::XmrOwner => ROLE_XMR_REFUND_SHARE,
        }
    }

    fn permits_dom_completion(self, path: SwapArbiterPath) -> bool {
        match self {
            Self::DomOwner => path == SwapArbiterPath::Refund,
            Self::XmrOwner => matches!(path, SwapArbiterPath::Claim | SwapArbiterPath::Punish),
        }
    }

    fn permits_xmr_signing(self, path: SwapArbiterPath) -> bool {
        match self {
            Self::DomOwner => matches!(path, SwapArbiterPath::Claim | SwapArbiterPath::Punish),
            Self::XmrOwner => path == SwapArbiterPath::Refund,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::DomOwner => "dom-owner",
            Self::XmrOwner => "xmr-owner",
        }
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("hex has odd length".into());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            let high = digit(pair[0]).ok_or_else(|| "invalid hex".to_string())?;
            let low = digit(pair[1]).ok_or_else(|| "invalid hex".to_string())?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    decode_hex(value)?
        .try_into()
        .map_err(|_| format!("expected {N} bytes"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn string_field<'a>(request: &'a Value, name: &str) -> Result<&'a str, String> {
    request
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {name}"))
}

fn u64_field(request: &Value, name: &str) -> Result<u64, String> {
    request
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing {name}"))
}

fn parse_path(value: &str) -> Result<SwapArbiterPath, String> {
    match value {
        "claim" => Ok(SwapArbiterPath::Claim),
        "refund" => Ok(SwapArbiterPath::Refund),
        "punish" => Ok(SwapArbiterPath::Punish),
        _ => Err("invalid arbiter path".into()),
    }
}

fn path_index(path: SwapArbiterPath) -> usize {
    match path {
        SwapArbiterPath::Claim => 0,
        SwapArbiterPath::Refund => 1,
        SwapArbiterPath::Punish => 2,
    }
}

struct Party {
    role: Role,
    settlement_id: [u8; 32],
    context_hash: [u8; 32],
    chain_id: [u8; 32],
    secret: CrossCurveSecret252,
    own_claim: CrossCurvePublicClaim,
    peer_claim: Option<CrossCurvePublicClaim>,
    joint_xmr_key: Option<[u8; 32]>,
    contract: Option<[u8; SWAP_ARBITER_CONTRACT_SIZE]>,
    authorized_dom_offers: [Option<[u8; 32]>; 3],
}

impl Party {
    fn bind_peer(&mut self, request: &Value) -> Result<Value, String> {
        if self.peer_claim.is_some() {
            return Err("peer proof already bound".into());
        }
        let proof: BoundCrossCurveProofV1 = serde_json::from_value(
            request
                .get("proof")
                .cloned()
                .ok_or_else(|| "missing proof".to_string())?,
        )
        .map_err(|_| "invalid peer proof encoding".to_string())?;
        let peer_claim = verify_bound(
            &proof,
            &self.settlement_id,
            &self.context_hash,
            self.role.peer_proof_role(),
        )
        .map_err(|_| "peer DLEQ proof failed".to_string())?;
        if peer_claim == self.own_claim {
            return Err("peer reused local share".into());
        }
        let own = CompressedEdwardsY(self.own_claim.ed_compressed)
            .decompress()
            .ok_or_else(|| "local XMR point failed".to_string())?;
        let peer = CompressedEdwardsY(peer_claim.ed_compressed)
            .decompress()
            .ok_or_else(|| "peer XMR point failed".to_string())?;
        let joint = (own + peer).compress().to_bytes();
        if joint == [0; 32] {
            return Err("joint XMR key is invalid".into());
        }
        self.peer_claim = Some(peer_claim);
        self.joint_xmr_key = Some(joint);
        Ok(json!({"joint_xmr_key":hex(&joint)}))
    }

    fn authorize_dom(&mut self, request: &Value) -> Result<Value, String> {
        if self.peer_claim.is_none() {
            return Err("peer proof not bound".into());
        }
        let contract_bytes = decode_hex(string_field(request, "contract")?)?;
        let contract = SwapArbiterContract::from_bytes(&contract_bytes)
            .map_err(|_| "invalid arbiter contract".to_string())?;
        let contract_bytes: [u8; SWAP_ARBITER_CONTRACT_SIZE] = contract_bytes
            .try_into()
            .map_err(|_| "wrong arbiter contract length".to_string())?;
        if self
            .contract
            .is_some_and(|current| current != contract_bytes)
        {
            return Err("arbiter contract changed".into());
        }
        let offer_bytes = decode_hex(string_field(request, "offer")?)?;
        let offer_digest = digest(&offer_bytes);
        let offer = DomClaimOffer::from_swap_arbiter_resume_bytes(&offer_bytes, offer_digest)
            .map_err(|_| "invalid DOM offer".to_string())?;
        let path = offer
            .swap_arbiter_path()
            .map_err(|_| "offer is not an arbiter path".to_string())?;
        if !self.role.permits_dom_completion(path)
            || offer.chain_id() != &self.chain_id
            || offer.adaptor_point().to_compressed_bytes() != self.own_claim.secp_compressed
            || offer
                .swap_arbiter_intent()
                .map_err(|_| "invalid offer intent".to_string())?
                != contract.intent(path)
        {
            return Err("offer does not match the participant contract".into());
        }
        let slot = &mut self.authorized_dom_offers[path_index(path)];
        if slot.is_some_and(|current| current != offer_digest) {
            return Err("DOM offer changed after authorization".into());
        }
        self.contract = Some(contract_bytes);
        *slot = Some(offer_digest);
        Ok(json!({"offer_digest":hex(&offer_digest)}))
    }

    fn complete_dom(&self, request: &Value) -> Result<Value, String> {
        if self.peer_claim.is_none() {
            return Err("peer proof not bound".into());
        }
        let bytes = decode_hex(string_field(request, "offer")?)?;
        let offer_digest = digest(&bytes);
        let offer = DomClaimOffer::from_swap_arbiter_resume_bytes(&bytes, offer_digest)
            .map_err(|_| "invalid DOM offer".to_string())?;
        let path = offer
            .swap_arbiter_path()
            .map_err(|_| "offer is not an arbiter path".to_string())?;
        if !self.role.permits_dom_completion(path)
            || offer.chain_id() != &self.chain_id
            || offer.adaptor_point().to_compressed_bytes() != self.own_claim.secp_compressed
            || self.authorized_dom_offers[path_index(path)] != Some(offer_digest)
        {
            return Err("offer is not assigned to this participant".into());
        }
        let height = u64_field(request, "height")?;
        let transaction = offer
            .complete(
                &SecretScalar::from_be_bytes(self.secret.dom_secret_big_endian())
                    .map_err(|_| "invalid local DOM share".to_string())?,
                &ValidationContext {
                    current_height: BlockHeight(height),
                    chain_id: self.chain_id,
                    now: Timestamp(u64::MAX),
                },
            )
            .map_err(|_| "DOM completion failed".to_string())?;
        let transaction = transaction
            .to_bytes()
            .map_err(|_| "DOM transaction encoding failed".to_string())?;
        Ok(json!({"transaction":hex(&transaction)}))
    }

    fn sign_xmr(&self, request: &Value) -> Result<Value, String> {
        let peer_claim = self
            .peer_claim
            .as_ref()
            .ok_or_else(|| "peer proof not bound".to_string())?;
        let path = parse_path(string_field(request, "path")?)?;
        if !self.role.permits_xmr_signing(path) {
            return Err("XMR spend is not assigned to this participant".into());
        }
        let opening = fixed_hex::<32>(string_field(request, "opening")?)?;
        let peer_share = revealed_dom_secret_to_xmr_scalar(opening, peer_claim)
            .map_err(|_| "DOM opening does not match peer DLEQ proof".to_string())?;
        let own_share = Option::<Scalar>::from(Scalar::from_canonical_bytes(
            self.secret.xmr_share_little_endian(),
        ))
        .ok_or_else(|| "local XMR share is invalid".to_string())?;
        let peer_share = Option::<Scalar>::from(Scalar::from_canonical_bytes(peer_share))
            .ok_or_else(|| "peer XMR share is invalid".to_string())?;
        let joint = own_share + peer_share;
        if (joint * ED25519_BASEPOINT_POINT).compress().to_bytes()
            != self
                .joint_xmr_key
                .ok_or_else(|| "joint XMR key missing".to_string())?
        {
            return Err("reconstructed XMR key does not match setup".into());
        }
        let signable_bytes = decode_hex(string_field(request, "signable")?)?;
        let mut input = signable_bytes.as_slice();
        let signable = SignableTransaction::read(&mut input)
            .map_err(|_| "invalid signable XMR transaction".to_string())?;
        if !input.is_empty() {
            return Err("trailing XMR signable bytes".into());
        }
        let transaction = signable
            .sign(&mut OsRng, &Zeroizing::new(MoneroScalar::from(joint)))
            .map_err(|_| "XMR signing failed".to_string())?;
        let transaction_id: [u8; 32] = transaction
            .hash()
            .as_ref()
            .try_into()
            .map_err(|_| "invalid XMR transaction hash".to_string())?;
        Ok(json!({
            "transaction":hex(&transaction.serialize()),
            "transaction_id":hex(&transaction_id),
        }))
    }

    fn handle(&mut self, request: &Value) -> Result<Value, String> {
        match string_field(request, "op")? {
            "bind-peer" => self.bind_peer(request),
            "authorize-dom" => self.authorize_dom(request),
            "complete-dom" => self.complete_dom(request),
            "sign-xmr" => self.sign_xmr(request),
            _ => Err("unknown operation".into()),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let role = Role::parse(&args.next().ok_or("missing role")?)?;
    let settlement_id = fixed_hex::<32>(&args.next().ok_or("missing settlement id")?)?;
    let context_hash = fixed_hex::<32>(&args.next().ok_or("missing context hash")?)?;
    let chain_id = fixed_hex::<32>(&args.next().ok_or("missing chain id")?)?;
    if args.next().is_some() {
        return Err("too many arguments".into());
    }

    let secret = CrossCurveSecret252::generate(&mut OsRng);
    let proof = prove_bound(
        &secret,
        settlement_id,
        context_hash,
        role.proof_role(),
        &mut OsRng,
    )?;
    let own_claim = secret.public_claim()?;
    let mut party = Party {
        role,
        settlement_id,
        context_hash,
        chain_id,
        secret,
        own_claim,
        peer_claim: None,
        joint_xmr_key: None,
        contract: None,
        authorized_dom_offers: [None; 3],
    };

    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(
        &mut stdout,
        &json!({"ok":true,"role":role.label(),"proof":proof}),
    )?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;

    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    loop {
        let mut line = String::new();
        let length = reader.read_line(&mut line)?;
        if length == 0 {
            break;
        }
        if length > MAX_LINE_BYTES {
            serde_json::to_writer(
                &mut stdout,
                &json!({"ok":false,"error":"request too large"}),
            )?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
            continue;
        }
        let response = serde_json::from_str::<Value>(&line)
            .map_err(|_| "invalid request JSON".to_string())
            .and_then(|request| party.handle(&request));
        match response {
            Ok(value) => serde_json::to_writer(&mut stdout, &json!({"ok":true,"value":value}))?,
            Err(error) => serde_json::to_writer(&mut stdout, &json!({"ok":false,"error":error}))?,
        }
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}
