//! Isolated share holder used by the funded DXA1 integration experiment.
//!
//! The process generates one cross-curve share and never returns it. It emits
//! only its public DLEQ proof, completes the DOM path assigned to its role, and
//! signs an already constructed Monero transaction after verifying the peer's
//! opening. Requests and responses are newline-delimited JSON on stdio.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
};
use dom_consensus::{SwapArbiterContract, SwapArbiterPath, Transaction, ValidationContext};
use dom_core::{BlockHeight, Timestamp, SWAP_ARBITER_CONTRACT_SIZE};
use dom_crypto::{pedersen::BlindingFactor, PublicKey, SchnorrSignature, SecretKey};
use dom_scriptless_primitives::SecretScalar;
use dom_serialization::{DomDeserialize, DomSerialize};
use dxp1_clsag_lab::{
    claim_resume::digest,
    dom_joint::{DomCommitment, DomRoundOne, DomRoundTwo, DomSigner, DomSigningIntent},
    dom_reserve::{
        ReserveCommitment, ReserveFinalizer, ReserveIntent, ReserveResponse, ReserveRoundOne,
        ReserveShare,
    },
    native_dom::{DomClaimOffer, PreparedDomClaim},
};
use monero_wallet::{ed25519::Scalar as MoneroScalar, send::SignableTransaction};
use rand_core::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use xmr_dleq_sigma::{
    prove_bound, revealed_dom_secret_to_xmr_scalar, verify_bound, BoundCrossCurveProofV1,
    CrossCurvePublicClaim, CrossCurveSecret252, ROLE_XMR_REFUND_SHARE, ROLE_XMR_SHARED_SPEND,
};
use zeroize::Zeroizing;

const MAX_LINE_BYTES: usize = 1 << 20;
const STATE_MAGIC: &[u8] = b"DXA1/party-state/v1\0";
const STATE_BODY_BYTES: usize = STATE_MAGIC.len() + 1 + 32 + 32 + 32 + 32;
const STATE_BYTES: usize = STATE_BODY_BYTES + 32;

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

    fn tag(self) -> u8 {
        match self {
            Self::DomOwner => 1,
            Self::XmrOwner => 2,
        }
    }
}

fn sync_parent(path: &Path) -> io::Result<()> {
    File::open(
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| io::Error::other("state path has no parent"))?,
    )?
    .sync_all()
}

fn load_or_create_secret(
    path: &Path,
    role: Role,
    settlement_id: [u8; 32],
    context_hash: [u8; 32],
    chain_id: [u8; 32],
) -> io::Result<(File, CrossCurveSecret252, bool)> {
    let binding_prefix = || {
        let mut bytes = Vec::with_capacity(STATE_BODY_BYTES);
        bytes.extend(STATE_MAGIC);
        bytes.push(role.tag());
        bytes.extend(settlement_id);
        bytes.extend(context_hash);
        bytes.extend(chain_id);
        bytes
    };
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            file.try_lock()
                .map_err(|_| io::Error::other("party state is locked"))?;
            let secret = CrossCurveSecret252::generate(&mut OsRng);
            let mut bytes = Zeroizing::new(binding_prefix());
            bytes.extend(secret.xmr_share_little_endian());
            let checksum = Sha256::digest(&*bytes);
            bytes.extend(checksum);
            debug_assert_eq!(bytes.len(), STATE_BYTES);
            file.write_all(&bytes)?;
            file.sync_all()?;
            sync_parent(path)?;
            Ok((file, secret, false))
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
                return Err(io::Error::other("unsafe party state file"));
            }
            let mut file = OpenOptions::new().read(true).write(true).open(path)?;
            file.try_lock()
                .map_err(|_| io::Error::other("party state is locked"))?;
            let mut bytes = Zeroizing::new(Vec::with_capacity(STATE_BYTES));
            (&mut file)
                .take((STATE_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.len() != STATE_BYTES
                || bytes[..STATE_BODY_BYTES - 32] != binding_prefix()
                || bytes[STATE_BODY_BYTES..] != Sha256::digest(&bytes[..STATE_BODY_BYTES])[..]
            {
                return Err(io::Error::other("corrupt or mismatched party state"));
            }
            let secret = CrossCurveSecret252::from_little_endian(
                bytes[STATE_BODY_BYTES - 32..STATE_BODY_BYTES]
                    .try_into()
                    .map_err(|_| io::Error::other("invalid party state secret"))?,
            )
            .map_err(io::Error::other)?;
            Ok((file, secret, true))
        }
        Err(error) => Err(error),
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

fn two_hex<const N: usize>(request: &Value, name: &str) -> Result<[[u8; N]; 2], String> {
    let values = request
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing {name}"))?;
    if values.len() != 2 {
        return Err(format!("{name} must contain two entries"));
    }
    Ok([
        fixed_hex(
            values[0]
                .as_str()
                .ok_or_else(|| format!("invalid {name}"))?,
        )?,
        fixed_hex(
            values[1]
                .as_str()
                .ok_or_else(|| format!("invalid {name}"))?,
        )?,
    ])
}

fn path_feature(path: SwapArbiterPath) -> u8 {
    match path {
        SwapArbiterPath::Claim => dom_core::KERNEL_FEAT_SWAP_CLAIM,
        SwapArbiterPath::Refund => dom_core::KERNEL_FEAT_SWAP_REFUND,
        SwapArbiterPath::Punish => dom_core::KERNEL_FEAT_SWAP_PUNISH,
    }
}

struct Party {
    _state_file: File,
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
    dom_signing_keys: [SecretKey; 3],
    reserve_shares: [Option<ReserveShare>; 3],
    reserve_rounds: [Option<ReserveRoundOne>; 3],
    reserve_finalizers: [Option<ReserveFinalizer>; 3],
    dom_rounds: [Option<DomRoundOne>; 3],
    dom_finalizers: [Option<DomRoundTwo>; 3],
}

impl Party {
    fn signer_index(&self) -> u8 {
        match self.role {
            Role::DomOwner => 0,
            Role::XmrOwner => 1,
        }
    }

    fn configure_branch(&mut self, request: &Value) -> Result<Value, String> {
        if self.peer_claim.is_none() {
            return Err("peer proof not bound".into());
        }
        let path = parse_path(string_field(request, "path")?)?;
        let index = path_index(path);
        if self.reserve_shares[index].is_some() {
            return Err("branch already configured".into());
        }
        let kernel_blind =
            BlindingFactor::from_bytes(self.dom_signing_keys[index].to_be_bytes_raw())
                .map_err(|_| "invalid local DOM signing share".to_string())?;
        let output_blind = match self.role {
            Role::DomOwner => {
                let input = BlindingFactor::from_bytes(fixed_hex(string_field(
                    request,
                    "input_blinding",
                )?)?)
                .map_err(|_| "invalid DOM input blinding".to_string())?;
                input
                    .add(&kernel_blind)
                    .map_err(|_| "invalid DOM output share".to_string())?
            }
            Role::XmrOwner => {
                if request.get("input_blinding").is_some() {
                    return Err("XMR owner must not receive DOM input blinding".into());
                }
                kernel_blind
            }
        };
        let share = ReserveShare::from_blinding(output_blind);
        let output_key = share.public_key().to_compressed_bytes();
        let kernel_key = self.dom_signing_keys[index]
            .public_key()
            .to_compressed_bytes();
        self.reserve_shares[index] = Some(share);
        Ok(json!({
            "kernel_key":hex(&kernel_key),
            "output_share_key":hex(&output_key),
        }))
    }

    fn reserve_intent(&self, request: &Value) -> Result<ReserveIntent, String> {
        let keys = two_hex::<33>(request, "output_share_keys")?
            .map(|bytes| PublicKey::from_compressed_bytes(&bytes))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "invalid DOM output share key".to_string())?
            .try_into()
            .map_err(|_| "invalid DOM output key roster".to_string())?;
        ReserveIntent::new(
            u64_field(request, "value")?,
            self.chain_id,
            fixed_hex(string_field(request, "session")?)?,
            fixed_hex(string_field(request, "terms")?)?,
            keys,
        )
        .map_err(|_| "invalid DOM reserve intent".to_string())
    }

    fn reserve_possession(&self, request: &Value) -> Result<Value, String> {
        let path = parse_path(string_field(request, "path")?)?;
        let intent = self.reserve_intent(request)?;
        let proof = self.reserve_shares[path_index(path)]
            .as_ref()
            .ok_or_else(|| "branch is not configured".to_string())?
            .prove(&intent, self.signer_index())
            .map_err(|_| "DOM reserve possession proof failed".to_string())?;
        Ok(json!({"proof":hex(&proof.to_bytes())}))
    }

    fn reserve_plan(
        &self,
        request: &Value,
    ) -> Result<dxp1_clsag_lab::dom_reserve::VerifiedReserve, String> {
        let proofs = two_hex::<65>(request, "proofs")?.map(|bytes| {
            SchnorrSignature::from_bytes(&bytes)
                .map_err(|_| "invalid DOM reserve possession proof".to_string())
        });
        let [first, second] = proofs;
        self.reserve_intent(request)?
            .authorize([first?, second?])
            .map_err(|_| "DOM reserve authorization failed".to_string())
    }

    fn reserve_round_one(&mut self, request: &Value) -> Result<Value, String> {
        let path = parse_path(string_field(request, "path")?)?;
        let slot = path_index(path);
        if self.reserve_rounds[slot].is_some() || self.reserve_finalizers[slot].is_some() {
            return Err("DOM reserve round already active".into());
        }
        let plan = self.reserve_plan(request)?;
        let share = self.reserve_shares[slot]
            .as_ref()
            .ok_or_else(|| "branch is not configured".to_string())?;
        let (round, commitment) = share
            .begin_proof(
                plan,
                self.signer_index(),
                &Zeroizing::new(fixed_hex(string_field(request, "common_seed")?)?),
                &mut OsRng,
            )
            .map_err(|_| "DOM reserve round one failed".to_string())?;
        self.reserve_rounds[slot] = Some(round);
        Ok(json!({
            "plan":hex(&commitment.plan),
            "index":commitment.index,
            "t_one":hex(&commitment.t_one),
            "t_two":hex(&commitment.t_two),
        }))
    }

    fn reserve_round_two(&mut self, request: &Value) -> Result<Value, String> {
        let path = parse_path(string_field(request, "path")?)?;
        let slot = path_index(path);
        let peer = ReserveCommitment {
            plan: fixed_hex(string_field(request, "plan")?)?,
            index: u8::try_from(u64_field(request, "index")?)
                .map_err(|_| "invalid reserve peer index".to_string())?,
            t_one: fixed_hex(string_field(request, "t_one")?)?,
            t_two: fixed_hex(string_field(request, "t_two")?)?,
        };
        let round = self.reserve_rounds[slot]
            .take()
            .ok_or_else(|| "DOM reserve round one missing".to_string())?;
        let (finalizer, response) = round
            .respond(&peer)
            .map_err(|_| "DOM reserve response failed".to_string())?;
        self.reserve_finalizers[slot] = Some(finalizer);
        Ok(json!({
            "round":hex(&response.round),
            "index":response.index,
            "scalar":hex(response.scalar.as_slice()),
        }))
    }

    fn reserve_complete(&mut self, request: &Value) -> Result<Value, String> {
        let path = parse_path(string_field(request, "path")?)?;
        let slot = path_index(path);
        let peer = ReserveResponse {
            round: fixed_hex(string_field(request, "round")?)?,
            index: u8::try_from(u64_field(request, "index")?)
                .map_err(|_| "invalid reserve peer index".to_string())?,
            scalar: Zeroizing::new(fixed_hex(string_field(request, "scalar")?)?),
        };
        let proof = self.reserve_finalizers[slot]
            .take()
            .ok_or_else(|| "DOM reserve finalizer missing".to_string())?
            .complete(peer)
            .map_err(|_| "DOM reserve finalization failed".to_string())?;
        Ok(json!({"range_proof":hex(&proof)}))
    }

    fn dom_intent(
        &self,
        request: &Value,
        path: SwapArbiterPath,
    ) -> Result<DomSigningIntent, String> {
        let peer_claim = self
            .peer_claim
            .as_ref()
            .ok_or_else(|| "peer proof not bound".to_string())?;
        let transaction =
            Transaction::from_bytes(&decode_hex(string_field(request, "transaction")?)?)
                .map_err(|_| "invalid unsigned DOM transaction".to_string())?;
        if transaction
            .kernels
            .first()
            .is_none_or(|kernel| kernel.features != path_feature(path))
        {
            return Err("DOM transaction path mismatch".into());
        }
        let prepared = PreparedDomClaim::new_swap_arbiter_path(transaction, self.chain_id)
            .map_err(|_| "invalid DOM arbiter transaction".to_string())?;
        let adaptor =
            PublicKey::from_compressed_bytes(&fixed_hex::<33>(string_field(request, "adaptor")?)?)
                .map_err(|_| "invalid DOM adaptor point".to_string())?;
        let adaptor_owner_is_local = match path {
            SwapArbiterPath::Refund => self.role == Role::DomOwner,
            SwapArbiterPath::Claim | SwapArbiterPath::Punish => self.role == Role::XmrOwner,
        };
        let expected_adaptor = if adaptor_owner_is_local {
            self.own_claim.secp_compressed
        } else {
            peer_claim.secp_compressed
        };
        if adaptor.to_compressed_bytes() != expected_adaptor {
            return Err("DOM adaptor does not match the bound XMR share".into());
        }
        let keys = two_hex::<33>(request, "kernel_keys")?
            .map(|bytes| PublicKey::from_compressed_bytes(&bytes))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "invalid DOM kernel key".to_string())?
            .try_into()
            .map_err(|_| "invalid DOM kernel key roster".to_string())?;
        DomSigningIntent::new(
            prepared,
            adaptor,
            keys,
            fixed_hex(string_field(request, "session")?)?,
            fixed_hex(string_field(request, "route")?)?,
        )
        .map_err(|_| "invalid DOM signing intent".to_string())
    }

    fn dom_possession(&self, request: &Value) -> Result<Value, String> {
        let path = parse_path(string_field(request, "path")?)?;
        let proof = self
            .dom_intent(request, path)?
            .prove_share(
                self.signer_index(),
                &self.dom_signing_keys[path_index(path)],
            )
            .map_err(|_| "DOM signing possession proof failed".to_string())?;
        Ok(json!({"proof":hex(&proof.to_bytes())}))
    }

    fn dom_plan(
        &self,
        request: &Value,
        path: SwapArbiterPath,
    ) -> Result<dxp1_clsag_lab::dom_joint::DomSigningPlan, String> {
        let proofs = two_hex::<65>(request, "proofs")?.map(|bytes| {
            SchnorrSignature::from_bytes(&bytes)
                .map_err(|_| "invalid DOM signing possession proof".to_string())
        });
        let [first, second] = proofs;
        self.dom_intent(request, path)?
            .authorize([first?, second?])
            .map_err(|_| "DOM signing authorization failed".to_string())
    }

    fn dom_round_one(&mut self, request: &Value) -> Result<Value, String> {
        let path = parse_path(string_field(request, "path")?)?;
        let slot = path_index(path);
        if self.dom_rounds[slot].is_some() || self.dom_finalizers[slot].is_some() {
            return Err("DOM signing round already active".into());
        }
        let signer = DomSigner::new(
            self.dom_plan(request, path)?,
            self.signer_index(),
            self.dom_signing_keys[slot].clone(),
        )
        .map_err(|_| "DOM signer setup failed".to_string())?;
        let (round, commitment) = signer
            .preprocess(&mut OsRng)
            .map_err(|_| "DOM signing round one failed".to_string())?;
        self.dom_rounds[slot] = Some(round);
        Ok(json!({
            "plan":hex(&commitment.plan),
            "signer":commitment.signer,
            "nonces":[hex(&commitment.nonces[0]),hex(&commitment.nonces[1])],
        }))
    }

    fn dom_round_two(&mut self, request: &Value) -> Result<Value, String> {
        let path = parse_path(string_field(request, "path")?)?;
        let slot = path_index(path);
        let peer = DomCommitment {
            plan: fixed_hex(string_field(request, "plan")?)?,
            signer: u8::try_from(u64_field(request, "signer")?)
                .map_err(|_| "invalid DOM signer index".to_string())?,
            nonces: two_hex(request, "nonces")?,
        };
        let round = self.dom_rounds[slot]
            .take()
            .ok_or_else(|| "DOM signing round one missing".to_string())?;
        let (finalizer, response) = round
            .sign(&peer)
            .map_err(|_| "DOM signing response failed".to_string())?;
        self.dom_finalizers[slot] = Some(finalizer);
        Ok(json!({
            "round":hex(&response.round),
            "signer":response.signer,
            "scalar":hex(&response.scalar),
        }))
    }

    fn dom_presign_complete(&mut self, request: &Value) -> Result<Value, String> {
        let path = parse_path(string_field(request, "path")?)?;
        let slot = path_index(path);
        let peer = dxp1_clsag_lab::dom_joint::DomResponse {
            round: fixed_hex(string_field(request, "round")?)?,
            signer: u8::try_from(u64_field(request, "signer")?)
                .map_err(|_| "invalid DOM signer index".to_string())?,
            scalar: fixed_hex(string_field(request, "scalar")?)?,
        };
        let offer = self.dom_finalizers[slot]
            .take()
            .ok_or_else(|| "DOM signing finalizer missing".to_string())?
            .complete(&peer)
            .map_err(|_| "DOM presignature finalization failed".to_string())?;
        let bytes = offer
            .to_swap_arbiter_resume_bytes()
            .map_err(|_| "DOM offer encoding failed".to_string())?;
        Ok(json!({"offer":hex(&bytes)}))
    }

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
            "configure-branch" => self.configure_branch(request),
            "reserve-possession" => self.reserve_possession(request),
            "reserve-round-one" => self.reserve_round_one(request),
            "reserve-round-two" => self.reserve_round_two(request),
            "reserve-complete" => self.reserve_complete(request),
            "dom-possession" => self.dom_possession(request),
            "dom-round-one" => self.dom_round_one(request),
            "dom-round-two" => self.dom_round_two(request),
            "dom-presign-complete" => self.dom_presign_complete(request),
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
    let state_path = PathBuf::from(args.next().ok_or("missing state path")?);
    if args.next().is_some() {
        return Err("too many arguments".into());
    }

    let (state_file, secret, restored) =
        load_or_create_secret(&state_path, role, settlement_id, context_hash, chain_id)?;
    let proof = prove_bound(
        &secret,
        settlement_id,
        context_hash,
        role.proof_role(),
        &mut OsRng,
    )?;
    let own_claim = secret.public_claim()?;
    let dom_signing_keys = std::array::from_fn(|_| {
        SecretKey::from_bytes(BlindingFactor::random().as_bytes()).expect("random DOM scalar")
    });
    let mut party = Party {
        _state_file: state_file,
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
        dom_signing_keys,
        reserve_shares: std::array::from_fn(|_| None),
        reserve_rounds: std::array::from_fn(|_| None),
        reserve_finalizers: std::array::from_fn(|_| None),
        dom_rounds: std::array::from_fn(|_| None),
        dom_finalizers: std::array::from_fn(|_| None),
    };

    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(
        &mut stdout,
        &json!({"ok":true,"role":role.label(),"proof":proof,"restored":restored}),
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
