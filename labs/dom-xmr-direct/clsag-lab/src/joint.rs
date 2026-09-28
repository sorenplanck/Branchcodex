//! Experimental 2-of-2 CLSAG adaptor signing, without reconstructing the spend key.
//!
//! This reuses modular-frost's nonce machine and monero-oxide's CLSAG share
//! signing/verification. The new adapter offsets both aggregate nonce points.
//! It reconstructs the public ring transcript at the pinned upstream revision
//! to verify the resulting PRE-signature instead of an already final CLSAG.
//!
//! The public API consumes each round, including on errors. No preprocess seed,
//! private nonce, cache restoration or arbitrary-message signing is exposed.
//! Durable nonce consumption and authenticated peer transport remain required.

use std::{
    collections::HashMap,
    io::{self, Read},
};

use dalek_ff_group as dfg;
use frost::{
    algorithm::Algorithm,
    curve::Ed25519,
    sign::{
        AlgorithmMachine, AlgorithmSignMachine, AlgorithmSignatureMachine, PreprocessMachine,
        SignMachine, SignatureMachine, Writable,
    },
    FrostError, Participant, ThresholdKeys, ThresholdView,
};
use group::Group;
use monero_clsag::{Clsag, ClsagAddendum, ClsagContext, ClsagMultisig, Decoys};
use monero_ed25519::{Commitment, CompressedPoint, Point, Scalar as MoneroScalar};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha2::{Digest, Sha512};
use transcript::{RecommendedTranscript, Transcript as _};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    prepare_ring, Context, Error, PreSignature, Scalar, Statement, Transcript, G, RING_SIZE,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JointError {
    Crypto(Error),
    Setup,
    Wire,
    Signing(FrostError),
}

impl From<Error> for JointError {
    fn from(error: Error) -> Self {
        Self::Crypto(error)
    }
}
impl From<FrostError> for JointError {
    fn from(error: FrostError) -> Self {
        Self::Signing(error)
    }
}

/// An immutable signing intent. It is not evidence of on-chain funding.
#[derive(Clone)]
pub struct JointPlan {
    context: Context,
    statement: Statement,
    offsets: Vec<u64>,
    tag: [u8; 64],
}

impl JointPlan {
    /// Bind the exact public capsule transcript as well as its selected window.
    /// The backend must independently verify the setup, puzzles and openings;
    /// this constructor alone does not authorize funding or establish delay.
    pub fn new_with_capsule(
        context: Context,
        statement: Statement,
        session: [u8; 32],
        offsets: Vec<u64>,
        recovery: &crate::recovery::RecoveryPlan,
        challenge: &crate::recovery_challenge::RecoveryChallenge,
        window: &crate::recovery::RecoveryWindow,
    ) -> Result<Self, JointError> {
        challenge
            .validate_window(recovery, window)
            .map_err(|_| JointError::Setup)?;
        let mut plan =
            Self::new_with_recovery(context, statement, session, offsets, recovery, window)?;
        let mut hash = Sha512::new();
        hash.update(b"DXP1/CLSAG-lab/joint-plan/capsule/v1");
        hash.update(plan.tag);
        hash.update(challenge.binding());
        plan.tag = hash.finalize().into();
        Ok(plan)
    }

    /// Bind a full input-key recovery plan to this signing session. This checks
    /// public consistency only: it does not prove a timed capsule exists or
    /// authorize funding. Share-key recovery needs a separate setup protocol.
    pub fn new_with_recovery(
        context: Context,
        statement: Statement,
        session: [u8; 32],
        offsets: Vec<u64>,
        recovery: &crate::recovery::RecoveryPlan,
        window: &crate::recovery::RecoveryWindow,
    ) -> Result<Self, JointError> {
        context.validate()?;
        if recovery.domain != session
            || recovery.public_key().map_err(|_| JointError::Setup)?
                != context.ring[context.real][0]
        {
            return Err(JointError::Setup);
        }
        let recovery_binding = window.binding(recovery).map_err(|_| JointError::Setup)?;
        let mut plan = Self::new(context, statement, session, offsets)?;
        let mut hash = Sha512::new();
        hash.update(b"DXP1/CLSAG-lab/joint-plan/recovery/v1");
        hash.update(plan.tag);
        hash.update(recovery_binding);
        plan.tag = hash.finalize().into();
        Ok(plan)
    }

    pub fn new(
        context: Context,
        statement: Statement,
        session: [u8; 32],
        offsets: Vec<u64>,
    ) -> Result<Self, JointError> {
        statement.verify(&context)?;
        if session == [0; 32] || offsets.len() != RING_SIZE {
            return Err(JointError::Setup);
        }
        // Native Decoys validates relative offsets; real chain membership is
        // not available in this signature laboratory.
        decoys(&context, offsets.clone())?;
        let mut hash = Sha512::new();
        hash.update(b"DXP1/CLSAG-lab/joint-plan/v1");
        hash.update(session);
        hash.update(context.binding());
        for point in [statement.t_g, statement.t_h, statement.r_g, statement.r_h] {
            hash.update(point.compress().as_bytes());
        }
        hash.update(statement.response.to_bytes());
        for offset in &offsets {
            hash.update(offset.to_le_bytes());
        }
        Ok(Self {
            context,
            statement,
            offsets,
            tag: hash.finalize().into(),
        })
    }
}

/// Shared knowledge of the input commitment, not of its private spend key.
pub struct InputOpening {
    pub commitment: Commitment,
    pub pseudo_mask: Zeroizing<Scalar>,
}

fn decoys(context: &Context, offsets: Vec<u64>) -> Result<Decoys, JointError> {
    Decoys::new(
        offsets,
        context.real as u8,
        context
            .ring
            .iter()
            .map(|pair| pair.map(Point::from))
            .collect(),
    )
    .ok_or(JointError::Setup)
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Interim {
    signature: Clsag,
    challenged_mask: Scalar,
}

// Kept private: only the wrappers below may choose messages and participant sets.
#[derive(Zeroize, ZeroizeOnDrop)]
struct JointAlgorithm {
    inner: ClsagMultisig,
    context: Context,
    statement: Statement,
    mask_delta: Zeroizing<Scalar>,
    arithmetic: Transcript,
    d: CompressedPoint,
    image_sum: dfg::EdwardsPoint,
    processed: usize,
    interim: Option<Interim>,
}

impl JointAlgorithm {
    fn new(plan: &JointPlan, opening: InputOpening) -> Result<Self, JointError> {
        let pseudo = Commitment::new(
            MoneroScalar::from(*opening.pseudo_mask),
            opening.commitment.amount,
        );
        if pseudo.commit().into() != plan.context.pseudo_out {
            return Err(JointError::Setup);
        }
        let delta = Zeroizing::new(opening.commitment.mask.into() - *opening.pseudo_mask);
        let d = CompressedPoint::from(
            (*delta * plan.context.image_generator() * MoneroScalar::INV_EIGHT.into())
                .compress()
                .to_bytes(),
        );
        let arithmetic = Transcript::new(&plan.context, d)?;
        let native_context = ClsagContext::new(
            decoys(&plan.context, plan.offsets.clone())?,
            opening.commitment,
        )
        .map_err(|_| JointError::Setup)?;
        let mut transcript = RecommendedTranscript::new(b"DXP1/CLSAG-lab/joint/v1");
        transcript.append_message(b"plan", plan.tag);
        let (inner, mask_sender) = ClsagMultisig::new(transcript, native_context);
        mask_sender.send(*opening.pseudo_mask);
        Ok(Self {
            inner,
            context: plan.context.clone(),
            statement: plan.statement.clone(),
            mask_delta: delta,
            arithmetic,
            d,
            image_sum: dfg::EdwardsPoint::identity(),
            processed: 0,
            interim: None,
        })
    }
}

impl Algorithm<Ed25519> for JointAlgorithm {
    type Transcript = RecommendedTranscript;
    type Addendum = ClsagAddendum;
    type Signature = PreSignature;

    fn transcript(&mut self) -> &mut RecommendedTranscript {
        self.inner.transcript()
    }
    fn nonces(&self) -> Vec<Vec<dfg::EdwardsPoint>> {
        self.inner.nonces()
    }
    fn preprocess_addendum<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        keys: &ThresholdKeys<Ed25519>,
    ) -> ClsagAddendum {
        self.inner.preprocess_addendum(rng, keys)
    }
    fn read_addendum<R: Read>(&self, reader: &mut R) -> io::Result<ClsagAddendum> {
        self.inner.read_addendum(reader)
    }
    fn process_addendum(
        &mut self,
        view: &ThresholdView<Ed25519>,
        participant: Participant,
        addendum: ClsagAddendum,
    ) -> Result<(), FrostError> {
        let factor =
            view.interpolation_factor(participant)
                .ok_or(FrostError::InvalidSigningSet(
                    "missing interpolation factor",
                ))?;
        let mut contribution = addendum.key_image_share() * factor * view.scalar();
        if self.processed == 0 {
            contribution += dfg::EdwardsPoint(self.context.image_generator() * view.offset());
        }
        self.inner.process_addendum(view, participant, addendum)?;
        self.image_sum += contribution;
        self.processed += 1;
        if self.processed == 2 && self.image_sum.0 != self.context.image {
            return Err(FrostError::InvalidSigningSet(
                "key image differs from the fixed plan",
            ));
        }
        Ok(())
    }
    fn sign_share(
        &mut self,
        view: &ThresholdView<Ed25519>,
        sums: &[Vec<dfg::EdwardsPoint>],
        nonces: Vec<Zeroizing<dfg::Scalar>>,
        message: &[u8],
    ) -> dfg::Scalar {
        // The private adapter is reached only through RoundOne::sign, which
        // supplies the fixed 32-byte message and exactly the two participants.
        assert_eq!(message, self.context.message);
        assert_eq!(self.processed, 2);
        let mut adjusted = sums.to_vec();
        adjusted[0][0] += dfg::EdwardsPoint(self.statement.t_g);
        adjusted[0][1] += dfg::EdwardsPoint(self.statement.t_h);

        // Match the pinned native sign_core's public decoy responses. Cloning
        // this transcript does not clone any nonce or change the inner state.
        let seed = self.inner.transcript().clone().rng_seed(b"decoy_responses");
        let (signature, c) = prepare_ring(
            &self.context,
            &self.arithmetic,
            self.d,
            adjusted[0][0].0,
            adjusted[0][1].0,
            &mut ChaCha20Rng::from_seed(seed),
        );
        self.interim = Some(Interim {
            signature,
            challenged_mask: c * self.arithmetic.mu_c * *self.mask_delta,
        });
        // Native code alone consumes the nonce and this participant's key share.
        self.inner.sign_share(view, &adjusted, nonces, message)
    }
    fn verify(
        &self,
        key: dfg::EdwardsPoint,
        _: &[Vec<dfg::EdwardsPoint>],
        sum: dfg::Scalar,
    ) -> Option<PreSignature> {
        if key.0 != self.context.ring[self.context.real][0] {
            return None;
        }
        let interim = self.interim.as_ref()?;
        let mut signature = interim.signature.clone();
        signature.s[self.context.real] = MoneroScalar::from(sum - interim.challenged_mask);
        let pre = PreSignature {
            signature,
            statement: self.statement.clone(),
        };
        pre.verify(&self.context).ok()?;
        Some(pre)
    }
    fn verify_share(
        &self,
        key: dfg::EdwardsPoint,
        nonces: &[Vec<dfg::EdwardsPoint>],
        share: dfg::Scalar,
    ) -> Result<Vec<(dfg::Scalar, dfg::EdwardsPoint)>, ()> {
        // Each individual share still obeys r_i - c_p*x_i. The adaptor offset
        // belongs to the aggregate nonce, not to any participant's response.
        self.inner.verify_share(key, nonces, share)
    }
}

/// Signing entry point. Key generation and authentication of the public roster
/// are outside this primitive; only an already agreed 2-of-2 key is accepted.
pub struct JointParticipant {
    machine: AlgorithmMachine<Ed25519, JointAlgorithm>,
    plan: JointPlan,
    us: Participant,
    peer: Participant,
}

impl JointParticipant {
    pub fn new(
        plan: JointPlan,
        opening: InputOpening,
        keys: ThresholdKeys<Ed25519>,
    ) -> Result<Self, JointError> {
        let params = keys.params();
        if params.t() != 2
            || params.n() != 2
            || keys.group_key().0 != plan.context.ring[plan.context.real][0]
            || **keys.original_secret_share() * G != keys.original_verification_share(params.i()).0
        {
            return Err(JointError::Setup);
        }
        for id in params.all_participant_indexes() {
            if !crate::valid_point(&keys.original_verification_share(id).0) {
                return Err(JointError::Setup);
            }
        }
        let peer = Participant::new(if u16::from(params.i()) == 1 { 2 } else { 1 })
            .ok_or(JointError::Setup)?;
        let machine = AlgorithmMachine::new(JointAlgorithm::new(&plan, opening)?, keys);
        Ok(Self {
            machine,
            plan,
            us: params.i(),
            peer,
        })
    }

    pub fn preprocess(self, rng: &mut (impl RngCore + CryptoRng)) -> (RoundOne, Vec<u8>) {
        let (machine, preprocess) = self.machine.preprocess(rng);
        let message = envelope(1, self.us, &self.plan.tag, &preprocess.serialize());
        (
            RoundOne {
                machine,
                plan: self.plan,
                us: self.us,
                peer: self.peer,
                ours: message.clone(),
            },
            message,
        )
    }
}

/// Owns nonces for exactly one signing attempt; neither Clone nor serialization.
///
/// ```compile_fail
/// use dxp1_clsag_lab::joint::RoundOne;
/// fn reuse(round: RoundOne, peer: &[u8]) {
///     let _ = round.sign(peer);
///     let _ = round.sign(peer);
/// }
/// ```
pub struct RoundOne {
    machine: AlgorithmSignMachine<Ed25519, JointAlgorithm>,
    plan: JointPlan,
    us: Participant,
    peer: Participant,
    ours: Vec<u8>,
}

impl RoundOne {
    pub fn sign(self, peer_message: &[u8]) -> Result<(RoundTwo, Vec<u8>), JointError> {
        let mut payload = decode(peer_message, 1, self.peer, &self.plan.tag)?;
        let preprocess = self
            .machine
            .read_preprocess(&mut payload)
            .map_err(|_| JointError::Wire)?;
        if !payload.is_empty() {
            return Err(JointError::Wire);
        }
        let mut hash = Sha512::new();
        hash.update(b"DXP1/CLSAG-lab/joint-round/v1");
        let messages = if u16::from(self.us) == 1 {
            [&self.ours[..], peer_message]
        } else {
            [peer_message, &self.ours[..]]
        };
        for message in messages {
            hash.update((message.len() as u64).to_le_bytes());
            hash.update(message);
        }
        let tag = hash.finalize().into();
        let (machine, share) = self.machine.sign(
            HashMap::from([(self.peer, preprocess)]),
            &self.plan.context.message,
        )?;
        let message = envelope(2, self.us, &tag, &share.serialize());
        Ok((
            RoundTwo {
                machine,
                plan: self.plan,
                peer: self.peer,
                tag,
            },
            message,
        ))
    }
}

/// Accepts the peer response only for the exact pair of round-one messages.
pub struct RoundTwo {
    machine: AlgorithmSignatureMachine<Ed25519, JointAlgorithm>,
    plan: JointPlan,
    peer: Participant,
    tag: [u8; 64],
}

impl RoundTwo {
    pub fn complete(self, peer_message: &[u8]) -> Result<PreSignature, JointError> {
        let mut payload = decode(peer_message, 2, self.peer, &self.tag)?;
        let share = self
            .machine
            .read_share(&mut payload)
            .map_err(|_| JointError::Wire)?;
        if !payload.is_empty() {
            return Err(JointError::Wire);
        }
        let pre = self.machine.complete(HashMap::from([(self.peer, share)]))?;
        pre.verify(&self.plan.context)?;
        Ok(pre)
    }
}

const MAGIC: &[u8; 8] = b"DXP1CS01";
const HEADER: usize = 8 + 1 + 2 + 64;
const MAX_MESSAGE: usize = HEADER + 4096;

fn envelope(kind: u8, sender: Participant, tag: &[u8; 64], payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER + payload.len());
    bytes.extend_from_slice(MAGIC);
    bytes.push(kind);
    bytes.extend_from_slice(&u16::from(sender).to_le_bytes());
    bytes.extend_from_slice(tag);
    bytes.extend_from_slice(payload);
    bytes
}

fn decode<'a>(
    bytes: &'a [u8],
    kind: u8,
    sender: Participant,
    tag: &[u8; 64],
) -> Result<&'a [u8], JointError> {
    if bytes.len() < HEADER
        || bytes.len() > MAX_MESSAGE
        || &bytes[..8] != MAGIC
        || bytes[8] != kind
        || bytes[9..11] != u16::from(sender).to_le_bytes()
        || bytes[11..HEADER] != tag[..]
    {
        return Err(JointError::Wire);
    }
    Ok(&bytes[HEADER..])
}
