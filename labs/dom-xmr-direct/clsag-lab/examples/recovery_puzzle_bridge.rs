//! Disposable lab shares; Go is a trusted local helper, not a remote prover.
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};
use dalek_ff_group::EdwardsPoint as GroupPoint;
use dxp1_clsag_lab::{
    joint::{InputOpening, JointParticipant, JointPlan},
    recovery::{RecoveryError, RecoveryPlan, RecoveryShare, RecoveryWindow},
    recovery_challenge::RecoveryChallenge,
    Context, Statement, RING_SIZE,
};
use frost::{curve::Ed25519, dkg::Interpolation, Participant, ThresholdKeys, ThresholdParams};
use monero_ed25519::{Commitment, Point, Scalar as MoneroScalar};
use rand_core::OsRng;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    process::{Child, Command, Stdio},
    time::Instant,
};
use zeroize::Zeroizing;

struct LabChild(Child);
impl Drop for LabChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn frame(reader: &mut impl BufRead) -> Result<Value, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    reader
        .take(4 * 1024 * 1024 + 1)
        .read_until(b'\n', &mut bytes)?;
    if bytes.len() > 4 * 1024 * 1024 || bytes.last() != Some(&b'\n') {
        return Err("invalid bridge frame".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}
fn share(value: &Value) -> Result<RecoveryShare, Box<dyn std::error::Error>> {
    let index = serde_json::from_value(value["index"].clone())?;
    let bytes: [u8; 32] = serde_json::from_value(value["scalar"].clone())?;
    let scalar =
        Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).ok_or("noncanonical share")?;
    Ok(RecoveryShare { index, scalar })
}
fn verify_public_openings(
    path: &str,
    offer: &Value,
    opened: &Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let mut child = LabChild(
        Command::new(path)
            .arg("verify-openings")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?,
    );
    let mut writer = child.0.stdin.take().ok_or("missing verifier stdin")?;
    let mut reader = BufReader::new(child.0.stdout.take().ok_or("missing verifier stdout")?);
    serde_json::to_writer(&mut writer, &json!({"offer":offer, "opened":opened}))?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    drop(writer);
    let response = frame(&mut reader)?;
    if !child.0.wait()?.success() {
        return Err("public verifier failed".into());
    }
    Ok(response)
}

// Disposable centralized keys and a synthetic ring. This connects the real
// capsule bytes to joint CLSAG signing; it does not establish a funded input.
fn sign_with_capsule(
    secret: &Zeroizing<Scalar>,
    recovery: &RecoveryPlan,
    challenge: &RecoveryChallenge,
    window: &RecoveryWindow,
) -> Result<(), Box<dyn std::error::Error>> {
    let ids = [Participant::new(1).unwrap(), Participant::new(2).unwrap()];
    let first = Zeroizing::new(Scalar::random(&mut OsRng));
    let second = Zeroizing::new(**secret - *first);
    let roster = HashMap::from([
        (ids[0], GroupPoint(*first * G)),
        (ids[1], GroupPoint(*second * G)),
    ]);
    let keys = [first, second]
        .into_iter()
        .enumerate()
        .map(|(i, share)| {
            ThresholdKeys::<Ed25519>::new(
                ThresholdParams::new(2, 2, ids[i]).unwrap(),
                Interpolation::Constant(vec![Scalar::ONE; 2]),
                share,
                roster.clone(),
            )
            .map_err(|e| format!("keys: {e:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let key = recovery.public_key().map_err(|e| format!("key: {e:?}"))?;
    let commitment = Commitment::new(MoneroScalar::random(&mut OsRng), 6_000_000);
    let pseudo_mask = Zeroizing::new(Scalar::random(&mut OsRng));
    let mut ring = std::array::from_fn(|i| {
        [
            Scalar::random(&mut OsRng) * G,
            Commitment::new(MoneroScalar::random(&mut OsRng), 700 + i as u64)
                .commit()
                .into(),
        ]
    });
    let real = 4;
    ring[real] = [key, commitment.commit().into()];
    let generator: curve25519_dalek::edwards::EdwardsPoint =
        Point::biased_hash(key.compress().to_bytes()).into();
    let context = Context {
        ring,
        real,
        image: generator * **secret,
        message: [55; 32],
        route_binding: [38; 32],
        pseudo_out: Commitment::new(MoneroScalar::from(*pseudo_mask), commitment.amount)
            .commit()
            .into(),
    };
    let witness = Zeroizing::new(Scalar::random(&mut OsRng));
    let statement = Statement::prove(&context, &witness, &mut OsRng)
        .map_err(|e| format!("statement: {e:?}"))?;
    let plan = JointPlan::new_with_capsule(
        context.clone(),
        statement,
        recovery.domain,
        vec![1; RING_SIZE],
        recovery,
        challenge,
        window,
    )
    .map_err(|e| format!("capsule plan: {e:?}"))?;
    let mut rounds = keys
        .into_iter()
        .map(|keys| {
            JointParticipant::new(
                plan.clone(),
                InputOpening {
                    commitment: commitment.clone(),
                    pseudo_mask: pseudo_mask.clone(),
                },
                keys,
            )
            .map(|p| p.preprocess(&mut OsRng))
            .map_err(|e| format!("participant: {e:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (b, mb) = rounds.pop().ok_or("missing second signer")?;
    let (a, ma) = rounds.pop().ok_or("missing first signer")?;
    let (a, sa) = a.sign(&mb).map_err(|e| format!("sign a: {e:?}"))?;
    let (b, sb) = b.sign(&ma).map_err(|e| format!("sign b: {e:?}"))?;
    let pa = a.complete(&sb).map_err(|e| format!("complete a: {e:?}"))?;
    let pb = b.complete(&sa).map_err(|e| format!("complete b: {e:?}"))?;
    if pa != pb {
        return Err("signers disagree".into());
    }
    let signature = pa
        .complete(&context, &witness)
        .map_err(|e| format!("adapt: {e:?}"))?;
    context
        .verify_native(&signature)
        .map_err(|e| format!("native verify: {e:?}"))?;
    if *pb
        .extract(&context, &signature)
        .map_err(|e| format!("extract: {e:?}"))?
        != *witness
    {
        return Err("wrong extracted witness".into());
    }
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("pass absolute lab bridge path")?;
    if !std::path::Path::new(&path).is_absolute() {
        return Err("bridge path must be absolute".into());
    }
    let participants: u16 = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "198".into())
        .parse()?;
    if ![6, 132, 166, 198].contains(&participants) {
        return Err("unsupported share count".into());
    }
    let threshold = participants / 2 + 1;
    let started = Instant::now();
    let secret = Zeroizing::new(Scalar::random(&mut OsRng));
    let (plan, shares) =
        RecoveryPlan::from_secret([81; 32], &secret, threshold, participants, &mut OsRng)
            .map_err(|e| format!("plan: {e:?}"))?;
    let mut child = LabChild(
        Command::new(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?,
    );
    let mut writer = child.0.stdin.take().ok_or("missing stdin")?;
    let mut reader = BufReader::new(child.0.stdout.take().ok_or("missing stdout")?);
    let request = Zeroizing::new(serde_json::to_vec(
        &json!({"shares": shares.iter().map(|s| s.scalar.to_bytes()).collect::<Vec<_>>()}),
    )?);
    writer.write_all(&request)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    let offer = frame(&mut reader)?;
    let setup = offer["setup"].as_str().ok_or("missing setup")?;
    let proof = offer["proof"].as_str().ok_or("missing proof")?;
    let puzzles = offer["puzzles"]
        .as_array()
        .ok_or("missing puzzles")?
        .iter()
        .map(|p| {
            p.as_str()
                .map(|s| s.as_bytes().to_vec())
                .ok_or("invalid puzzle")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let challenge = RecoveryChallenge::derive(&plan, setup.as_bytes(), &puzzles, proof.as_bytes())
        .map_err(|e| format!("challenge: {e:?}"))?;
    let delayed_index = challenge.delayed_indexes()[0];
    serde_json::to_writer(
        &mut writer,
        &json!({"opened":challenge.opened_indexes(), "delayed":delayed_index}),
    )?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    drop(writer);
    let response = frame(&mut reader)?;
    if !child.0.wait()?.success() {
        return Err("bridge failed".into());
    }
    if response["range_bits"] != 160
        || response["rejected_mutated_proof"] != true
        || response["rejected_wrong_nonce"] != true
        || response["public_verified_openings"] != true
        || response["checked_openings"] != participants / 2
    {
        return Err("missing verification results".into());
    }
    let public_verification = verify_public_openings(&path, &offer, &response["opened"])?;
    if public_verification["result"] != "verified"
        || public_verification["public_verifier_no_share_secret"] != true
        || public_verification["setup_relation_verified"] != true
        || public_verification["rejected_wrong_nonce"] != true
        || public_verification["checked_openings"] != participants / 2
    {
        return Err("public opening verification failed".into());
    }
    let opened = response["opened"]
        .as_array()
        .ok_or("missing opened shares")?
        .iter()
        .map(share)
        .collect::<Result<Vec<_>, _>>()?;
    let window = challenge
        .window(&plan, opened)
        .map_err(|e| format!("window: {e:?}"))?;
    let signing_started = Instant::now();
    sign_with_capsule(&secret, &plan, &challenge, &window)?;
    let signing_seconds = signing_started.elapsed().as_secs_f64();
    let openings = response["openings"]
        .as_array()
        .ok_or("missing delayed opening")?;
    if openings.len() != 1 {
        return Err("wrong delayed opening count".into());
    }
    let delayed = share(&openings[0])?;
    if delayed.index != delayed_index {
        return Err("wrong delayed index".into());
    }
    let mut forged = delayed.clone();
    forged.scalar += Scalar::ONE;
    if window.recover_with_delayed_share(&plan, forged) != Err(RecoveryError::Share) {
        return Err("forged delayed share accepted".into());
    }
    if *window
        .recover_with_delayed_share(&plan, delayed)
        .map_err(|e| format!("recovery: {e:?}"))?
        != *secret
    {
        return Err("wrong secret".into());
    }
    println!(
        "{}",
        json!({"result":"passed", "curve":"Ed25519", "rsa_bits":2048,
        "participants":participants, "threshold":threshold, "squarings":200000,
        "challenge_bound_to_real_capsule":true, "checked_openings":response["checked_openings"],
        "rejected_wrong_nonce":true, "rejected_mutated_proof":true, "rejected_forged_share":true,
        "recovered_original_key":true, "range_bits":160,
        "setup_seconds":response["setup_seconds"], "encryption_seconds":response["encryption_seconds"],
        "proof_generation_seconds":response["proof_generation_seconds"], "proof_verification_seconds":response["proof_verification_seconds"],
        "opening_verification_seconds":response["opening_verification_seconds"], "solve_seconds":response["solve_seconds"],
        "external_public_proof_verification_seconds":public_verification["proof_verification_seconds"],
        "external_public_opening_verification_seconds":public_verification["opening_verification_seconds"],
        "external_public_verifier_no_share_secret":true,
        "external_public_setup_relation_verified":true,
        "capsule_bound_joint_signature_native_verified":true,
        "joint_signature_witness_extracted":true,
        "joint_signing_seconds":signing_seconds,
        "total_seconds":started.elapsed().as_secs_f64(),
        "scope":"public opening verification and capsule-bound joint CLSAG on a synthetic ring with disposable centralized keys; not a funded swap or audited pre-funding verifier"})
    );
    Ok(())
}
