//! Local test-only client. The producer exits before public solving. The RSA
//! setup remains centralized; no adversarial delay or erasure claim is made.
use curve25519_dalek::scalar::Scalar;
use dxp1_clsag_lab::{
    recovery::{RecoveryError, RecoveryPlan, RecoveryShare, RecoveryWindow},
    recovery_challenge::RecoveryChallenge,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
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
fn frame(reader: &mut impl BufRead) -> Value {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take(4 * 1024 * 1024 + 1)
        .read_until(b'\n', &mut bytes)
        .unwrap();
    assert!(bytes.len() <= 4 * 1024 * 1024 && bytes.last() == Some(&b'\n'));
    serde_json::from_slice(&bytes).unwrap()
}
fn share(v: &Value) -> RecoveryShare {
    let bytes: [u8; 32] = serde_json::from_value(v["scalar"].clone()).unwrap();
    RecoveryShare {
        index: serde_json::from_value(v["index"].clone()).unwrap(),
        scalar: Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).unwrap(),
    }
}
fn challenge(plan: &RecoveryPlan, offer: &Value) -> RecoveryChallenge {
    let puzzles = offer["puzzles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap().as_bytes().to_vec())
        .collect::<Vec<_>>();
    RecoveryChallenge::derive(
        plan,
        offer["setup"].as_str().unwrap().as_bytes(),
        &puzzles,
        offer["proof"].as_str().unwrap().as_bytes(),
    )
    .unwrap()
}

struct PreparedPublicSession {
    process: LabChild,
    writer: ChildStdin,
    reader: BufReader<ChildStdout>,
    setup_verification_seconds: f64,
    offer_verification_seconds: f64,
}

pub struct PublicCapsule {
    pub challenge: RecoveryChallenge,
    pub window: RecoveryWindow,
    offer: Value,
    plan: RecoveryPlan,
    session: Option<PreparedPublicSession>,
}

#[derive(Debug, Default)]
pub struct SolveEvidence {
    pub attempted_indexes: Vec<u16>,
    pub rejected_indexes: Vec<u16>,
    pub sequential_solve_seconds: f64,
    pub verification_and_solve_seconds: f64,
    pub public_offer_verifications: u32,
    pub public_verification_seconds: f64,
    pub setup_verification_seconds: f64,
    pub setup_verified_before_offer: bool,
    pub public_offer_verified_before_funding: bool,
}

impl PublicCapsule {
    pub fn prepare(
        bridge: &Path,
        plan: &RecoveryPlan,
        shares: Zeroizing<Vec<RecoveryShare>>,
    ) -> Self {
        Self::try_prepare(bridge, plan, shares).unwrap()
    }

    // Returns a rejected challenge opening to the adversarial fixture. The
    // fixture may generate a fresh offer, never change an existing challenge.
    pub fn try_prepare(
        bridge: &Path,
        plan: &RecoveryPlan,
        shares: Zeroizing<Vec<RecoveryShare>>,
    ) -> Result<Self, RecoveryError> {
        assert!(bridge.is_absolute() && bridge.is_file());
        assert_eq!(shares.len(), usize::from(plan.participants));
        let mut producer = LabChild(
            Command::new(bridge)
                .arg("open-staged")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let mut writer = producer.0.stdin.take().unwrap();
        let mut reader = BufReader::new(producer.0.stdout.take().unwrap());
        let request = Zeroizing::new(
            serde_json::to_vec(&json!({"shares":shares.iter()
            .map(|s| s.scalar.to_bytes()).collect::<Vec<_>>()}))
            .unwrap(),
        );
        writer.write_all(&request).unwrap();
        writer.write_all(b"\n").unwrap();
        writer.flush().unwrap();
        drop(request);
        drop(shares);
        let announced = frame(&mut reader);
        assert_eq!(announced["result"], "setup");
        let setup = announced["setup"].as_str().unwrap();
        let setup_binding = Sha256::digest(setup.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let mut process = LabChild(
            Command::new(bridge)
                .arg("prepare-session")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let mut public_writer = process.0.stdin.take().unwrap();
        let mut public_reader = BufReader::new(process.0.stdout.take().unwrap());
        serde_json::to_writer(&mut public_writer, &json!({"setup":setup})).unwrap();
        public_writer.write_all(b"\n").unwrap();
        public_writer.flush().unwrap();
        let setup_ready = frame(&mut public_reader);
        assert_eq!(setup_ready["result"], "setup_ready");
        assert_eq!(setup_ready["setup_binding"], setup_binding);
        assert_eq!(setup_ready["setup_verifications"], 1);
        let setup_seconds = setup_ready["setup_verification_seconds"].as_f64().unwrap();
        assert!(setup_seconds.is_finite() && setup_seconds >= 0.0);
        // Only after public verification of these exact parameters can the
        // honest producer create and disclose the ciphertexts/proof.
        serde_json::to_writer(&mut writer, &json!({"accepted_setup":setup_binding})).unwrap();
        writer.write_all(b"\n").unwrap();
        writer.flush().unwrap();
        let offer = frame(&mut reader);
        assert_eq!(offer["setup"], setup);
        let challenge = challenge(plan, &offer);
        let delayed_index = challenge.delayed_indexes()[0];
        serde_json::to_writer(
            &mut writer,
            &json!({"opened":challenge.opened_indexes(),"delayed":delayed_index}),
        )
        .unwrap();
        writer.write_all(b"\n").unwrap();
        drop(writer);
        let response = frame(&mut reader);
        assert!(producer.0.wait().unwrap().success());
        drop(producer);
        assert!(
            response["openings"].is_null() || response["openings"].as_array().unwrap().is_empty()
        );
        assert_eq!(response["public_verified_openings"], true);
        serde_json::to_writer(
            &mut public_writer,
            &json!({
                "offer":offer,"opened":response["opened"],"indexes":challenge.delayed_indexes()
            }),
        )
        .unwrap();
        public_writer.write_all(b"\n").unwrap();
        public_writer.flush().unwrap();
        let verified = frame(&mut public_reader);
        assert_eq!(verified["result"], "ready");
        assert_eq!(verified["checked_openings"], plan.participants / 2);
        assert_eq!(verified["setup_relation_verified"], true);
        assert_eq!(verified["setup_verified_before_offer"], true);
        assert_eq!(verified["setup_binding"], setup_binding);
        assert_eq!(verified["public_solver_no_dealer_secrets"], true);
        assert_eq!(verified["public_offer_verifications"], 1);
        assert_eq!(verified["range_proof_verified"], true);
        assert_eq!(
            serde_json::from_value::<Vec<u16>>(verified["indexes"].clone()).unwrap(),
            challenge.delayed_indexes()
        );
        let offer_seconds = verified["public_verification_seconds"].as_f64().unwrap();
        assert!(offer_seconds.is_finite() && offer_seconds >= 0.0);
        let window = challenge.window(
            plan,
            response["opened"]
                .as_array()
                .unwrap()
                .iter()
                .map(share)
                .collect(),
        )?;
        Ok(Self {
            challenge,
            window,
            offer,
            plan: plan.clone(),
            session: Some(PreparedPublicSession {
                process,
                writer: public_writer,
                reader: public_reader,
                setup_verification_seconds: setup_seconds,
                offer_verification_seconds: offer_seconds,
            }),
        })
    }

    pub fn solve(mut self) -> Result<(RecoveryShare, SolveEvidence), SolveEvidence> {
        let started = Instant::now();
        assert_eq!(
            challenge(&self.plan, &self.offer).binding(),
            self.challenge.binding()
        );
        self.challenge
            .validate_window(&self.plan, &self.window)
            .unwrap();
        let PreparedPublicSession {
            mut process,
            mut writer,
            mut reader,
            setup_verification_seconds,
            offer_verification_seconds,
        } = self
            .session
            .take()
            .expect("public preparation session missing");
        let mut result = self.solve_with(|index| {
            serde_json::to_writer(&mut writer, &json!({"index":index})).unwrap();
            writer.write_all(b"\n").unwrap();
            writer.flush().unwrap();
            let solved = frame(&mut reader);
            let opening = match solved["result"].as_str().unwrap() {
                "solved" => Some(share(&solved["opening"])),
                "invalid" => {
                    assert_eq!(solved["index"], index);
                    assert_eq!(solved["reason"], "noncanonical_plaintext");
                    None
                }
                _ => panic!("unexpected solver response"),
            };
            (opening, solved["solve_seconds"].as_f64().unwrap())
        });
        // Closing stdin cancels every unrequested candidate. Wait for an exact
        // completion count and successful exit; do not hide work at shutdown.
        drop(writer);
        let closed = frame(&mut reader);
        assert_eq!(closed["result"], "closed");
        assert_eq!(closed["public_offer_verifications"], 1);
        let evidence = match &mut result {
            Ok((_, evidence)) | Err(evidence) => evidence,
        };
        assert_eq!(closed["completed"], evidence.attempted_indexes.len());
        assert!(process.0.wait().unwrap().success());
        evidence.public_offer_verifications = 1;
        evidence.public_verification_seconds = offer_verification_seconds;
        evidence.setup_verification_seconds = setup_verification_seconds;
        evidence.setup_verified_before_offer = true;
        evidence.public_offer_verified_before_funding = true;
        evidence.verification_and_solve_seconds = started.elapsed().as_secs_f64();
        result
    }

    fn solve_with(
        &self,
        mut solver: impl FnMut(u16) -> (Option<RecoveryShare>, f64),
    ) -> Result<(RecoveryShare, SolveEvidence), SolveEvidence> {
        let started = Instant::now();
        self.challenge
            .validate_window(&self.plan, &self.window)
            .unwrap();
        let mut evidence = SolveEvidence::default();
        // Cut-and-choose does not establish that the FIRST delayed scalar is
        // correct. Every candidate remains subject to the Feldman commitment.
        // Bound this search to the committed delayed set, each index once.
        for &index in self.challenge.delayed_indexes() {
            let (delayed, seconds) = solver(index);
            assert!(seconds.is_finite() && seconds >= 0.0);
            evidence.attempted_indexes.push(index);
            evidence.sequential_solve_seconds += seconds;
            if let Some(delayed) = delayed {
                if delayed.index == index && self.plan.verify_share(&delayed).is_ok() {
                    evidence.verification_and_solve_seconds = started.elapsed().as_secs_f64();
                    return Ok((delayed, evidence));
                }
            }
            evidence.rejected_indexes.push(index);
        }
        evidence.verification_and_solve_seconds = started.elapsed().as_secs_f64();
        Err(evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn fixture() -> (PublicCapsule, Zeroizing<Vec<RecoveryShare>>) {
        let (plan, shares) = RecoveryPlan::from_secret(
            [31; 32],
            &Zeroizing::new(Scalar::from(19u64)),
            4,
            6,
            &mut OsRng,
        )
        .unwrap();
        let challenge =
            RecoveryChallenge::derive(&plan, b"fixture setup", &vec![vec![1]; 6], b"fixture proof")
                .unwrap();
        let opened = challenge
            .opened_indexes()
            .iter()
            .map(|&i| shares[usize::from(i) - 1].clone())
            .collect();
        let window = challenge.window(&plan, opened).unwrap();
        (
            PublicCapsule {
                challenge,
                window,
                plan,
                offer: Value::Null,
                session: None,
            },
            Zeroizing::new(shares),
        )
    }

    #[test]
    fn bad_first_share_is_skipped_and_all_solve_costs_are_retained() {
        let (capsule, shares) = fixture();
        let indexes = capsule.challenge.delayed_indexes();
        let (delayed, evidence) = capsule
            .solve_with(|i| {
                let mut share = shares[usize::from(i) - 1].clone();
                if i == indexes[0] {
                    share.scalar += Scalar::ONE;
                }
                (Some(share), 2.0)
            })
            .unwrap();
        assert_eq!(delayed.index, indexes[1]);
        assert_eq!(evidence.attempted_indexes, indexes[..2]);
        assert_eq!(evidence.rejected_indexes, indexes[..1]);
        assert_eq!(evidence.sequential_solve_seconds, 4.0);
        let recovered = capsule
            .window
            .recover_with_delayed_share(&capsule.plan, delayed)
            .unwrap();
        assert_eq!(*recovered, Scalar::from(19u64));
    }

    #[test]
    fn exhausted_wrong_or_relabelled_openings_never_return_a_share() {
        for relabel in [false, true] {
            let (capsule, shares) = fixture();
            let evidence = capsule
                .solve_with(|i| {
                    let mut share = shares[usize::from(i) - 1].clone();
                    if relabel {
                        // Even a valid polynomial share is not the requested puzzle.
                        share =
                            shares[usize::from(capsule.challenge.opened_indexes()[0]) - 1].clone();
                    } else {
                        share.scalar += Scalar::ONE;
                    }
                    (Some(share), 1.0)
                })
                .unwrap_err();
            assert_eq!(
                evidence.attempted_indexes,
                capsule.challenge.delayed_indexes()
            );
            assert_eq!(evidence.rejected_indexes, evidence.attempted_indexes);
            assert_eq!(evidence.sequential_solve_seconds, 3.0);
        }
    }

    #[test]
    fn noncanonical_plaintext_rejection_does_not_hide_cost_or_abort_remaining_shares() {
        let (capsule, shares) = fixture();
        let first = capsule.challenge.delayed_indexes()[0];
        let (valid, evidence) = capsule
            .solve_with(|index| {
                if index == first {
                    (None, 3.0)
                } else {
                    (Some(shares[usize::from(index) - 1].clone()), 2.0)
                }
            })
            .unwrap();
        assert_eq!(evidence.rejected_indexes, [first]);
        assert_eq!(evidence.attempted_indexes.len(), 2);
        assert_eq!(evidence.sequential_solve_seconds, 5.0);
        assert_eq!(
            *capsule
                .window
                .recover_with_delayed_share(&capsule.plan, valid)
                .unwrap(),
            Scalar::from(19u64)
        );
        let exhausted = capsule.solve_with(|_| (None, 1.0)).unwrap_err();
        assert_eq!(
            exhausted.rejected_indexes,
            capsule.challenge.delayed_indexes()
        );
        assert_eq!(exhausted.sequential_solve_seconds, 3.0);
    }
}
