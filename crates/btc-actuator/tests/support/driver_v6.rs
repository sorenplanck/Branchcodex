//! Actual MuSig2 operations, Unix sockets and physical journal reopens.
use super::*;
use btc_actuator::{
    drive_bitcoin_claim_v6, BitcoinClaimDriverErrorV6 as DriverError,
    BitcoinClaimExchangePhaseV6 as Phase, BitcoinClaimMessageV3, BitcoinClaimSigningPortV6,
    BitcoinClaimTransportV6, BitcoinPreSignatureV1, UnixBitcoinClaimTransportV6,
};
use std::{os::unix::net::UnixStream, time::Duration};

struct Party {
    directory: tempfile::TempDir,
    owner: [u8; 32],
    authority: BitcoinParticipantClaimAuthorityV1,
    vault: BitcoinParticipantNonceVaultV1,
    store: DurableBitcoinActuatorV1,
    seal: BitcoinNonceSealKeyV1,
    session: BitcoinClaimSessionV1,
    scope: BitcoinActuationScopeV1,
    now: u64,
    authorizations: usize,
}
impl Party {
    fn create(role: BitcoinParticipantRoleV1) -> TestResult<Self> {
        let deployment = deployment()?;
        let maker = role == BitcoinParticipantRoleV1::Maker;
        let (id, mut secret) = if maker {
            ([1; 32], [0x11; 32])
        } else {
            ([2; 32], [0x22; 32])
        };
        let authority = BitcoinParticipantClaimAuthorityV1::authorize_local_key(
            BitcoinParticipantClaimAuthorityRequestV1 {
                deployment: &deployment,
                route_id: ROUTE,
                terms_digest: TERMS,
                participant_id: id,
                role,
                expected_public_key: compressed(secret)?,
            },
            &mut secret,
        )?;
        assert_eq!(secret, [0; 32]);
        let roster = ParticipantKeyRosterV1::new([
            ParticipantKeyV1 {
                participant_id: [1; 32],
                role: BitcoinSignerRoleV1::Maker,
                compressed_key: compressed([0x11; 32])?,
            },
            ParticipantKeyV1 {
                participant_id: [2; 32],
                role: BitcoinSignerRoleV1::Taker,
                compressed_key: compressed([0x22; 32])?,
            },
        ])?;
        let (session, scope) = session_and_scope(
            &deployment,
            roster,
            compressed([0x33; 32])?[1..].try_into()?,
            compressed([0x2b; 32])?,
            // v6 driver predates the v11 route-terms binding.
            None,
        )?;
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let vault = BitcoinParticipantNonceVaultV1::create(
            &directory.path().join("nonce.sqlite"),
            &authority,
        )?;
        let mut store =
            DurableBitcoinActuatorV1::create(&directory.path().join("actuator.sqlite"), id)?;
        store.acquire_lease(100, 5_000)?;
        Ok(Self {
            directory,
            owner: id,
            authority,
            vault,
            store,
            seal: BitcoinNonceSealKeyV1::new(if maker { [0x61; 32] } else { [0x62; 32] })?,
            session,
            scope,
            now: 100,
            authorizations: 0,
        })
    }
    fn fresh(&mut self) -> Result<AnchoredCrossChainWindowV1, BitcoinActuatorErrorV1> {
        self.now += 1;
        self.authorizations += 1;
        m8_authorization().map_err(|_| BitcoinActuatorErrorV1::ClaimAuthorityMismatch)
    }
    fn retain_final(
        &mut self,
        exact: btc_actuator::ExactBitcoinTransactionV1,
    ) -> TestResult<Vec<u8>> {
        let deployment = deployment()?;
        let final_scope =
            BitcoinActuationScopeV1::authorize(BitcoinActuationScopeAuthorizationV1 {
                deployment: &deployment,
                route_id: ROUTE,
                effect_id: EFFECT,
                leg: BitcoinLegV1::Downstream,
                action: BitcoinActionV1::Claim,
                fence_epoch: 1,
                terms_digest: TERMS,
                expected_txid: self.scope.expected_txid(),
                intent_digest: exact.intent_digest(),
                contract_outpoint: Some(BitcoinOutpointV1 {
                    txid: FUNDING_TXID,
                    vout: FUNDING_VOUT,
                }),
                contract_amount_sat: FUNDING_AMOUNT,
                refund_record_digest: None,
                fee_policy: self.scope.fee_policy(),
                valid_until_ms: 10_000,
            })?;
        self.store
            .prepare_terminal(&final_scope, exact, self.now + 1)?;
        Ok(
            Connection::open(self.directory.path().join("actuator.sqlite"))?.query_row(
                "SELECT raw_transaction FROM operations WHERE effect_id=?1",
                [EFFECT.as_slice()],
                |row| row.get(0),
            )?,
        )
    }
    fn reopen(self) -> TestResult<Self> {
        let Self {
            directory,
            owner,
            authority,
            vault,
            store,
            seal,
            session,
            scope,
            now,
            authorizations,
        } = self;
        drop(store);
        drop(vault);
        let store = DurableBitcoinActuatorV1::open_existing(
            &directory.path().join("actuator.sqlite"),
            owner,
        )?;
        let vault = BitcoinParticipantNonceVaultV1::open_existing(
            &directory.path().join("nonce.sqlite"),
            &authority,
        )?;
        Ok(Self {
            directory,
            owner,
            authority,
            vault,
            store,
            seal,
            session,
            scope,
            now,
            authorizations,
        })
    }
}
impl BitcoinClaimSigningPortV6 for Party {
    type Completion = BitcoinPreSignatureV1;
    fn expose_nonce(&mut self) -> Result<BitcoinClaimMessageV3, BitcoinActuatorErrorV1> {
        let authorization = self.fresh()?;
        self.store
            .expose_claim_message_v3(BitcoinClaimSigningContextV1 {
                scope: &self.scope,
                authority: &self.authority,
                session: &self.session,
                authorization,
                seal_key: &self.seal,
                participant_state: &mut self.vault,
                now_ms: self.now,
            })
    }
    fn produce_partial(
        &mut self,
        peer: &BitcoinClaimMessageV3,
    ) -> Result<BitcoinClaimMessageV3, BitcoinActuatorErrorV1> {
        let authorization = self.fresh()?;
        self.store.produce_claim_message_v3(
            BitcoinClaimSigningContextV1 {
                scope: &self.scope,
                authority: &self.authority,
                session: &self.session,
                authorization,
                seal_key: &self.seal,
                participant_state: &mut self.vault,
                now_ms: self.now,
            },
            peer,
        )
    }
    fn complete(
        &mut self,
        nonce: &BitcoinClaimMessageV3,
        partial: &BitcoinClaimMessageV3,
    ) -> Result<Self::Completion, BitcoinActuatorErrorV1> {
        let authorization = self.fresh()?;
        self.store.aggregate_claim_messages_v3(
            BitcoinClaimSigningContextV1 {
                scope: &self.scope,
                authority: &self.authority,
                session: &self.session,
                authorization,
                seal_key: &self.seal,
                participant_state: &mut self.vault,
                now_ms: self.now,
            },
            nonce,
            partial,
        )
    }
}
struct Capture {
    inner: UnixBitcoinClaimTransportV6,
    frames: Vec<Vec<u8>>,
    stop_at_partial: bool,
}
impl BitcoinClaimTransportV6 for Capture {
    fn exchange(
        &mut self,
        phase: Phase,
        local: &BitcoinClaimMessageV3,
    ) -> Result<BitcoinClaimMessageV3, DriverError> {
        self.frames.push(local.to_bytes());
        if self.stop_at_partial && phase == Phase::Partial {
            return Err(DriverError::TransportUnavailable);
        }
        self.inner.exchange(phase, local)
    }
}
fn pair_transport() -> TestResult<(Capture, Capture)> {
    let (a, b) = UnixStream::pair()?;
    let make = |s| -> Result<Capture, DriverError> {
        Ok(Capture {
            inner: UnixBitcoinClaimTransportV6::new(s, Duration::from_secs(2))?,
            frames: Vec::new(),
            stop_at_partial: false,
        })
    };
    Ok((make(a)?, make(b)?))
}
fn parallel_round(
    a: &mut Party,
    b: &mut Party,
    x: &mut Capture,
    y: &mut Capture,
) -> (
    Result<BitcoinPreSignatureV1, DriverError>,
    Result<BitcoinPreSignatureV1, DriverError>,
) {
    std::thread::scope(|threads| {
        let peer = threads.spawn(|| drive_bitcoin_claim_v6(b, y));
        let local = drive_bitcoin_claim_v6(a, x);
        let remote = match peer.join() {
            Ok(value) => value,
            Err(_) => Err(DriverError::TransportUnavailable),
        };
        (local, remote)
    })
}

#[test]
fn driver_v6_two_real_signers_exchange_and_finalize_the_same_claim() -> TestResult {
    let mut a = Party::create(BitcoinParticipantRoleV1::Maker)?;
    let mut b = Party::create(BitcoinParticipantRoleV1::Taker)?;
    let (mut x, mut y) = pair_transport()?;
    let (first, second) = parallel_round(&mut a, &mut b, &mut x, &mut y);
    let first = first?;
    let second = second?;
    assert_eq!(first.session_digest(), second.session_digest());
    assert_eq!((a.authorizations, b.authorizations), (3, 3));
    let secret_a = BitcoinAdaptorSecretV1::verify(&mut [0x2b; 32], compressed([0x2b; 32])?)?;
    let secret_b = BitcoinAdaptorSecretV1::verify(&mut [0x2b; 32], compressed([0x2b; 32])?)?;
    let tx_a = first.finalize_claim(secret_a)?;
    let tx_b = second.finalize_claim(secret_b)?;
    let bytes_a = a.retain_final(tx_a)?;
    let bytes_b = b.retain_final(tx_b)?;
    assert_eq!(bytes_a, bytes_b);
    if let Some(path) = std::env::var_os("DOM_INTEROP_V6_DRIVER_CLAIM") {
        let hex = |value: &[u8]| value.iter().map(|v| format!("{v:02x}")).collect::<String>();
        let report = format!(
            r#"{{"schema_version":6,"claim_transaction":"{}","funding_txid":"{}","funding_vout":{},"principal_sat":{},"contract_script_pubkey":"{}","recipient_script_pubkey":"{}","fee_sat":{}}}"#,
            hex(&bytes_a),
            hex(&FUNDING_TXID),
            FUNDING_VOUT,
            FUNDING_AMOUNT,
            hex(&a.session.contract_script_pubkey),
            hex(&a.session.destination_script_pubkey),
            CLAIM_FEE
        );
        std::fs::write(path, report)?;
    }
    Ok(())
}

#[test]
fn driver_v6_disconnect_after_partial_persistence_reopens_and_replays_identical_frames(
) -> TestResult {
    let mut a = Party::create(BitcoinParticipantRoleV1::Maker)?;
    let mut b = Party::create(BitcoinParticipantRoleV1::Taker)?;
    let (mut x, mut y) = pair_transport()?;
    x.stop_at_partial = true;
    y.stop_at_partial = true;
    let (first, second) = parallel_round(&mut a, &mut b, &mut x, &mut y);
    assert!(matches!(first, Err(DriverError::TransportUnavailable)));
    assert!(matches!(second, Err(DriverError::TransportUnavailable)));
    assert_eq!((x.frames.len(), y.frames.len()), (2, 2));
    let before_a = x.frames.clone();
    let before_b = y.frames.clone();
    drop(x);
    drop(y);
    let mut a = a.reopen()?;
    let mut b = b.reopen()?;
    let (mut x, mut y) = pair_transport()?;
    let (first, second) = parallel_round(&mut a, &mut b, &mut x, &mut y);
    first?;
    second?;
    assert_eq!(x.frames, before_a);
    assert_eq!(y.frames, before_b);
    for party in [&a, &b] {
        let count: i64 = Connection::open(party.directory.path().join("actuator.sqlite"))?
            .query_row("SELECT COUNT(*) FROM claim_transcripts", [], |row| {
                row.get(0)
            })?;
        assert_eq!(count, 1);
    }
    Ok(())
}

#[test]
fn driver_v6_rejects_forged_peer_before_partial_persistence() -> TestResult {
    struct Forged(BitcoinClaimMessageV3);
    impl BitcoinClaimTransportV6 for Forged {
        fn exchange(
            &mut self,
            _: Phase,
            _: &BitcoinClaimMessageV3,
        ) -> Result<BitcoinClaimMessageV3, DriverError> {
            Ok(self.0.clone())
        }
    }
    let mut a = Party::create(BitcoinParticipantRoleV1::Maker)?;
    let mut b = Party::create(BitcoinParticipantRoleV1::Taker)?;
    let mut wire = b.expose_nonce()?.to_bytes();
    wire[44] ^= 1;
    assert!(matches!(
        drive_bitcoin_claim_v6(
            &mut a,
            &mut Forged(BitcoinClaimMessageV3::from_bytes(&wire)?)
        ),
        Err(DriverError::Signing(_))
    ));
    let count: i64 = Connection::open(a.directory.path().join("actuator.sqlite"))?.query_row(
        "SELECT COUNT(*) FROM claim_transcripts WHERE local_partial IS NOT NULL",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn driver_v6_bounds_silent_peer_and_refuses_wrong_envelope_without_large_allocation() -> TestResult
{
    use std::io::{Read, Write};
    let mut a = Party::create(BitcoinParticipantRoleV1::Maker)?;
    let nonce = a.expose_nonce()?;
    let (local, _silent) = UnixStream::pair()?;
    let mut transport = UnixBitcoinClaimTransportV6::new(local, Duration::from_millis(20))?;
    assert!(matches!(
        transport.exchange(Phase::Nonce, &nonce),
        Err(DriverError::TransportUnavailable)
    ));
    for (phase, size) in [(1u8, 65_535u16), (2, 270)] {
        let (local, mut peer) = UnixStream::pair()?;
        let mut transport = UnixBitcoinClaimTransportV6::new(local, Duration::from_secs(2))?;
        let result = std::thread::scope(|threads| {
            let worker = threads.spawn(move || -> std::io::Result<()> {
                let mut incoming = [0; 282];
                peer.read_exact(&mut incoming)?;
                let mut header = [0; 12];
                header[..8].copy_from_slice(b"DOMBTCX6");
                header[8] = phase;
                header[10..].copy_from_slice(&size.to_be_bytes());
                peer.write_all(&header)
            });
            let result = transport.exchange(Phase::Nonce, &nonce);
            let _ = worker.join();
            result
        });
        assert!(matches!(result, Err(DriverError::EnvelopeRejected)));
    }
    Ok(())
}

#[test]
fn driver_v9_failed_stream_is_closed_and_cannot_replay_into_partial_framing() -> TestResult {
    use std::io::{Read, Write};
    let mut a = Party::create(BitcoinParticipantRoleV1::Maker)?;
    let nonce = a.expose_nonce()?;
    for malformed in [false, true] {
        let (local, mut peer) = UnixStream::pair()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        let mut transport = UnixBitcoinClaimTransportV6::new(local, Duration::from_millis(40))?;
        std::thread::scope(|threads| -> TestResult {
            let worker = threads.spawn(move || -> std::io::Result<()> {
                let mut outgoing = [0; 282];
                peer.read_exact(&mut outgoing)?;
                if malformed {
                    peer.write_all(&[0; 12])?;
                } else {
                    // A valid-looking but truncated header cannot be reused.
                    peer.write_all(b"DOMBTC")?;
                }
                let mut byte = [0; 1];
                assert_eq!(peer.read(&mut byte)?, 0, "failed transport must close");
                Ok(())
            });
            let first = transport.exchange(Phase::Nonce, &nonce);
            if malformed {
                assert!(matches!(first, Err(DriverError::EnvelopeRejected)));
            } else {
                assert!(matches!(first, Err(DriverError::TransportUnavailable)));
            }
            assert!(matches!(
                transport.exchange(Phase::Nonce, &nonce),
                Err(DriverError::TransportUnavailable)
            ));
            worker.join().map_err(|_| "peer panicked")??;
            Ok(())
        })?;
    }
    Ok(())
}
