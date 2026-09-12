//! Native V23 builder. Its private outgoing key and exact signable plan are
//! durable/encrypted BEFORE signing; public bytes and proofs publish together.
use super::*;
use monero_oxide_wallet::{
    OutputWithDecoys, Scanner, ViewPair, WalletOutput,
    address::{AddressType, MoneroAddress, Network},
    interface::{
        FeePriority, ProvidesBlockchain, ProvidesBlockchainMeta, ProvidesFeeRates,
        ProvidesScannableBlocks, ProvidesTransactions,
    },
    ringct::RctType,
    send::{Change, SignableTransaction, TransactionKeys},
    transaction::{Input, NotPruned, Transaction},
};
use rand_core::{OsRng, RngCore};
use xmr_key_image_proof::{
    BuildSweepRequestV23, BuildSweepResponseV23, BuiltRingMemberV23, InputSpendContextV23,
    destination_digest_v23, prove_input_spend_v23, prove_tx_key_derivation_v23,
};

type Request = BuildSweepRequestV23<BuildSweepRequestV2>;
type Response = BuildSweepResponseV23<BuildSweepResponseV2>;
const MAINNET_GENESIS: [u8; 32] = [
    0x41, 0x80, 0x15, 0xbb, 0x9a, 0xe9, 0x82, 0xa1, 0x97, 0x5d, 0xa7, 0xd7, 0x92, 0x77, 0xc2, 0x70,
    0x57, 0x27, 0xa5, 0x68, 0x94, 0xba, 0x0f, 0xb2, 0x46, 0xad, 0xaa, 0xbb, 0x1f, 0x46, 0x32, 0xe3,
];
fn cache_error(error: CacheError) -> SidecarOperationError {
    match error {
        CacheError::Unavailable => SidecarOperationError::Retryable,
        CacheError::Conflict | CacheError::Corrupt => rejected(),
    }
}
fn rejected() -> SidecarOperationError {
    SidecarOperationError::Rejected("native V23 build scope or durable state mismatch".to_owned())
}

struct Prepared {
    funding_raw: Vec<u8>,
    outgoing: Zeroizing<[u8; 32]>,
    output: WalletOutput,
    decoys: OutputWithDecoys,
    dummy: MoneroAddress,
    plan: SignableTransaction,
}
impl Prepared {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, SidecarOperationError> {
        let mut bytes = Zeroizing::new(b"XMRBUILDPLAN23\0".to_vec());
        bytes.extend_from_slice(&*self.outgoing);
        for value in [
            Zeroizing::new(self.output.serialize()),
            Zeroizing::new(self.decoys.serialize()),
            Zeroizing::new(self.dummy.to_string().into_bytes()),
            Zeroizing::new(self.plan.serialize()),
            Zeroizing::new(self.funding_raw.clone()),
        ] {
            let len = u32::try_from(value.len()).map_err(|_| rejected())?;
            bytes.extend_from_slice(&len.to_le_bytes());
            bytes.extend_from_slice(&value);
        }
        Ok(bytes)
    }
    fn decode(mut bytes: &[u8]) -> Result<Self, SidecarOperationError> {
        fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Result<&'a [u8], SidecarOperationError> {
            if n > bytes.len() {
                return Err(rejected());
            }
            let (head, tail) = bytes.split_at(n);
            *bytes = tail;
            Ok(head)
        }
        fn field<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8], SidecarOperationError> {
            let n =
                u32::from_le_bytes(take(bytes, 4)?.try_into().map_err(|_| rejected())?) as usize;
            if n == 0 || n > 128 * 1024 {
                return Err(rejected());
            }
            take(bytes, n)
        }
        if take(&mut bytes, 15)? != b"XMRBUILDPLAN23\0" {
            return Err(rejected());
        }
        let outgoing = Zeroizing::new(take(&mut bytes, 32)?.try_into().map_err(|_| rejected())?);
        let mut encoded_output = field(&mut bytes)?;
        let output = WalletOutput::read(&mut encoded_output).map_err(|_| rejected())?;
        if !encoded_output.is_empty() {
            return Err(rejected());
        }
        let mut encoded_decoys = field(&mut bytes)?;
        let decoys = OutputWithDecoys::read(&mut encoded_decoys).map_err(|_| rejected())?;
        if !encoded_decoys.is_empty() {
            return Err(rejected());
        }
        let dummy = MoneroAddress::from_str(
            Network::Mainnet,
            std::str::from_utf8(field(&mut bytes)?).map_err(|_| rejected())?,
        )
        .map_err(|_| rejected())?;
        let encoded_plan = field(&mut bytes)?;
        let mut cursor = encoded_plan;
        let plan = SignableTransaction::read(&mut cursor).map_err(|_| rejected())?;
        let funding_raw = field(&mut bytes)?.to_vec();
        if !cursor.is_empty()
            || Zeroizing::new(plan.serialize()).as_slice() != encoded_plan
            || !bytes.is_empty()
        {
            return Err(rejected());
        }
        Ok(Self {
            funding_raw,
            outgoing,
            output,
            decoys,
            dummy,
            plan,
        })
    }
}

fn reconstruct_plan(
    request: &Request,
    outgoing: &Zeroizing<[u8; 32]>,
    decoys: &OutputWithDecoys,
    dummy: &MoneroAddress,
    rate: monero_oxide_wallet::interface::FeeRate,
) -> Result<SignableTransaction, SidecarOperationError> {
    let destination = MoneroAddress::from_str(Network::Mainnet, &request.build.destination)
        .map_err(|_| rejected())?;
    // Dummy is a distinct standard address. Its output value is zero, not a
    // fabricated omission of the second output required by Monero.
    if dummy == &destination
        || !matches!(dummy.kind(), AddressType::Legacy)
        || dummy.is_subaddress()
        || dummy.payment_id().is_some()
        || dummy.network() != Network::Mainnet
    {
        return Err(rejected());
    }
    let initial = SignableTransaction::new(
        RctType::ClsagBulletproofPlus,
        outgoing.clone(),
        vec![decoys.clone()],
        vec![(destination.clone(), 0), (dummy.clone(), 0)],
        Change::fingerprintable(None),
        vec![],
        rate,
    )
    .map_err(|_| rejected())?;
    let mut fee = initial.necessary_fee();
    for _ in 0..3 {
        if fee == 0 || fee > request.max_fee || fee >= request.build.expected_amount_piconero {
            return Err(rejected());
        }
        let plan = SignableTransaction::new(
            RctType::ClsagBulletproofPlus,
            outgoing.clone(),
            vec![decoys.clone()],
            vec![
                (
                    destination.clone(),
                    request.build.expected_amount_piconero - fee,
                ),
                (dummy.clone(), 0),
            ],
            Change::fingerprintable(None),
            vec![],
            rate,
        )
        .map_err(|_| rejected())?;
        if plan.necessary_fee() == fee {
            return Ok(plan);
        }
        fee = plan.necessary_fee();
    }
    Err(rejected())
}

pub(super) async fn build(
    config: &Config,
    request: &Request,
) -> Result<Response, SidecarOperationError> {
    let action = request.validate_scope().map_err(|_| rejected())?;
    request
        .build
        .validate_public_fields()
        .map_err(|_| rejected())?;
    config
        .auth
        .verify_build_proof_v23(request)
        .map_err(|_| rejected())?;
    let destination = MoneroAddress::from_str(Network::Mainnet, &request.build.destination)
        .map_err(|_| rejected())?;
    if destination.network() != Network::Mainnet
        || !matches!(destination.kind(), AddressType::Legacy)
        || destination.is_subaddress()
        || destination.payment_id().is_some()
        || destination.to_string() != request.build.destination
        || request.network_genesis != MAINNET_GENESIS
    {
        return Err(rejected());
    }
    let canonical_build = Zeroizing::new(
        request
            .build
            .canonical_auth_bytes()
            .map_err(|_| rejected())?,
    );
    let canonical = Zeroizing::new(
        request
            .canonical_auth_bytes(&canonical_build)
            .map_err(|_| rejected())?,
    );
    let request_hash = SweepCache::request_hash(&canonical);
    let guard = config
        .cache
        .begin_build_v23(request.build.request_nonce, request_hash)
        .map_err(cache_error)?;
    let encryption_key = config.auth.build_plan_key_v23(&request_hash);
    if let Some(response) = guard.load_ready().map_err(cache_error)? {
        let encoded = guard
            .load_plan(&encryption_key)
            .map_err(cache_error)?
            .ok_or_else(rejected)?;
        let retained_plan = Prepared::decode(&encoded)?;
        return revalidate_cached_response(request, &retained_plan, response);
    }
    let spend = Zeroizing::new(request.build.spend_scalar.expose(|s| parse_scalar(*s))?);
    if monero_wallet_ng::util::public_key(&spend)
        .compress()
        .to_bytes()
        != request.build.expected_spend_public_key
    {
        return Err(rejected());
    }
    let prepared = match guard.load_plan(&encryption_key).map_err(cache_error)? {
        Some(encoded) => Prepared::decode(&encoded)?,
        None => {
            let rpc = monerod(config).await?;
            if ProvidesBlockchain::block_hash(&rpc, 0)
                .await
                .map_err(|_| SidecarOperationError::Retryable)?
                != request.network_genesis
            {
                return Err(rejected());
            }
            let tip = rpc
                .latest_block_number()
                .await
                .map_err(|_| SidecarOperationError::Retryable)?;
            let height = usize::try_from(request.funding_height).map_err(|_| rejected())?;
            if height.checked_add(9).ok_or_else(rejected)? > tip {
                return Err(SidecarOperationError::Retryable);
            }
            let view = Zeroizing::new(request.build.view_scalar.expose(|s| parse_scalar(*s))?);
            let pair = ViewPair::new(parse_point(request.build.expected_spend_public_key)?, view)
                .map_err(|_| rejected())?;
            let block = ProvidesScannableBlocks::scannable_block_by_number(&rpc, height)
                .await
                .map_err(|_| SidecarOperationError::Retryable)?;
            let mut outputs = Scanner::new(pair)
                .scan(block)
                .map_err(|_| rejected())?
                .not_additionally_locked()
                .into_iter()
                .filter(|o| {
                    o.transaction() == request.build.funding_tx_hash
                        && o.index_in_transaction() == request.output_index
                });
            let output = outputs.next().ok_or_else(rejected)?;
            if outputs.next().is_some()
                || output.commitment().amount != request.build.expected_amount_piconero
            {
                return Err(rejected());
            }
            let funding_raw =
                ProvidesTransactions::transaction(&rpc, request.build.funding_tx_hash)
                    .await
                    .map_err(|_| SidecarOperationError::Retryable)?
                    .serialize();
            let decoys = OutputWithDecoys::new(&mut OsRng, &rpc, 16, tip, output.clone())
                .await
                .map_err(|_| SidecarOperationError::Retryable)?;
            // Public fee-rate limiter also prevents overflow in native weight multiplication.
            let rate = rpc
                .fee_rate(
                    FeePriority::Normal,
                    request.max_fee.min(u64::MAX / 1_000_000),
                )
                .await
                .map_err(|_| SidecarOperationError::Retryable)?;
            let rate_bytes = rate.serialize();
            let mask = u64::from_le_bytes(rate_bytes[8..16].try_into().map_err(|_| rejected())?);
            if mask > request.max_fee.min(u64::MAX / 2) {
                return Err(rejected());
            }
            let mut outgoing = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(&mut *outgoing);
            if *outgoing == [0; 32] {
                return Err(rejected());
            }
            let dummy_spend = Zeroizing::new(Scalar::random(&mut OsRng));
            let dummy_view = Zeroizing::new(Scalar::random(&mut OsRng));
            let dummy = MoneroAddress::new(
                Network::Mainnet,
                AddressType::Legacy,
                monero_wallet_ng::util::public_key(&dummy_spend),
                monero_wallet_ng::util::public_key(&dummy_view),
            );
            let plan = reconstruct_plan(request, &outgoing, &decoys, &dummy, rate)?;
            let prepared = Prepared {
                funding_raw,
                outgoing,
                output,
                decoys,
                dummy,
                plan,
            };
            guard
                .store_plan(&encryption_key, &prepared.encode()?)
                .map_err(cache_error)?;
            prepared
        }
    };
    if prepared.output.transaction() != request.build.funding_tx_hash
        || prepared.output.index_in_transaction() != request.output_index
        || prepared.output.commitment().amount != request.build.expected_amount_piconero
        || prepared.decoys.key() != prepared.output.key()
        || prepared.decoys.commitment().mask != prepared.output.commitment().mask
        || prepared.decoys.commitment().amount != prepared.output.commitment().amount
        || prepared.decoys.key_offset() != prepared.output.key_offset()
    {
        return Err(rejected());
    }
    let reconstructed = reconstruct_plan(
        request,
        &prepared.outgoing,
        &prepared.decoys,
        &prepared.dummy,
        prepared.plan.fee_rate(),
    )?;
    if *Zeroizing::new(reconstructed.serialize()) != *Zeroizing::new(prepared.plan.serialize()) {
        return Err(rejected());
    }
    // Public TransactionKeys recovers the ACTUAL r chosen before signing.
    let mut tx_keys = TransactionKeys::new(
        &prepared.outgoing,
        vec![(prepared.output.key(), prepared.output.commitment().commit())],
    );
    let tx_key = tx_keys.next().ok_or_else(rejected)?;
    let transaction = prepared
        .plan
        .sign(&mut OsRng, &spend)
        .map_err(|_| rejected())?;
    let raw_tx = transaction.serialize();
    if raw_tx.is_empty() || raw_tx.len() > MAX_RAW_TX_BYTES {
        return Err(rejected());
    }
    let Transaction::V2 {
        prefix,
        proofs: Some(proofs),
    } = &transaction
    else {
        return Err(rejected());
    };
    if prefix.inputs.len() != 1
        || prefix.outputs.len() != 2
        || proofs.rct_type() != RctType::ClsagBulletproofPlus
        || proofs.base.fee == 0
        || proofs.base.fee > request.max_fee
        || proofs.base.fee >= request.build.expected_amount_piconero
    {
        return Err(rejected());
    }
    let Input::ToKey { key_image, .. } = &prefix.inputs[0] else {
        return Err(rejected());
    };
    let context = InputSpendContextV23 {
        network_genesis: request.network_genesis,
        route: request.route,
        session: request.session,
        terms: request.terms,
        funding_tx: request.build.funding_tx_hash,
        output_index: request.output_index,
        sweep_tx: transaction.hash(),
        destination: destination_digest_v23(&request.build.destination),
        funded_amount: request.build.expected_amount_piconero,
        fee: proofs.base.fee,
        action,
    };
    let x = Zeroizing::<curve25519_dalek::scalar::Scalar>::new((*spend).into());
    let offset =
        Zeroizing::<curve25519_dalek::scalar::Scalar>::new(prepared.output.key_offset().into());
    let witness = Zeroizing::new(*x + *offset);
    let witness_bytes = Zeroizing::new(witness.to_bytes());
    let input_proof = prove_input_spend_v23(
        &context,
        prepared.output.key().compress().to_bytes(),
        key_image.to_bytes(),
        &witness_bytes,
        &mut OsRng,
    )
    .map_err(|_| rejected())?;
    let r_bytes = Zeroizing::new(<[u8; 32]>::from(*tx_key));
    let r_public = monero_wallet_ng::util::public_key(&tx_key)
        .compress()
        .to_bytes();
    if prefix.extra.first() != Some(&1) || prefix.extra.get(1..33) != Some(r_public.as_slice()) {
        return Err(rejected());
    }
    let payout = prove_tx_key_derivation_v23(
        &context,
        destination.view().compress().to_bytes(),
        r_public,
        &r_bytes,
        &mut OsRng,
    )
    .map_err(|_| rejected())?;
    let ring_members: Vec<BuiltRingMemberV23> = prepared
        .decoys
        .decoys()
        .positions()
        .into_iter()
        .zip(prepared.decoys.decoys().ring())
        .map(|(global_index, points)| BuiltRingMemberV23 {
            global_index,
            key: points[0].compress().to_bytes(),
            commitment: points[1].compress().to_bytes(),
        })
        .collect();
    // Independent public verification before publishing; chain membership of
    // decoys remains the remote observer's responsibility, not this cache's grant.
    let evidence: Vec<xmr_raw_tx_verify::RingMemberEvidenceV23> = ring_members
        .iter()
        .map(|member| xmr_raw_tx_verify::RingMemberEvidenceV23 {
            global_index: member.global_index,
            key: member.key,
            commitment: member.commitment,
        })
        .collect();
    xmr_raw_tx_verify::verify_sweep_payout_v23(
        &context,
        &prepared.funding_raw,
        &raw_tx,
        &request.build.destination,
        request.max_fee,
        &input_proof,
        std::slice::from_ref(&payout),
        &evidence,
        &mut OsRng,
    )
    .map_err(|_| rejected())?;
    let response = Response {
        api_version: 23,
        authorization_digest: request.authorization_digest,
        request_message_digest: request.request_message_digest,
        sweep: BuildSweepResponseV2 {
            api_version: API_VERSION_V2,
            request_nonce: request.build.request_nonce,
            tx_hash: context.sweep_tx,
            raw_tx,
        },
        context: context.canonical_bytes().map_err(|_| rejected())?,
        input_proof: input_proof.as_bytes().to_vec(),
        tx_key_proofs: vec![payout.encode().to_vec()],
        ring_members,
    };
    // Complete cryptographic result is durable before anything crosses the socket.
    guard.store_ready(&response).map_err(cache_error)?;
    validate_response(request, response)
}

// Readback performs no RPC and no signing. The encrypted plan anchors the
// exact unsigned prefix/outputs/ciphertexts; public files alone are insufficient.
fn revalidate_cached_response(
    request: &Request,
    prepared: &Prepared,
    response: Response,
) -> Result<Response, SidecarOperationError> {
    let response = validate_response(request, response)?;
    let context = response.validate_framing().map_err(|_| rejected())?;
    if prepared.output.transaction() != request.build.funding_tx_hash
        || prepared.output.index_in_transaction() != request.output_index
        || prepared.output.commitment().amount != request.build.expected_amount_piconero
        || prepared.decoys.key() != prepared.output.key()
        || prepared.decoys.commitment().mask != prepared.output.commitment().mask
        || prepared.decoys.commitment().amount != prepared.output.commitment().amount
        || prepared.decoys.key_offset() != prepared.output.key_offset()
    {
        return Err(rejected());
    }
    let reconstructed = reconstruct_plan(
        request,
        &prepared.outgoing,
        &prepared.decoys,
        &prepared.dummy,
        prepared.plan.fee_rate(),
    )?;
    if *Zeroizing::new(reconstructed.serialize()) != *Zeroizing::new(prepared.plan.serialize()) {
        return Err(rejected());
    }
    let mut cursor = response.sweep.raw_tx.as_slice();
    let transaction: Transaction<NotPruned> =
        Transaction::read(&mut cursor).map_err(|_| rejected())?;
    if !cursor.is_empty() || transaction.serialize() != response.sweep.raw_tx {
        return Err(rejected());
    }
    let [Input::ToKey { key_image, .. }] = transaction.prefix().inputs.as_slice() else {
        return Err(rejected());
    };
    let unsigned = reconstructed
        .unsigned_transaction(vec![*key_image])
        .ok_or_else(rejected)?;
    if unsigned.prefix() != transaction.prefix() {
        return Err(rejected());
    }
    let (
        Transaction::V2 {
            proofs: Some(expected),
            ..
        },
        Transaction::V2 {
            proofs: Some(actual),
            ..
        },
    ) = (&unsigned, &transaction)
    else {
        return Err(rejected());
    };
    if expected.rct_type() != actual.rct_type()
        || expected.base.fee != actual.base.fee
        || expected.base.commitments != actual.base.commitments
        || expected.base.encrypted_amounts != actual.base.encrypted_amounts
    {
        return Err(rejected());
    }
    let expected_ring: Vec<BuiltRingMemberV23> = prepared
        .decoys
        .decoys()
        .positions()
        .into_iter()
        .zip(prepared.decoys.decoys().ring())
        .map(|(global_index, points)| BuiltRingMemberV23 {
            global_index,
            key: points[0].compress().to_bytes(),
            commitment: points[1].compress().to_bytes(),
        })
        .collect();
    if response.ring_members != expected_ring {
        return Err(rejected());
    }
    let evidence: Vec<xmr_raw_tx_verify::RingMemberEvidenceV23> = expected_ring
        .iter()
        .map(|member| xmr_raw_tx_verify::RingMemberEvidenceV23 {
            global_index: member.global_index,
            key: member.key,
            commitment: member.commitment,
        })
        .collect();
    let input_proof = xmr_key_image_proof::InputSpendProofV23::decode(&response.input_proof)
        .map_err(|_| rejected())?;
    let payout_proofs = response
        .tx_key_proofs
        .iter()
        .map(|bytes| {
            xmr_key_image_proof::TxKeyDerivationProofV23::decode(bytes).map_err(|_| rejected())
        })
        .collect::<Result<Vec<_>, _>>()?;
    xmr_raw_tx_verify::verify_sweep_payout_v23(
        &context,
        &prepared.funding_raw,
        &response.sweep.raw_tx,
        &request.build.destination,
        request.max_fee,
        &input_proof,
        &payout_proofs,
        &evidence,
        &mut OsRng,
    )
    .map_err(|_| rejected())?;
    Ok(response)
}

fn validate_response(
    request: &Request,
    response: Response,
) -> Result<Response, SidecarOperationError> {
    let c = response.validate_framing().map_err(|_| rejected())?;
    if response.request_message_digest != request.request_message_digest
        || response.authorization_digest != request.authorization_digest
        || response.sweep.api_version != API_VERSION_V2
        || response.sweep.request_nonce != request.build.request_nonce
        || response.sweep.tx_hash != c.sweep_tx
        || response.sweep.raw_tx.is_empty()
        || response.sweep.raw_tx.len() > MAX_RAW_TX_BYTES
        || c.network_genesis != request.network_genesis
        || c.route != request.route
        || c.session != request.session
        || c.terms != request.terms
        || c.funding_tx != request.build.funding_tx_hash
        || c.output_index != request.output_index
        || c.funded_amount != request.build.expected_amount_piconero
        || c.destination != destination_digest_v23(&request.build.destination)
        || c.action != request.validate_scope().map_err(|_| rejected())?
        || c.fee > request.max_fee
    {
        return Err(rejected());
    }
    Ok(response)
}
