//! Mutable local RPC ledger. Transactions and coinbases are natively validated;
//! headers model an authenticated RPC history, not mined mainnet blocks.
use super::*;

pub(super) struct EvolvingDomV23 {
    ledger: ledger_v23::NativeDomLedgerV23,
    identity: ExpectedDomIdentityV1,
    public: Value,
    blocks: Vec<Value>,
    confirmations: u32,
    hold_submissions: bool,
    pending: std::collections::BTreeMap<[u8; 32], Vec<u8>>,
}
impl EvolvingDomV23 {
    pub(super) fn new(
        ledger: ledger_v23::NativeDomLedgerV23,
        identity: ExpectedDomIdentityV1,
        public: Value,
        blocks: Vec<Value>,
        confirmations: u32,
    ) -> Self {
        Self {
            ledger,
            identity,
            public,
            blocks,
            confirmations,
            hold_submissions: false,
            pending: std::collections::BTreeMap::new(),
        }
    }
    pub(super) fn identity_json(&self) -> &Value {
        &self.public
    }
    pub(super) fn blocks(&self) -> &[Value] {
        &self.blocks
    }

    /// Scenario-owner control only, never reachable through the HTTP server.
    pub(super) fn arm_submission_barrier(&mut self) -> Result<()> {
        if self.hold_submissions || !self.pending.is_empty() {
            return Err("local submission barrier already armed".into());
        }
        self.hold_submissions = true;
        Ok(())
    }

    pub(super) fn pending_transactions(&self) -> Vec<([u8; 32], Vec<u8>)> {
        self.pending
            .iter()
            .map(|(hash, bytes)| (*hash, bytes.clone()))
            .collect()
    }

    pub(super) fn release_submissions(&mut self) -> Result<()> {
        if !self.hold_submissions || self.pending.is_empty() {
            return Err("local release requires retained unconfirmed submissions".into());
        }
        // Revalidate each exact transaction against the then-current UTXO set.
        // A failure retains that transaction and all later ones for diagnosis.
        while let Some((&hash, bytes)) = self.pending.first_key_value() {
            let bytes = bytes.clone();
            self.admit(&bytes)?;
            self.pending.remove(&hash);
        }
        self.hold_submissions = false;
        Ok(())
    }

    pub(super) fn advance_to_height(&mut self, target: u64) -> Result<()> {
        let current = self.public["tip_height"].as_u64().ok_or("local tip")?;
        if target < current || target >= 4096 || self.hold_submissions || !self.pending.is_empty() {
            return Err(
                "local recovery advance must be monotonic, bounded and after inclusion".into(),
            );
        }
        while self.public["tip_height"].as_u64().ok_or("local tip")? < target {
            self.append_empty()?;
        }
        Ok(())
    }

    fn submit(&mut self, bytes: &[u8]) -> Result<Value> {
        let hash = dom_scriptless_chain_adapter::canonical_transaction_hash_v1(bytes)?;
        if !self.hold_submissions || self.ledger.contains_transaction(&hash) {
            return self.admit(bytes);
        }
        let already_known = self.pending.contains_key(&hash);
        if !already_known {
            if self.pending.len() >= 4 {
                return Err("local pending submission bound".into());
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let prepared = self.ledger.prepare(bytes, now)?;
            for retained in self.pending.values() {
                let previous = dom_consensus::Transaction::from_bytes(retained)?;
                if prepared.transaction().inputs.iter().any(|input| {
                    previous
                        .inputs
                        .iter()
                        .any(|other| other.commitment == input.commitment)
                }) {
                    return Err(
                        "local pending input already reserved by another transaction".into(),
                    );
                }
            }
            self.pending.insert(hash, bytes.to_vec());
        } else if self.pending.get(&hash).map(Vec::as_slice) != Some(bytes) {
            return Err("local pending transaction hash collision".into());
        }
        Ok(
            json!({"accepted":true,"relayed":false,"tx_hash":hex::encode(hash),
            "state":"pending","already_known":already_known,"confirmed":false,
            "warning":"controlled local pending ledger; not mined mainnet","error":null}),
        )
    }

    fn append_empty(&mut self) -> Result<()> {
        let height = u64::try_from(self.blocks.len())?;
        if height >= 4096 {
            return Err("local finality history bound".into());
        }
        let (validated, projection) =
            baseline_coinbase_v23::material_v23(&self.identity.chain_id, height, 0)?;
        let previous = self.blocks.last().ok_or("local predecessor")?;
        let previous_hash = hex::decode(previous["block_hash"].as_str().ok_or("previous hash")?)?;
        let mut header = hex::decode(
            previous["canonical_header_bytes"]
                .as_str()
                .ok_or("previous header")?,
        )?;
        if header.len() != 256 {
            return Err("local header width".into());
        }
        header[4..12].copy_from_slice(&height.to_le_bytes());
        header[12..44].copy_from_slice(&previous_hash);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let timestamp = now.max(previous["timestamp"].as_u64().ok_or("previous time")?);
        header[44..52].copy_from_slice(&timestamp.to_le_bytes());
        let material = serde_json::to_vec(&projection)?;
        for (index, domain) in [
            b"outputs".as_slice(),
            b"proofs".as_slice(),
            b"kernels".as_slice(),
        ]
        .iter()
        .enumerate()
        {
            header[52 + index * 32..84 + index * 32].copy_from_slice(
                dom_crypto::blake2b_256(&[domain.to_vec(), material.clone()].concat()).as_bytes(),
            );
        }
        header[148..180].fill(0);
        let parsed = dom_consensus::BlockHeader::from_bytes(&header)?;
        if parsed.to_bytes()? != header {
            return Err("local empty header codec".into());
        }
        let hash = hex::encode(dom_crypto::blake2b_256(&header).as_bytes());
        let block = json!({"height":height,"block_hash":hash,"previous_block_hash":hex::encode(previous_hash),
            "canonical_header_bytes":hex::encode(header),"timestamp":timestamp,"canonical_marker":hash,
            "transactions":[],"coinbase":projection,"total_fees_noms":0,
            "protocol_version":self.identity.protocol_version,"range_proof_serialization_version":self.identity.range_proof_serialization_version});
        self.blocks.try_reserve(1)?;
        self.ledger.seed_coinbase(height, &validated)?;
        self.blocks.push(block);
        self.public["tip_height"] = json!(height);
        self.public["tip_hash"] = json!(hash);
        Ok(())
    }

    fn admit(&mut self, bytes: &[u8]) -> Result<Value> {
        let hash = dom_scriptless_chain_adapter::canonical_transaction_hash_v1(bytes)?;
        if !self.ledger.contains_transaction(&hash) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let prepared = self.ledger.prepare(bytes, now)?;
            if prepared.hash() != hash {
                return Err("native ledger hash mismatch".into());
            }
            let height = u64::try_from(self.blocks.len())?;
            if height >= 4096 {
                return Err("evolving DOM history bound".into());
            }
            let tx = prepared.transaction();
            let fees = tx.total_fee()?;
            let (coinbase, projection) =
                baseline_coinbase_v23::material_v23(&self.identity.chain_id, height, fees)?;
            let previous = self.blocks.last().ok_or("evolving baseline absent")?;
            let previous_hash: [u8; 32] =
                hex::decode(previous["block_hash"].as_str().ok_or("previous hash")?)?
                    .try_into()
                    .map_err(|_| "hash size")?;
            let previous_time = previous["timestamp"].as_u64().ok_or("previous timestamp")?;
            // Equal-second blocks are a local RPC simulation, not PoW admission.
            let timestamp = now.max(previous_time);
            let mut header = Vec::new();
            header.extend_from_slice(&self.identity.protocol_version.to_le_bytes());
            header.extend_from_slice(&height.to_le_bytes());
            header.extend_from_slice(&previous_hash);
            header.extend_from_slice(&timestamp.to_le_bytes());
            // Deterministic transaction-content roots for the simulated header;
            // do not assert these are a mainnet PMMR or a mined block proof.
            for domain in [
                b"outputs".as_slice(),
                b"proofs".as_slice(),
                b"kernels".as_slice(),
            ] {
                header.extend_from_slice(
                    dom_crypto::blake2b_256(&[domain, bytes].concat()).as_bytes(),
                );
            }
            header.extend_from_slice(&tx.offset);
            header.extend_from_slice(&0x207fffffu32.to_le_bytes());
            header.extend_from_slice(&[0; 32]);
            header.extend_from_slice(&0u64.to_le_bytes());
            header.extend_from_slice(&[0; 32]);
            let decoded = dom_consensus::BlockHeader::from_bytes(&header)?;
            if decoded.to_bytes()? != header {
                return Err("evolving header codec".into());
            }
            let block_hash = hex::encode(dom_crypto::blake2b_256(&header).as_bytes());
            let outputs = tx.outputs.iter().enumerate().map(|(i,o)| -> Result<Value> {
                let capsule=o.recovery_capsule()?;
                Ok(json!({"commitment":hex::encode(o.commitment.as_bytes()),"range_proof":hex::encode(o.range_proof_bytes()?),
                    "recovery_capsule":capsule.as_ref().map(|c|hex::encode(c.as_bytes())).unwrap_or_default(),
                    "recovery_version":capsule.as_ref().map_or(0,|c|c.version()),"is_coinbase":false,
                    "block_height":height,"block_hash":block_hash,"output_position":i+1}))
            }).collect::<Result<Vec<_>>>()?;
            let transaction = json!({"block_height":height,"block_hash":block_hash,"transaction_index":0,
                "tx_hash":hex::encode(hash),"canonical_bytes":hex::encode(bytes),"outputs":outputs,
                "inputs":tx.inputs.iter().map(|i|json!({"spent_commitment":hex::encode(i.commitment.as_bytes())})).collect::<Vec<_>>(),
                "kernels":tx.kernels.iter().map(|k|json!({"excess":hex::encode(k.excess.as_bytes()),"features":k.features,
                    "fee":k.fee.noms(),"lock_height":k.lock_height,"excess_signature":hex::encode(k.excess_signature)})).collect::<Vec<_>>(),
                "offset":hex::encode(tx.offset)});
            let block = json!({"height":height,"block_hash":block_hash,"previous_block_hash":hex::encode(previous_hash),
                "canonical_header_bytes":hex::encode(header),"timestamp":timestamp,"canonical_marker":block_hash,
                "transactions":[transaction],"coinbase":projection,"total_fees_noms":fees,
                "protocol_version":self.identity.protocol_version,"range_proof_serialization_version":self.identity.range_proof_serialization_version});
            // All fallible validation/projection precedes the atomic publication.
            self.blocks.try_reserve(1)?;
            self.ledger.commit(prepared, &coinbase)?;
            self.blocks.push(block);
            self.public["tip_height"] = json!(height);
            self.public["tip_hash"] = json!(block_hash);
        }
        let included = self
            .blocks
            .iter()
            .find(|block| {
                block["transactions"]
                    .as_array()
                    .is_some_and(|transactions| {
                        transactions
                            .iter()
                            .any(|tx| tx["tx_hash"].as_str() == Some(hex::encode(hash).as_str()))
                    })
            })
            .and_then(|block| block["height"].as_u64())
            .ok_or("admitted transaction absent from RPC history")?;
        let target = included
            .checked_add(u64::from(
                self.confirmations
                    .checked_sub(1)
                    .ok_or("zero DOM confirmations")?,
            ))
            .ok_or("finality height overflow")?;
        while self.public["tip_height"].as_u64().ok_or("local tip")? < target {
            self.append_empty()?;
        }
        Ok(
            json!({"accepted":true,"relayed":false,"tx_hash":hex::encode(hash),"state":"confirmed",
            "already_known":true,"confirmed":true,"warning":"controlled local RPC ledger; not mined mainnet","error":null}),
        )
    }
}

/// Caller has already authenticated exactly one bearer header. This parser
/// independently bounds framing and never treats malformed input as admission.
pub(super) fn submit_http_v23(
    stream: &mut std::net::TcpStream,
    received: &[u8],
    ledger: &std::sync::Mutex<EvolvingDomV23>,
) -> Result<()> {
    let result = (|| -> Result<Value> {
        let split = received
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("HTTP delimiter")?
            + 4;
        let head = std::str::from_utf8(&received[..split])?;
        let mut length = None;
        for line in head.lines().skip(1).filter(|l| !l.is_empty()) {
            let (name, value) = line.split_once(':').ok_or("HTTP field")?;
            if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err("chunked submission refused".into());
            }
            if name.eq_ignore_ascii_case("content-length") {
                if length.is_some() {
                    return Err("duplicate length".into());
                }
                length = Some(value.trim().parse::<usize>()?);
            }
        }
        let length = length
            .filter(|n| *n > 0 && *n <= 4 * 1024 * 1024)
            .ok_or("submission size")?;
        let mut body = received[split..].to_vec();
        if body.len() > length {
            return Err("HTTP trailing bytes".into());
        }
        while body.len() < length {
            let mut buffer = [0; 8192];
            let count = (length - body.len()).min(buffer.len());
            let n = stream.read(&mut buffer[..count])?;
            if n == 0 {
                return Err("short submission".into());
            }
            body.extend_from_slice(&buffer[..n]);
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Request {
            tx_hex: String,
        }
        let request: Request = serde_json::from_slice(&body)?;
        let bytes = hex::decode(request.tx_hex)?;
        ledger
            .lock()
            .map_err(|_| "local ledger poisoned")?
            .submit(&bytes)
    })();
    let (status, value) = match result {
        Ok(value) => ("200 OK", value),
        Err(_) => (
            "400 Bad Request",
            json!({"accepted":false,
        "relayed":false,"tx_hash":null,"state":"rejected","already_known":false,"confirmed":false,"warning":null,"error":"native local admission refused"}),
        ),
    };
    let response = serde_json::to_vec(&value)?;
    write!(stream,"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",response.len())?;
    stream.write_all(&response)?;
    Ok(())
}
