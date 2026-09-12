//! Bounded Epee transport for the offline ledger. This module invents no
//! outputs, transaction identities, heights, or spendability facts.
//! Header/type definitions come from the exact pinned monero-epee package.
use anyhow::{Result, anyhow, ensure};
use monero_epee::{Array, HEADER, Type, VERSION};

const MAX_REQUEST: usize = 16_384;
const MAX_OUTPUTS: usize = 128;
const MAX_HEIGHTS: usize = 1_000_001;
const MAX_RESPONSE: usize = 65_536;
const MAX_DISTRIBUTION_RESPONSE: usize = 8 * 1024 * 1024;
const MAX_BLOCKS: usize = 200;
const MAX_BLOCK_RESPONSE: usize = 4 * 1024 * 1024;

/// Canonical pruned bytes and the real prunable hash, in block transaction order.
pub(super) struct PrunedTransaction {
    pub(super) blob: Vec<u8>,
    pub(super) prunable_hash: [u8; 32],
}

/// Indices include the miner transaction first; transactions do not include it.
pub(super) struct ScannableBlock {
    pub(super) block: Vec<u8>,
    pub(super) transactions: Vec<PrunedTransaction>,
    pub(super) output_indices: Vec<Vec<u64>>,
}

/// All fields must originate in the immutable ledger's canonical transactions.
pub(super) struct Output {
    pub(super) height: u64,
    pub(super) key: [u8; 32],
    pub(super) mask: [u8; 32],
    pub(super) txid: [u8; 32],
    pub(super) unlocked: bool,
}

pub(super) trait Ledger {
    /// Exact contiguous interval; never pad absent blocks or invent indices.
    fn scannable_blocks(&self, start: u64, count: u64) -> Result<Vec<ScannableBlock>>;
    fn output_indexes(&self, txid: [u8; 32]) -> Result<Vec<u64>>;
    /// Global cumulative counts, one value per height in the inclusive range.
    fn cumulative_distribution(&self, from: u64, to: u64) -> Result<Vec<u64>>;
    /// Preserve the requested index order, including repetitions if any.
    fn outputs(&self, indexes: &[u64]) -> Result<Vec<Output>>;
}

#[derive(Debug, PartialEq, Eq)]
enum Value {
    U8(u8),
    U64(u64),
    Bool(bool),
    Bytes(Vec<u8>),
    Object(Vec<(String, Value)>),
    Array(u8, Vec<Value>),
}
type Fields = Vec<(String, Value)>;

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(len)
            .ok_or_else(|| anyhow!("Epee offset overflow"))?;
        let bytes = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| anyhow!("short Epee"))?;
        self.at = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn count(&mut self, max: usize) -> Result<usize> {
        // Pinned daemon deliberately uses an eight-byte array count even for
        // a short list. Accept Epee's valid non-minimal widths, not trailing data.
        let first = self.byte()?;
        let width = 1usize << (first & 3);
        let mut encoded = [0; 8];
        encoded[0] = first;
        encoded[1..width].copy_from_slice(self.take(width - 1)?);
        let value = usize::try_from(u64::from_le_bytes(encoded) >> 2)?;
        ensure!(value <= max, "Epee count bound");
        Ok(value)
    }
    fn fields(&mut self, depth: usize) -> Result<Fields> {
        ensure!(depth <= 3, "Epee nesting bound");
        let count = self.count(8)?;
        let mut fields: Fields = Vec::with_capacity(count);
        for _ in 0..count {
            let length = usize::from(self.byte()?);
            ensure!(length > 0 && length <= 32, "Epee key bound");
            let key = std::str::from_utf8(self.take(length)?)?.to_owned();
            ensure!(
                key.is_ascii() && !fields.iter().any(|(k, _)| k == &key),
                "duplicate/invalid Epee key"
            );
            let tag = self.byte()?;
            let value = self.value(tag, depth + 1)?;
            fields.push((key, value));
        }
        Ok(fields)
    }
    fn value(&mut self, tag: u8, depth: usize) -> Result<Value> {
        ensure!(depth <= 4, "Epee value nesting bound");
        if tag & Array::Array as u8 != 0 {
            let unit = tag & !(Array::Array as u8);
            ensure!(
                unit == Type::Uint8 as u8 || unit == Type::Object as u8,
                "unsupported Epee request array"
            );
            let count = self.count(MAX_OUTPUTS)?;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push(self.value(unit, depth + 1)?);
            }
            return Ok(Value::Array(unit, values));
        }
        Ok(match tag {
            n if n == Type::Uint8 as u8 => Value::U8(self.byte()?),
            n if n == Type::Uint64 as u8 => {
                Value::U64(u64::from_le_bytes(self.take(8)?.try_into()?))
            }
            n if n == Type::Bool as u8 => {
                let value = self.byte()?;
                ensure!(value <= 1, "invalid Epee boolean");
                Value::Bool(value == 1)
            }
            n if n == Type::String as u8 => {
                let len = self.count(MAX_REQUEST)?;
                Value::Bytes(self.take(len)?.to_vec())
            }
            n if n == Type::Object as u8 => Value::Object(self.fields(depth)?),
            _ => return Err(anyhow!("unsupported Epee request type")),
        })
    }
}
fn decode(bytes: &[u8]) -> Result<Fields> {
    ensure!(bytes.len() <= MAX_REQUEST, "Epee request byte bound");
    let mut cursor = Cursor { bytes, at: 0 };
    ensure!(
        cursor.take(8)? == HEADER && cursor.byte()? == VERSION,
        "Epee header/version"
    );
    let fields = cursor.fields(0)?;
    ensure!(cursor.at == bytes.len(), "trailing Epee request bytes");
    Ok(fields)
}
fn field(fields: &mut Fields, name: &str) -> Result<Value> {
    let index = fields
        .iter()
        .position(|(key, _)| key == name)
        .ok_or_else(|| anyhow!("missing Epee field {name}"))?;
    Ok(fields.remove(index).1)
}
fn uint(fields: &mut Fields, name: &str) -> Result<u64> {
    match field(fields, name)? {
        Value::U64(n) => Ok(n),
        _ => Err(anyhow!("Epee u64 field {name}")),
    }
}
fn count(out: &mut Vec<u8>, len: usize) -> Result<()> {
    let value = u64::try_from(len)?;
    let (width, tag) = if value < 1 << 6 {
        (1, 0)
    } else if value < 1 << 14 {
        (2, 1)
    } else if value < 1 << 30 {
        (4, 2)
    } else {
        ensure!(value < 1 << 62, "Epee length overflow");
        (8, 3)
    };
    out.extend_from_slice(&((value << 2) | tag).to_le_bytes()[..width]);
    Ok(())
}
fn key(out: &mut Vec<u8>, name: &str, kind: u8) -> Result<()> {
    ensure!(
        !name.is_empty() && name.len() <= 255,
        "Epee response key bound"
    );
    out.push(u8::try_from(name.len())?);
    out.extend_from_slice(name.as_bytes());
    out.push(kind);
    Ok(())
}
fn string(out: &mut Vec<u8>, name: &str, bytes: &[u8]) -> Result<()> {
    key(out, name, Type::String as u8)?;
    count(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}
fn u64_field(out: &mut Vec<u8>, name: &str, value: u64) -> Result<()> {
    key(out, name, Type::Uint64 as u8)?;
    out.extend_from_slice(&value.to_le_bytes());
    Ok(())
}
fn response(fields: usize) -> Result<Vec<u8>> {
    let mut out = HEADER.to_vec();
    out.push(VERSION);
    count(&mut out, fields)?;
    string(&mut out, "status", b"OK")?;
    Ok(out)
}

/// None denotes another endpoint, never a missing or malformed ledger result.
pub(super) fn dispatch(path: &str, body: &[u8], ledger: &impl Ledger) -> Result<Option<Vec<u8>>> {
    if !matches!(
        path,
        "/get_o_indexes.bin" | "/get_output_distribution.bin" | "/get_outs.bin" | "/get_blocks.bin"
    ) {
        return Ok(None);
    }
    let mut fields = decode(body)?;
    let mut out = response(if path == "/get_blocks.bin" { 3 } else { 2 })?;
    match path {
        "/get_blocks.bin" => {
            ensure!(
                field(&mut fields, "prune")? == Value::Bool(true),
                "unpruned block request"
            );
            let start = uint(&mut fields, "start_height")?;
            let requested = uint(&mut fields, "max_block_count")?;
            ensure!(
                start > 0
                    && requested > 0
                    && requested <= MAX_BLOCKS as u64
                    && start.checked_add(requested - 1).is_some()
                    && fields.is_empty(),
                "block request range/fields"
            );
            let blocks = ledger.scannable_blocks(start, requested)?;
            ensure!(
                blocks.len() == usize::try_from(requested)?,
                "ledger block cardinality"
            );
            key(&mut out, "blocks", Type::Object as u8 | Array::Array as u8)?;
            count(&mut out, blocks.len())?;
            for block in &blocks {
                ensure!(
                    !block.block.is_empty()
                        && block.block.len() <= MAX_BLOCK_RESPONSE
                        && block.transactions.len() <= MAX_OUTPUTS
                        && block.output_indices.len() == block.transactions.len() + 1,
                    "ledger block shape"
                );
                count(&mut out, 2)?;
                string(&mut out, "block", &block.block)?;
                key(&mut out, "txs", Type::Object as u8 | Array::Array as u8)?;
                count(&mut out, block.transactions.len())?;
                for tx in &block.transactions {
                    // This fixture contains only V2 non-miner RingCT transactions.
                    // A zero/missing hash makes the pinned daemon fall back to JSON.
                    ensure!(
                        !tx.blob.is_empty()
                            && tx.blob.len() <= MAX_BLOCK_RESPONSE
                            && tx.prunable_hash != [0; 32],
                        "ledger pruned transaction shape"
                    );
                    count(&mut out, 2)?;
                    string(&mut out, "blob", &tx.blob)?;
                    string(&mut out, "prunable_hash", &tx.prunable_hash)?;
                    ensure!(out.len() <= MAX_BLOCK_RESPONSE, "block response bound");
                }
                ensure!(out.len() <= MAX_BLOCK_RESPONSE, "block response bound");
            }
            key(
                &mut out,
                "output_indices",
                Type::Object as u8 | Array::Array as u8,
            )?;
            count(&mut out, blocks.len())?;
            for block in &blocks {
                count(&mut out, 1)?;
                key(&mut out, "indices", Type::Object as u8 | Array::Array as u8)?;
                count(&mut out, block.output_indices.len())?;
                for indexes in &block.output_indices {
                    ensure!(
                        !indexes.is_empty() && indexes.len() <= MAX_OUTPUTS,
                        "block output index bound"
                    );
                    count(&mut out, 1)?;
                    key(&mut out, "indices", Type::Uint64 as u8 | Array::Array as u8)?;
                    count(&mut out, indexes.len())?;
                    for index in indexes {
                        out.extend_from_slice(&index.to_le_bytes());
                    }
                }
                ensure!(out.len() <= MAX_BLOCK_RESPONSE, "block response bound");
            }
        }
        "/get_o_indexes.bin" => {
            let Value::Bytes(hash) = field(&mut fields, "txid")? else {
                return Err(anyhow!("txid is not bytes"));
            };
            let hash: [u8; 32] = hash.try_into().map_err(|_| anyhow!("txid length"))?;
            ensure!(fields.is_empty(), "unexpected output-index fields");
            let indexes = ledger.output_indexes(hash)?;
            ensure!(
                !indexes.is_empty() && indexes.len() <= MAX_OUTPUTS,
                "ledger index count bound"
            );
            key(
                &mut out,
                "o_indexes",
                Type::Uint64 as u8 | Array::Array as u8,
            )?;
            count(&mut out, indexes.len())?;
            for index in indexes {
                out.extend_from_slice(&index.to_le_bytes());
            }
        }
        "/get_output_distribution.bin" => {
            let from = uint(&mut fields, "from_height")?;
            let to = uint(&mut fields, "to_height")?;
            ensure!(
                field(&mut fields, "cumulative")? == Value::Bool(true),
                "only cumulative distribution supported"
            );
            ensure!(
                field(&mut fields, "compress")? == Value::Bool(false),
                "compressed distribution unsupported"
            );
            ensure!(
                field(&mut fields, "amounts")?
                    == Value::Array(Type::Uint8 as u8, vec![Value::U8(0)]),
                "only RingCT distribution supported"
            );
            ensure!(fields.is_empty(), "unexpected distribution fields");
            let len = to
                .checked_sub(from)
                .and_then(|n| n.checked_add(1))
                .ok_or_else(|| anyhow!("distribution range"))?;
            ensure!(len <= MAX_HEIGHTS as u64, "distribution height bound");
            let values = ledger.cumulative_distribution(from, to)?;
            ensure!(
                values.len() == usize::try_from(len)? && values.windows(2).all(|w| w[0] <= w[1]),
                "ledger cumulative distribution mismatch"
            );
            key(
                &mut out,
                "distributions",
                Type::Object as u8 | Array::Array as u8,
            )?;
            count(&mut out, 1)?;
            count(&mut out, 2)?;
            u64_field(&mut out, "start_height", from)?;
            let mut bytes = Vec::with_capacity(values.len() * 8);
            for value in values {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            string(&mut out, "distribution", &bytes)?;
        }
        "/get_outs.bin" => {
            let Value::Array(tag, entries) = field(&mut fields, "outputs")? else {
                return Err(anyhow!("output array required"));
            };
            ensure!(
                tag == Type::Object as u8
                    && !entries.is_empty()
                    && entries.len() <= MAX_OUTPUTS
                    && fields.is_empty(),
                "output request scope"
            );
            let mut indexes = Vec::with_capacity(entries.len());
            for entry in entries {
                let Value::Object(mut fields) = entry else {
                    return Err(anyhow!("output object required"));
                };
                ensure!(
                    field(&mut fields, "amount")? == Value::U8(0),
                    "only RingCT output indices supported"
                );
                indexes.push(uint(&mut fields, "index")?);
                ensure!(fields.is_empty(), "unexpected output fields");
            }
            let outputs = ledger.outputs(&indexes)?;
            ensure!(
                outputs.len() == indexes.len(),
                "ledger output cardinality mismatch"
            );
            key(&mut out, "outs", Type::Object as u8 | Array::Array as u8)?;
            count(&mut out, outputs.len())?;
            for output in outputs {
                count(&mut out, 5)?;
                u64_field(&mut out, "height", output.height)?;
                string(&mut out, "key", &output.key)?;
                string(&mut out, "mask", &output.mask)?;
                string(&mut out, "txid", &output.txid)?;
                key(&mut out, "unlocked", Type::Bool as u8)?;
                out.push(u8::from(output.unlocked));
            }
        }
        _ => return Err(anyhow!("Epee dispatch mismatch")),
    }
    let limit = if path == "/get_blocks.bin" {
        MAX_BLOCK_RESPONSE
    } else if path == "/get_output_distribution.bin" {
        MAX_DISTRIBUTION_RESPONSE
    } else {
        MAX_RESPONSE
    };
    ensure!(out.len() <= limit, "Epee response bound");
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_pruned_block_request_has_exact_fields() -> Result<()> {
        let mut bytes = HEADER.to_vec();
        bytes.push(VERSION);
        count(&mut bytes, 3)?;
        key(&mut bytes, "prune", Type::Bool as u8)?;
        bytes.push(1);
        u64_field(&mut bytes, "start_height", 100)?;
        u64_field(&mut bytes, "max_block_count", 1)?;
        let mut fields = decode(&bytes)?;
        assert_eq!(field(&mut fields, "prune")?, Value::Bool(true));
        assert_eq!(uint(&mut fields, "start_height")?, 100);
        assert_eq!(uint(&mut fields, "max_block_count")?, 1);
        assert!(fields.is_empty());
        bytes.push(0);
        assert!(decode(&bytes).is_err());
        Ok(())
    }

    #[test]
    fn bounded_decoder_rejects_trailing_duplicate_and_oversize() -> Result<()> {
        let mut bytes = HEADER.to_vec();
        bytes.push(VERSION);
        count(&mut bytes, 1)?;
        string(&mut bytes, "txid", &[7; 32])?;
        assert_eq!(
            decode(&bytes)?,
            vec![("txid".into(), Value::Bytes(vec![7; 32]))]
        );
        bytes.push(0);
        assert!(decode(&bytes).is_err());
        bytes.pop();
        bytes[9] = 2 << 2;
        string(&mut bytes, "txid", &[8; 32])?;
        assert!(decode(&bytes).is_err());
        assert!(decode(&vec![0; MAX_REQUEST + 1]).is_err());
        Ok(())
    }
    #[test]
    fn pinned_daemon_nonminimal_array_count_is_supported() -> Result<()> {
        let mut bytes = HEADER.to_vec();
        bytes.push(VERSION);
        count(&mut bytes, 1)?;
        key(
            &mut bytes,
            "outputs",
            Type::Object as u8 | Array::Array as u8,
        )?;
        bytes.extend_from_slice(&((1u64 << 2) | 3).to_le_bytes());
        count(&mut bytes, 2)?;
        key(&mut bytes, "amount", Type::Uint8 as u8)?;
        bytes.push(0);
        u64_field(&mut bytes, "index", 19)?;
        assert!(
            matches!(decode(&bytes)?.pop(), Some((_, Value::Array(_, entries))) if entries.len() == 1)
        );
        Ok(())
    }
}
