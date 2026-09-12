//! Bounded pages of one immutable simulated DOM snapshot, never live chain data.
use super::*;

pub(super) fn scan_response(first: &str, identity: &Value, blocks: &[Value]) -> Result<Vec<u8>> {
    let target = first
        .strip_prefix("GET ")
        .and_then(|s| s.strip_suffix(" HTTP/1.1"))
        .ok_or("snapshot HTTP method/version")?;
    let query = target
        .strip_prefix("/chain/scan/scriptless/v1?")
        .ok_or("snapshot path")?;
    let mut fields = std::collections::BTreeMap::new();
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').ok_or("snapshot query pair")?;
        if fields.insert(name, value).is_some() {
            return Err("duplicate snapshot query".into());
        }
    }
    let from: u64 = fields.remove("from").ok_or("snapshot from")?.parse()?;
    let to: u64 = fields.remove("to").ok_or("snapshot to")?.parse()?;
    let magic: u64 = fields
        .remove("expected_network_magic")
        .ok_or("snapshot magic")?
        .parse()?;
    let chain = fields.remove("expected_chain_id").ok_or("snapshot chain")?;
    if identity["network_magic"].as_u64() != Some(magic)
        || identity["chain_id"].as_str() != Some(chain)
        || to.checked_sub(from).filter(|span| *span < 64).is_none()
    {
        return Err("snapshot request scope/range".into());
    }
    let anchor = fields.remove("anchor_hash");
    let request_anchor = match (from, anchor) {
        (0, None) => Value::Null,
        (height, Some(hash)) if height > 0 => {
            let previous = blocks
                .get(usize::try_from(height - 1)?)
                .ok_or("snapshot prior block")?;
            if previous["block_hash"].as_str() != Some(hash) {
                return Err("snapshot anchor mismatch".into());
            }
            json!({"height":height - 1,"block_hash":hash})
        }
        _ => return Err("snapshot anchor required".into()),
    };
    if !fields.is_empty() {
        return Err("unknown snapshot query".into());
    }
    let tip = identity["tip_height"].as_u64().ok_or("snapshot tip")?;
    let page = if from <= tip {
        blocks
            .get(usize::try_from(from)?..=usize::try_from(to.min(tip))?)
            .ok_or("snapshot page absent")?
            .to_vec()
    } else {
        Vec::new()
    };
    let last = page.last();
    let served_to = last.map(|b| b["height"].clone()).unwrap_or(Value::Null);
    let continuation = match last {
        Some(last) if last["height"].as_u64().ok_or("page height")? < tip => json!({
            "next_height":last["height"].as_u64().ok_or("page height")? + 1,
            "anchor":{"height":last["height"],"block_hash":last["block_hash"]},
            "snapshot_tip_height":tip,"snapshot_tip_hash":identity["tip_hash"]}),
        _ => Value::Null,
    };
    Ok(serde_json::to_vec(
        &json!({"schema_version":1,"status":"ok","canonical":true,
        "identity":identity,"requested_from":from,"requested_to":to,"served_from":from,
        "served_to":served_to,"request_anchor":request_anchor,"blocks":page,"continuation":continuation}),
    )?)
}
