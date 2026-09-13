//! Test-only pagination across an immutable baseline and its contiguous live
//! suffix. No combined history allocation, rebased heights, or synthetic genesis.
use super::*;

fn block_at<'a>(baseline: &'a [Value], window: &'a [Value], height: u64) -> Result<&'a Value> {
    if baseline.is_empty() || baseline.len() > 4096 || window.is_empty() || window.len() > 4096 {
        return Err("split DOM history bounds".into());
    }
    let anchor = baseline.last().ok_or("baseline anchor")?;
    let base = anchor["height"].as_u64().ok_or("baseline height")?;
    if baseline.first().and_then(|block| block["height"].as_u64()) != Some(0)
        || u64::try_from(baseline.len())? != base.checked_add(1).ok_or("baseline overflow")?
        || window.first() != Some(anchor)
    {
        return Err("split DOM history does not share the original anchor".into());
    }
    let block = if height <= base {
        baseline.get(usize::try_from(height)?)
    } else {
        window.get(usize::try_from(
            height.checked_sub(base).ok_or("window offset")?,
        )?)
    }
    .ok_or("requested DOM history is unavailable")?;
    if block["height"].as_u64() != Some(height) {
        return Err("DOM history height discontinuity".into());
    }
    Ok(block)
}

pub(super) fn scan_response(
    first: &str,
    identity: &Value,
    baseline: &[Value],
    window: &[Value],
) -> Result<Vec<u8>> {
    let tip = identity["tip_height"].as_u64().ok_or("snapshot tip")?;
    if window.last() != Some(block_at(baseline, window, tip)?) {
        return Err("split DOM history tip mismatch".into());
    }
    scan_response_with_reader_v24(first, identity, |height| {
        Ok(block_at(baseline, window, height)?.clone())
    })
}

pub(super) fn scan_response_with_reader_v24(
    first: &str,
    identity: &Value,
    mut block_at: impl FnMut(u64) -> Result<Value>,
) -> Result<Vec<u8>> {
    let query = first
        .strip_prefix("GET /chain/scan/scriptless/v1?")
        .and_then(|value| value.strip_suffix(" HTTP/1.1"))
        .ok_or("snapshot HTTP path/method/version")?;
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
    let request_anchor = match (from, fields.remove("anchor_hash")) {
        (0, None) => {
            block_at(0)?;
            Value::Null
        }
        (height, Some(hash)) if height > 0 => {
            let previous = block_at(height - 1)?;
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
    let tip_block = block_at(tip)?;
    if tip_block["block_hash"] != identity["tip_hash"] {
        return Err("split DOM history tip mismatch".into());
    }
    let mut page = Vec::new();
    if from <= tip {
        for height in from..=to.min(tip) {
            let block = block_at(height)?;
            if height > 0 && block["previous_block_hash"] != block_at(height - 1)?["block_hash"] {
                return Err("split DOM history hash discontinuity".into());
            }
            page.push(block);
        }
    }
    let last = page.last();
    let served_to = last
        .map(|block| block["height"].clone())
        .unwrap_or(Value::Null);
    let continuation = match last {
        Some(last) if last["height"].as_u64().ok_or("page height")? < tip => json!({
            "next_height":last["height"].as_u64().ok_or("page height")?.checked_add(1).ok_or("continuation overflow")?,
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

#[test]
fn split_history_pages_match_legacy_and_refuse_missing_genesis_or_changed_anchor() {
    let blocks: Vec<_> = (0..6)
        .map(|height| {
            json!({"height":height,"block_hash":format!("h{height}"),
        "previous_block_hash":format!("h{}",height - 1)})
        })
        .collect();
    let identity = json!({"tip_height":5,"tip_hash":"h5","network_magic":7,"chain_id":"chain"});
    let request = "GET /chain/scan/scriptless/v1?from=1&to=5&expected_network_magic=7&expected_chain_id=chain&anchor_hash=h0 HTTP/1.1";
    assert_eq!(
        scan_response(request, &identity, &blocks[..3], &blocks[2..]).unwrap(),
        super::scan_response(request, &identity, &blocks).unwrap()
    );
    assert!(scan_response(request, &identity, &blocks[1..3], &blocks[2..]).is_err());
    let mut changed = blocks[2..].to_vec();
    changed[0]["block_hash"] = json!("changed");
    assert!(scan_response(request, &identity, &blocks[..3], &changed).is_err());
    changed = blocks[2..].to_vec();
    changed[1]["previous_block_hash"] = json!("changed");
    assert!(scan_response(request, &identity, &blocks[..3], &changed).is_err());
}

#[test]
fn absolute_height_above_4096_remains_paginated_without_combining_vectors() {
    let block = |height: u64| {
        json!({"height":height,"block_hash":format!("h{height}"),
        "previous_block_hash":format!("h{}", height.saturating_sub(1))})
    };
    let baseline: Vec<_> = (0..=4095).map(block).collect();
    let window: Vec<_> = (4095..=4100).map(block).collect();
    let identity =
        json!({"tip_height":4100,"tip_hash":"h4100","network_magic":7,"chain_id":"chain"});
    let request = "GET /chain/scan/scriptless/v1?from=4094&to=4100&expected_network_magic=7&expected_chain_id=chain&anchor_hash=h4093 HTTP/1.1";
    let response: Value =
        serde_json::from_slice(&scan_response(request, &identity, &baseline, &window).unwrap())
            .unwrap();
    assert_eq!(response["blocks"].as_array().unwrap().len(), 7);
    assert_eq!(response["blocks"][2]["height"], json!(4096));
    assert_eq!(response["blocks"][2]["previous_block_hash"], json!("h4095"));
    assert!(response["continuation"].is_null());
}
