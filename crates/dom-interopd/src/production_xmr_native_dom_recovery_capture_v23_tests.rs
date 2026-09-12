//! Captures only an actual loopback submission and always refuses admission.
use super::*;

pub(super) fn capture_submission(
    stream: &mut std::net::TcpStream,
    received: &[u8],
) -> Result<Vec<u8>> {
    let split = received
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("capture header end")?
        + 4;
    let header = std::str::from_utf8(&received[..split])?;
    if header.lines().next() != Some("POST /tx/submit HTTP/1.1") {
        return Err("capture endpoint".into());
    }
    let mut length = None;
    let mut auth = false;
    for line in header.lines().skip(1).filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("capture header")?;
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("duplicate capture length".into());
            }
            length = Some(value.trim().parse::<usize>()?);
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("chunked capture refused".into());
        }
        if name.eq_ignore_ascii_case("authorization") {
            if auth || value.trim() != "Bearer offline-dom-snapshot-v23" {
                return Err("capture authorization".into());
            }
            auth = true;
        }
    }
    let length = length.ok_or("capture length missing")?;
    if !auth || length == 0 || length > 4 * 1024 * 1024 {
        return Err("capture scope/size".into());
    }
    let mut body = received[split..].to_vec();
    if body.len() > length {
        return Err("capture trailing bytes".into());
    }
    while body.len() < length {
        let remaining = (length - body.len()).min(8192);
        let mut buffer = [0; 8192];
        let n = stream.read(&mut buffer[..remaining])?;
        if n == 0 {
            return Err("capture short body".into());
        }
        body.extend_from_slice(&buffer[..n]);
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Submission {
        tx_hex: String,
    }
    let submission: Submission = serde_json::from_slice(&body)?;
    let bytes = hex::decode(submission.tx_hex)?;
    let tx = dom_consensus::Transaction::from_bytes(&bytes)?;
    if tx.to_bytes()? != bytes {
        return Err("noncanonical captured transaction".into());
    }
    stream.write_all(
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )?;
    Ok(bytes)
}
