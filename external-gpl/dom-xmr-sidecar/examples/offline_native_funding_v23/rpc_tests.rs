use super::*;
use crate::{build, point, Request};

#[test]
fn idle_keep_alive_connection_does_not_monopolize_a_voter() -> Result<()> {
    let request = Request {
        route_peer: None,
        position: 0,
        schema: "DOM-XMR-OFFLINE-FUNDING-REQUEST-V23".into(),
        network_tag: 1,
        combined_spend_public_key: hex::encode(point(11).compress().to_bytes()),
        amount_piconero: 1_000_000,
        max_fee_piconero: 1_000_000,
        recipient_view_public_key: None,
    };
    let servers = Servers::start(build(&request)?.0, 1)?;
    let address = servers.urls()[0]
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("test URL"))?;
    let idle = TcpStream::connect(address)?;
    for (method, path) in [
        ("GET", "/get_height"),
        ("POST", "/get_height"),
        ("GET", "/get_info"),
        ("POST", "/get_info"),
    ] {
        let mut active = TcpStream::connect(address)?;
        active.set_read_timeout(Some(Duration::from_secs(2)))?;
        active.set_write_timeout(Some(Duration::from_secs(2)))?;
        active.write_all(
            format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
                .as_bytes(),
        )?;
        let mut response = Vec::new();
        loop {
            let mut buffer = [0; 512];
            let count = active.read(&mut buffer)?;
            ensure!(
                count > 0 && response.len() + count <= 2048,
                "test response bound"
            );
            response.extend_from_slice(&buffer[..count]);
            if let Some(end) = response.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&response[..end])?;
                let length = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .ok_or_else(|| anyhow!("test response length"))?
                    .parse::<usize>()?;
                if response.len() >= end + 4 + length {
                    let body: Value = serde_json::from_slice(&response[end + 4..])?;
                    assert_eq!(body["height"], ledger::TIP_HEIGHT + 1);
                    break;
                }
            }
        }
        drop(active);
    }
    drop(idle);
    servers.finish()
}
