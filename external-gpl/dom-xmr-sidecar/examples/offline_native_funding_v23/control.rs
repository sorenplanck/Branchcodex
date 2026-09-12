//! Private supervisor pipe; never a network administrative interface.
use anyhow::{Result, anyhow, ensure};
use serde::Deserialize;
use serde_json::json;
use std::io::{BufRead, BufReader, Read, Write};

use super::rpc::Servers;

const SCHEMA: &str = "DOM-XMR-OFFLINE-CONTROL-V23";
const ACK_SCHEMA: &str = "DOM-XMR-OFFLINE-CONTROL-ACK-V23";
const MAX_CONTROL_LINE: usize = 8192;

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Status {
        schema: String,
        sequence: u64,
    },
    Advance {
        schema: String,
        sequence: u64,
        height: u64,
        timestamp: u64,
        include_tx_hashes: Vec<String>,
    },
    Stop {
        schema: String,
        sequence: u64,
    },
}

fn hashes(values: &[String]) -> Result<Vec<[u8; 32]>> {
    ensure!(values.len() <= 16, "control inclusion bound");
    values
        .iter()
        .map(|text| {
            ensure!(
                text.len() == 64
                    && text
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "control hash encoding"
            );
            let hash: [u8; 32] = hex::decode(text)?
                .try_into()
                .map_err(|_| anyhow!("control hash length"))?;
            ensure!(hash != [0; 32], "control zero hash");
            Ok(hash)
        })
        .collect()
}

pub(super) fn serve(input: impl Read, servers: Servers) -> Result<()> {
    let mut reader = BufReader::new(input);
    let mut sequence = 1u64;
    loop {
        let mut line = String::new();
        let length = reader
            .by_ref()
            .take((MAX_CONTROL_LINE + 1) as u64)
            .read_line(&mut line)?;
        if length == 0 {
            return servers.finish();
        }
        ensure!(
            length <= MAX_CONTROL_LINE && line.ends_with('\n'),
            "bounded control JSON line required"
        );
        // Malformed framing/schema/sequence is terminal, never guessed or
        // retried as a different command. Semantic refusal consumes one seq.
        let command: Command = serde_json::from_str(&line)?;
        let (schema, supplied_sequence) = match &command {
            Command::Status { schema, sequence }
            | Command::Advance {
                schema, sequence, ..
            }
            | Command::Stop { schema, sequence } => (schema, *sequence),
        };
        ensure!(
            schema == SCHEMA && supplied_sequence == sequence,
            "control schema/sequence mismatch"
        );
        let stop = matches!(&command, Command::Stop { .. });
        let result = match command {
            Command::Status { .. } | Command::Stop { .. } => servers.scenario_status(),
            Command::Advance {
                height,
                timestamp,
                include_tx_hashes,
                ..
            } => hashes(&include_tx_hashes)
                .and_then(|hashes| servers.advance(height, timestamp, &hashes)),
        };
        let accepted = result.is_ok();
        // Even a rejected semantic transition reports the actual retained
        // state, never an invented requested height or an optimistic receipt.
        let status = match result {
            Ok(status) => status,
            Err(_) => servers.scenario_status()?,
        };
        let ack = json!({"schema":ACK_SCHEMA,"sequence":sequence,"accepted":accepted,"status":status,
            "error":if accepted { serde_json::Value::Null } else { json!("control-refused") }});
        let mut output = std::io::stdout().lock();
        serde_json::to_writer(&mut output, &ack)?;
        output.write_all(b"\n")?;
        output.flush()?;
        drop(output);
        if stop {
            return servers.finish();
        }
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| anyhow!("control sequence exhausted"))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_commands_reject_unknown_fields_and_unbounded_hashes() {
        assert!(serde_json::from_str::<Command>(r#"{"schema":"DOM-XMR-OFFLINE-CONTROL-V23","sequence":1,"operation":"status","height":999}"#).is_err());
        assert!(hashes(&["00".repeat(32)]).is_err());
        assert!(hashes(&["AA".repeat(32)]).is_err());
        assert!(hashes(&vec!["11".repeat(32); 17]).is_err());
        assert_eq!(hashes(&["11".repeat(32)]).unwrap(), vec![[0x11; 32]]);
    }
}
