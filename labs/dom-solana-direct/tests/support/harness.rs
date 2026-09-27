//! The live environment, exactly as `scripts/f8-run-solana-live-v1.sh` exports
//! it, plus the evidence record the workflow uploads.
//!
//! Every value is read from the environment and none is defaulted: a missing
//! variable means the harness did not run, and a test that silently invented a
//! program id or a genesis hash would be testing nothing. `require` therefore
//! panics with the variable's name, which is the fastest possible diagnosis.

use dom_solana_direct_lab::cluster::KeypairV1;
use solana_types::{SolanaHash, SolanaPubkey};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

/// Bound on waiting for one Solana transaction to reach a status.
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(90);

pub struct LiveEnvironment {
    pub rpc_url: String,
    pub program_id: SolanaPubkey,
    pub programdata: SolanaPubkey,
    pub programdata_sha256: [u8; 32],
    pub genesis: SolanaHash,
    pub payer: PathBuf,
    pub funder: PathBuf,
    pub beneficiary: PathBuf,
    pub refund: PathBuf,
    pub directory: PathBuf,
    pub campaign: PathBuf,
    /// The object the program job built and the harness loaded, so a scenario can
    /// prove the bytes on chain are those bytes rather than trust that they are.
    pub program_so: PathBuf,
    /// The legacy SPL mint the harness created, and its decimals. The escrow's
    /// `transfer_checked` fails if the frozen setup declares different decimals
    /// than the mint has, so this value is read, never assumed.
    pub mint: SolanaPubkey,
    pub mint_decimals: u8,
    /// Token accounts, each owned by the settlement role of the same name.
    pub funder_token: SolanaPubkey,
    pub beneficiary_token: SolanaPubkey,
    pub refund_token: SolanaPubkey,
}

fn require(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => value,
        _ => panic!(
            "{name} is not set: run this test through scripts/f8-run-solana-live-v1.sh, \
             which starts the cluster, deploys the escrow, revokes the upgrade authority \
             and exports every value these tests refuse to invent"
        ),
    }
}

fn decode_hex32(value: &str, name: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64, "{name} must be 32 hex-encoded bytes");
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        let byte = &value[index * 2..index * 2 + 2];
        *slot = u8::from_str_radix(byte, 16).unwrap_or_else(|_| panic!("{name} is not hex"));
    }
    out
}

impl LiveEnvironment {
    /// Read the environment, or explain which variable is missing.
    pub fn from_env() -> Self {
        let directory = PathBuf::from(require("DOM_SOLANA_LIVE_DIR_V1"));
        let campaign = std::env::var("DOM_SOLANA_LIVE_CAMPAIGN_V1")
            .map(PathBuf::from)
            .unwrap_or_else(|_| directory.join("campaign.json"));
        Self {
            rpc_url: require("DOM_SOLANA_LIVE_RPC_V1"),
            program_id: SolanaPubkey::from_base58(&require("DOM_SOLANA_LIVE_PROGRAM_V1"))
                .expect("DOM_SOLANA_LIVE_PROGRAM_V1 is base58"),
            programdata: SolanaPubkey::from_base58(&require("DOM_SOLANA_LIVE_PROGRAMDATA_V1"))
                .expect("DOM_SOLANA_LIVE_PROGRAMDATA_V1 is base58"),
            programdata_sha256: decode_hex32(
                &require("DOM_SOLANA_LIVE_PROGRAMDATA_SHA256_V1"),
                "DOM_SOLANA_LIVE_PROGRAMDATA_SHA256_V1",
            ),
            genesis: SolanaHash::from_base58(&require("DOM_SOLANA_LIVE_GENESIS_V1"))
                .expect("DOM_SOLANA_LIVE_GENESIS_V1 is base58"),
            payer: PathBuf::from(require("DOM_SOLANA_LIVE_PAYER_V1")),
            funder: PathBuf::from(require("DOM_SOLANA_LIVE_FUNDER_V1")),
            beneficiary: PathBuf::from(require("DOM_SOLANA_LIVE_BENEFICIARY_V1")),
            refund: PathBuf::from(require("DOM_SOLANA_LIVE_REFUND_V1")),
            program_so: PathBuf::from(require("DOM_SOLANA_LIVE_PROGRAM_SO_V1")),
            mint: SolanaPubkey::from_base58(&require("DOM_SOLANA_LIVE_MINT_V1"))
                .expect("DOM_SOLANA_LIVE_MINT_V1 is base58"),
            mint_decimals: require("DOM_SOLANA_LIVE_MINT_DECIMALS_V1")
                .parse()
                .expect("DOM_SOLANA_LIVE_MINT_DECIMALS_V1 is a small integer"),
            funder_token: SolanaPubkey::from_base58(&require("DOM_SOLANA_LIVE_FUNDER_TOKEN_V1"))
                .expect("DOM_SOLANA_LIVE_FUNDER_TOKEN_V1 is base58"),
            beneficiary_token: SolanaPubkey::from_base58(&require(
                "DOM_SOLANA_LIVE_BENEFICIARY_TOKEN_V1",
            ))
            .expect("DOM_SOLANA_LIVE_BENEFICIARY_TOKEN_V1 is base58"),
            refund_token: SolanaPubkey::from_base58(&require("DOM_SOLANA_LIVE_REFUND_TOKEN_V1"))
                .expect("DOM_SOLANA_LIVE_REFUND_TOKEN_V1 is base58"),
            directory,
            campaign,
        }
    }

    pub fn keypair(path: &Path) -> KeypairV1 {
        KeypairV1::load_solana_keygen_json(path)
            .unwrap_or_else(|error| panic!("keypair {}: {error}", path.display()))
    }

    /// Append one scenario's outcome to the campaign record. Written after every
    /// scenario, pass or fail, so an interrupted run still says how far it got.
    pub fn record(&self, scenario: &str, outcome: serde_json::Value) {
        let mut root = fs::read_to_string(&self.campaign)
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
            .unwrap_or_else(|| {
                serde_json::json!({
                    "schema": "DOM-SOLANA-LIVE-CAMPAIGN-V1",
                    "status": "running",
                    "scenarios": {},
                })
            });
        root["schema"] = serde_json::json!("DOM-SOLANA-LIVE-CAMPAIGN-V1");
        // Per-scenario `status` fields carry each outcome; the authoritative
        // verdict for the campaign as a whole is the test binary's exit status,
        // recorded by the harness in harness.json.
        root["status"] = serde_json::json!("recorded");
        root["cluster"] = serde_json::json!({
            "rpc_url": self.rpc_url,
            "genesis": self.genesis.to_base58(),
            "program_id": self.program_id.to_base58(),
            "programdata": self.programdata.to_base58(),
            "programdata_sha256": hex32(&self.programdata_sha256),
        });
        root["limits"] = serde_json::json!([
            "A local cluster is not mainnet-beta: fees, congestion and validator set differ.",
            "Both DOM participants run in one process: the cryptography is real, the \
             separation of the two parties is not.",
            "The DOM chain is regtest with its own timestamp tolerance; the schedule \
             arithmetic is exercised, not a mainnet block interval.",
        ]);
        // `root["scenarios"]` inserts Null for a missing key, and
        // `as_object_mut()` on Null is None -- so the first recording silently
        // wrote nothing and the campaign of the first green run said
        // `"scenarios": null`. Establish the object before inserting into it.
        if !root["scenarios"].is_object() {
            root["scenarios"] = serde_json::json!({});
        }
        let recorded = match root["scenarios"].as_object_mut() {
            Some(map) => {
                map.insert(scenario.to_string(), outcome);
                map.len()
            }
            None => 0,
        };
        root["scenarios_recorded"] = serde_json::json!(recorded);
        if let Some(map) = root.as_object_mut() {
            // Written by the workflow before the harness ran; it is no longer
            // true once a scenario has reported.
            map.remove("reason");
        }
        if let Some(parent) = self.campaign.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(
            &self.campaign,
            format!("{}\n", serde_json::to_string_pretty(&root).unwrap_or_default()),
        );
    }
}

pub fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
