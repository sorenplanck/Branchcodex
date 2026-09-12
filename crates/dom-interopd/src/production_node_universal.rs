//! V4 credential stream: seven common owners plus two independently tagged
//! chain credential groups. V1--V3 parsers keep their exact frozen semantics.
use super::*;
use crate::production_config::ProductionChainFamilyV11;
use std::io::Read as _;

const HEADER: &[u8] = b"DOM-INTEROPD-SECRETS-V4";
const MAX_BYTES: usize = MAX_PRODUCTION_SECRET_STREAM_BYTES_V3 + 1024;

/// Redacted errors from the universal credential boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProductionSecretsV4Error {
    /// The supervisor did not deliver a bounded, nonterminal complete stream.
    #[error("universal credential stream unavailable or oversized")]
    Stream,
    /// Header, position, family, field count or encoding is not canonical.
    #[error("universal credential stream shape rejected")]
    Shape,
    /// Independent authorities were given the same secret material.
    #[error("universal credentials are not independent")]
    Reused,
    /// Credential families do not match the admitted ordered route.
    #[error("credential families do not match the route")]
    FamilyMismatch,
}

/// One external leg's single-use key owners. No other chain's key is required.
/// The selected family's signer performs its own scalar/public-key checks.
pub enum ProductionLegCredentialsV4 {
    /// Bitcoin participant signing share.
    Bitcoin {
        /// Local participant's key, zeroized on drop.
        participant: Zeroizing<[u8; 32]>,
    },
    /// EVM local signer.
    Evm {
        /// Local EIP-1559 key, zeroized on drop.
        signing: Zeroizing<[u8; 32]>,
    },
    /// Solana local signing seed and independent authenticated peer connection.
    Solana {
        /// Local Ed25519 seed.
        seed: Zeroizing<[u8; 32]>,
        /// Authentication key for the peer signer.
        peer_auth: Zeroizing<[u8; 32]>,
    },
    /// One encrypted local-share store and the authenticated XMR sidecar.
    /// The complementary share must come from a verified DOM revelation.
    Monero {
        /// Local participant share-store master key.
        local_store: Zeroizing<[u8; 32]>,
        /// Sidecar transport key.
        sidecar_auth: Zeroizing<[u8; 32]>,
    },
}
impl ProductionLegCredentialsV4 {
    /// Family identified by this credential group.
    pub const fn family(&self) -> ProductionChainFamilyV11 {
        match self {
            Self::Bitcoin { .. } => ProductionChainFamilyV11::Btc,
            Self::Evm { .. } => ProductionChainFamilyV11::Evm,
            Self::Solana { .. } => ProductionChainFamilyV11::Sol,
            Self::Monero { .. } => ProductionChainFamilyV11::Xmr,
        }
    }
    fn borrow_keys(&self) -> Vec<&[u8]> {
        match self {
            Self::Bitcoin { participant } => vec![participant.as_slice()],
            Self::Evm { signing } => vec![signing.as_slice()],
            Self::Solana { seed, peer_auth } => vec![seed.as_slice(), peer_auth.as_slice()],
            Self::Monero {
                local_store,
                sidecar_auth,
            } => vec![local_store.as_slice(), sidecar_auth.as_slice()],
        }
    }
}

/// Decoded universal stream. No formatter, clone, serializer or default can
/// duplicate or expose it. Common fields are crate-private for the sole root.
pub struct ProductionSecretsV4 {
    pub(crate) bearer: Zeroizing<Vec<u8>>,
    pub(crate) upstream_relay: Zeroizing<[u8; 32]>,
    pub(crate) downstream_relay: Zeroizing<[u8; 32]>,
    pub(crate) identity_passphrase: Zeroizing<Vec<u8>>,
    pub(crate) dom_wallet_passphrase: Zeroizing<Vec<u8>>,
    pub(crate) route_seal: Zeroizing<[u8; 32]>,
    pub(crate) refund_credential: Zeroizing<[u8; 32]>,
    pub(crate) legs: [ProductionLegCredentialsV4; 2],
    pub(crate) f6_hsm: [Vec<Zeroizing<[u8; 32]>>; 2],
}

/// Native common authorities plus exactly two selected credential owners.
/// No Bitcoin/EVM fallback key is constructed during this conversion.
#[cfg(feature = "production")]
pub(crate) struct ProductionSecretPartsV4 {
    pub(crate) bearer: BearerTokenV1,
    pub(crate) upstream_relay_signing_secret: Zeroizing<[u8; 32]>,
    pub(crate) downstream_relay_signing_secret: Zeroizing<[u8; 32]>,
    pub(crate) identity_passphrase: Zeroizing<Vec<u8>>,
    pub(crate) dom_wallet_passphrase: Zeroizing<String>,
    pub(crate) route_secret_seal_key: RouteSecretSealKeyV1,
    pub(crate) xmr_graph_vault_key_v23:
        crate::production_dom_vaults_v12::ProductionXmrGraphVaultKeyV23,
    pub(crate) refund_arming_credential: ProductionRefundArmingCredentialV1,
    pub(crate) legs: [ProductionLegCredentialsV4; 2],
    pub(crate) f6_hsm: [Vec<Zeroizing<[u8; 32]>>; 2],
}

#[cfg(feature = "production")]
impl ProductionSecretsV4 {
    /// Import native common authorities only after exact selected-family
    /// agreement. Moving this value consumes every secret-bearing field once.
    pub(crate) fn into_parts(
        self,
        expected: [ProductionChainFamilyV11; 2],
    ) -> Result<ProductionSecretPartsV4, ProductionSecretsV4Error> {
        self.require_families(expected)?;
        let bearer = secret_string(self.bearer)?;
        // BearerTokenV1 takes String by value and immediately protects it with
        // its own zeroizing owner. The temporary Zeroizing remains wiped.
        let bearer =
            BearerTokenV1::new(bearer.to_string()).map_err(|_| ProductionSecretsV4Error::Shape)?;
        let dom_wallet_passphrase = secret_string(self.dom_wallet_passphrase)?;
        let xmr_graph_vault_key_v23 =
            crate::production_dom_vaults_v12::ProductionXmrGraphVaultKeyV23::retain(
                &self.route_seal,
            );
        let route_secret_seal_key = RouteSecretSealKeyV1::import_zeroizing(self.route_seal)
            .map_err(|_| ProductionSecretsV4Error::Shape)?;
        let refund_arming_credential =
            ProductionRefundArmingCredentialV1::import_zeroizing(self.refund_credential)
                .map_err(|_| ProductionSecretsV4Error::Shape)?;
        Ok(ProductionSecretPartsV4 {
            bearer,
            upstream_relay_signing_secret: self.upstream_relay,
            downstream_relay_signing_secret: self.downstream_relay,
            identity_passphrase: self.identity_passphrase,
            dom_wallet_passphrase,
            route_secret_seal_key,
            xmr_graph_vault_key_v23,
            refund_arming_credential,
            legs: self.legs,
            f6_hsm: self.f6_hsm,
        })
    }
}

#[cfg(feature = "production")]
fn secret_string(value: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, ProductionSecretsV4Error> {
    match String::from_utf8(value.to_vec()) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(error) => {
            use zeroize::Zeroize as _;
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            Err(ProductionSecretsV4Error::Shape)
        }
    }
}

/// One bounded read distinguishes the two explicit live headers. A malformed
/// V4 body never falls back to V3, and a V3 stream never gains V4 semantics.
#[cfg(feature = "production")]
pub(crate) enum ProductionRunSecretsV11 {
    LegacyV3(ProductionSecretsV3),
    UniversalV4(ProductionSecretsV4),
}

#[cfg(feature = "production")]
impl ProductionRunSecretsV11 {
    pub(crate) fn read(mut reader: impl std::io::Read) -> Result<Self, ProductionSecretsV4Error> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_BYTES + 1));
        std::io::Read::by_ref(&mut reader)
            .take(MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ProductionSecretsV4Error::Stream)?;
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(ProductionSecretsV4Error::Stream);
        }
        match bytes.split(|byte| *byte == b'\n').next() {
            Some(header) if header == HEADER => parse(&bytes).map(Self::UniversalV4),
            Some(b"DOM-INTEROPD-SECRETS-V3") => {
                let fields = read_production_secret_fields_v3(bytes.as_slice())
                    .map_err(|_| ProductionSecretsV4Error::Shape)?;
                let common = production_secrets_from_fields(fields.common.common)
                    .map_err(|_| ProductionSecretsV4Error::Shape)?;
                Ok(Self::LegacyV3(ProductionSecretsV3 {
                    common: ProductionSecretsV2 {
                        common,
                        evm_signing_secret: fields.common.evm_signing_secret,
                    },
                    upstream_f6_hsm_credentials: fields.upstream_f6_hsm_credentials,
                    downstream_f6_hsm_credentials: fields.downstream_f6_hsm_credentials,
                }))
            }
            _ => Err(ProductionSecretsV4Error::Shape),
        }
    }
}

#[cfg(feature = "production")]
pub(crate) fn read_production_run_secrets_v11_from_stdin(
) -> Result<ProductionRunSecretsV11, ProductionSecretsV4Error> {
    use std::io::IsTerminal as _;
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(ProductionSecretsV4Error::Stream);
    }
    ProductionRunSecretsV11::read(stdin.lock())
}
impl ProductionSecretsV4 {
    /// Cross-check both positions before opening any key owner or client.
    pub fn require_families(
        &self,
        families: [ProductionChainFamilyV11; 2],
    ) -> Result<(), ProductionSecretsV4Error> {
        if self.legs[0].family() != families[0] || self.legs[1].family() != families[1] {
            return Err(ProductionSecretsV4Error::FamilyMismatch);
        }
        Ok(())
    }

    /// Consume a bounded supervisor stream. The read window is wiped on all
    /// paths, including interrupted/oversized reads. No trailing newline is
    /// accepted; the supervisor must close its writer to terminate the stream.
    pub fn read(mut reader: impl std::io::Read) -> Result<Self, ProductionSecretsV4Error> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_BYTES + 1));
        std::io::Read::by_ref(&mut reader)
            .take(MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ProductionSecretsV4Error::Stream)?;
        if bytes.len() > MAX_BYTES {
            return Err(ProductionSecretsV4Error::Stream);
        }
        parse(&bytes)
    }
}

/// Read V4 exactly once from a nonterminal supervisor-owned standard input.
/// No legacy stream is inferred or substituted on parsing failure.
pub fn read_production_secrets_v4_from_stdin(
) -> Result<ProductionSecretsV4, ProductionSecretsV4Error> {
    use std::io::IsTerminal as _;
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(ProductionSecretsV4Error::Stream);
    }
    ProductionSecretsV4::read(stdin.lock())
}

fn parse(bytes: &[u8]) -> Result<ProductionSecretsV4, ProductionSecretsV4Error> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(ProductionSecretsV4Error::Stream);
    }
    let mut fields = bytes.split(|byte| *byte == b'\n');
    if fields.next() != Some(HEADER) {
        return Err(ProductionSecretsV4Error::Shape);
    }
    let bearer = field(&mut fields, MAX_DOM_NODE_BEARER_BYTES_V1)?;
    let upstream_relay = key(&mut fields)?;
    let downstream_relay = key(&mut fields)?;
    let identity_passphrase = field(&mut fields, MAX_CONTRACTS_IDENTITY_PASSPHRASE_BYTES_V1)?;
    let dom_wallet_passphrase = field(&mut fields, MAX_DOM_WALLET_PASSPHRASE_BYTES_V1)?;
    if std::str::from_utf8(&bearer).is_err() || std::str::from_utf8(&dom_wallet_passphrase).is_err()
    {
        return Err(ProductionSecretsV4Error::Shape);
    }
    let route_seal = key(&mut fields)?;
    let refund_credential = key(&mut fields)?;
    let upstream = leg(&mut fields, b"upstream_family=")?;
    let downstream = leg(&mut fields, b"downstream_family=")?;
    let upstream_count = parse_hsm_count_v3(
        fields.next().ok_or(ProductionSecretsV4Error::Shape)?,
        UPSTREAM_F6_HSM_COUNT_PREFIX_V3,
    )
    .map_err(|_| ProductionSecretsV4Error::Shape)?;
    let upstream_hsm = decode_hsm_credentials_v3(&mut fields, upstream_count)
        .map_err(|_| ProductionSecretsV4Error::Shape)?;
    let downstream_count = parse_hsm_count_v3(
        fields.next().ok_or(ProductionSecretsV4Error::Shape)?,
        DOWNSTREAM_F6_HSM_COUNT_PREFIX_V3,
    )
    .map_err(|_| ProductionSecretsV4Error::Shape)?;
    let downstream_hsm = decode_hsm_credentials_v3(&mut fields, downstream_count)
        .map_err(|_| ProductionSecretsV4Error::Shape)?;
    if fields.next().is_some() {
        return Err(ProductionSecretsV4Error::Shape);
    }
    let result = ProductionSecretsV4 {
        bearer,
        upstream_relay,
        downstream_relay,
        identity_passphrase,
        dom_wallet_passphrase,
        route_seal,
        refund_credential,
        legs: [upstream, downstream],
        f6_hsm: [upstream_hsm, downstream_hsm],
    };
    let mut keys = vec![
        result.upstream_relay.as_slice(),
        result.downstream_relay.as_slice(),
        result.route_seal.as_slice(),
        result.refund_credential.as_slice(),
        result.bearer.as_slice(),
        result.identity_passphrase.as_slice(),
        result.dom_wallet_passphrase.as_slice(),
    ];
    for credentials in &result.legs {
        keys.extend(credentials.borrow_keys());
    }
    for group in &result.f6_hsm {
        keys.extend(group.iter().map(|key| key.as_slice()));
    }
    if keys
        .iter()
        .enumerate()
        .any(|(index, key)| keys[..index].contains(key))
    {
        return Err(ProductionSecretsV4Error::Reused);
    }
    drop(keys);
    Ok(result)
}

fn field<'a>(
    fields: &mut impl Iterator<Item = &'a [u8]>,
    bound: usize,
) -> Result<Zeroizing<Vec<u8>>, ProductionSecretsV4Error> {
    let value = fields.next().ok_or(ProductionSecretsV4Error::Shape)?;
    require_secret_field(
        value,
        bound,
        ProductionConfigErrorV1::SecretStreamUnavailable,
    )
    .map_err(|_| ProductionSecretsV4Error::Shape)?;
    Ok(Zeroizing::new(value.to_vec()))
}
fn key<'a>(
    fields: &mut impl Iterator<Item = &'a [u8]>,
) -> Result<Zeroizing<[u8; 32]>, ProductionSecretsV4Error> {
    decode_exact_secret_v1(
        fields.next().ok_or(ProductionSecretsV4Error::Shape)?,
        ProductionConfigErrorV1::SecretStreamUnavailable,
        true,
    )
    .map_err(|_| ProductionSecretsV4Error::Shape)
}
fn leg<'a>(
    fields: &mut impl Iterator<Item = &'a [u8]>,
    prefix: &[u8],
) -> Result<ProductionLegCredentialsV4, ProductionSecretsV4Error> {
    let family = fields
        .next()
        .ok_or(ProductionSecretsV4Error::Shape)?
        .strip_prefix(prefix)
        .ok_or(ProductionSecretsV4Error::Shape)?;
    Ok(match family {
        b"BTC" => ProductionLegCredentialsV4::Bitcoin {
            participant: key(fields)?,
        },
        b"EVM" => ProductionLegCredentialsV4::Evm {
            signing: key(fields)?,
        },
        b"SOL" => ProductionLegCredentialsV4::Solana {
            seed: key(fields)?,
            peer_auth: key(fields)?,
        },
        b"XMR" => ProductionLegCredentialsV4::Monero {
            local_store: key(fields)?,
            sidecar_auth: key(fields)?,
        },
        _ => return Err(ProductionSecretsV4Error::Shape),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(up: &str, down: &str) -> Vec<u8> {
        let mut lines = vec![
            "DOM-INTEROPD-SECRETS-V4".to_owned(),
            "node-token".to_owned(),
            "01".repeat(32),
            "02".repeat(32),
            "identity-pass".to_owned(),
            "wallet-pass".to_owned(),
            "03".repeat(32),
            "04".repeat(32),
        ];
        let mut byte = 5u8;
        for (position, family) in [("upstream", up), ("downstream", down)] {
            lines.push(format!("{position}_family={family}"));
            let count = if matches!(family, "XMR" | "SOL") {
                2
            } else {
                1
            };
            for _ in 0..count {
                lines.push(format!("{byte:02x}").repeat(32));
                byte += 1;
            }
        }
        lines.push(String::from_utf8_lossy(UPSTREAM_F6_HSM_COUNT_PREFIX_V3).to_string() + "1");
        lines.push("30".repeat(32));
        lines.push(String::from_utf8_lossy(DOWNSTREAM_F6_HSM_COUNT_PREFIX_V3).to_string() + "1");
        lines.push("31".repeat(32));
        lines.join("\n").into_bytes()
    }

    #[test]
    fn v4_all_sixteen_credential_pairs_are_independent() {
        let families = [
            ("BTC", ProductionChainFamilyV11::Btc),
            ("EVM", ProductionChainFamilyV11::Evm),
            ("SOL", ProductionChainFamilyV11::Sol),
            ("XMR", ProductionChainFamilyV11::Xmr),
        ];
        for (up, up_family) in families {
            for (down, down_family) in families {
                let value =
                    ProductionSecretsV4::read(stream(up, down).as_slice()).expect("strict stream");
                value
                    .require_families([up_family, down_family])
                    .expect("ordered families");
                assert_eq!(
                    value.legs[0].borrow_keys().len(),
                    if matches!(up, "SOL" | "XMR") { 2 } else { 1 }
                );
            }
        }
    }

    #[test]
    fn v4_refuses_swapped_positions_reused_keys_and_additional_chain_fields() {
        let bytes = stream("XMR", "SOL");
        let value = ProductionSecretsV4::read(bytes.as_slice()).expect("stream");
        assert_eq!(
            value.require_families([ProductionChainFamilyV11::Sol, ProductionChainFamilyV11::Xmr]),
            Err(ProductionSecretsV4Error::FamilyMismatch)
        );
        let text = String::from_utf8(bytes).expect("UTF8 fixture");
        for bad in [
            text.clone() + "\n",
            text.clone() + "\n" + &"32".repeat(32),
            text.replace(&"05".repeat(32), &"01".repeat(32)),
            text.replace("upstream_family=XMR", "upstream_family=BTC"),
            text.replace(&"05".repeat(32), &"FF".repeat(32)),
            text.replace(&"05".repeat(32), &"00".repeat(32)),
        ] {
            assert!(ProductionSecretsV4::read(bad.as_bytes()).is_err());
        }
        let oversized = vec![b'x'; MAX_BYTES + 1];
        assert!(matches!(
            ProductionSecretsV4::read(oversized.as_slice()),
            Err(ProductionSecretsV4Error::Stream)
        ));
    }

    #[cfg(feature = "production")]
    #[test]
    fn v11_runtime_handoff_imports_native_common_owners_without_legacy_chain_keys() {
        use ProductionChainFamilyV11::*;
        for (up, down, expected) in [
            ("XMR", "SOL", [Xmr, Sol]),
            ("XMR", "XMR", [Xmr, Xmr]),
            ("SOL", "SOL", [Sol, Sol]),
            ("BTC", "XMR", [Btc, Xmr]),
        ] {
            let bytes = stream(up, down);
            let decoded = ProductionRunSecretsV11::read(bytes.as_slice()).expect("one stream");
            let ProductionRunSecretsV11::UniversalV4(decoded) = decoded else {
                panic!("V4 family");
            };
            let native = decoded.into_parts(expected).expect("native owner import");
            assert_eq!([native.legs[0].family(), native.legs[1].family()], expected);
            assert_eq!(native.dom_wallet_passphrase.as_str(), "wallet-pass");
            assert_eq!([native.f6_hsm[0].len(), native.f6_hsm[1].len()], [1, 1]);
            let mut malformed = bytes;
            malformed.extend_from_slice(b"\n");
            assert!(ProductionRunSecretsV11::read(malformed.as_slice()).is_err());
        }
        let value = ProductionSecretsV4::read(stream("XMR", "SOL").as_slice()).unwrap();
        assert!(matches!(
            value.into_parts([Sol, Xmr]),
            Err(ProductionSecretsV4Error::FamilyMismatch)
        ));
    }
}
