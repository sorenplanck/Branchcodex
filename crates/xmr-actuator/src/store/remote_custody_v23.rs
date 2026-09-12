//! Atomic ancestry marker for independently verified remote sweep imports.
//! These are public commitments, not a proof verifier or broadcast grant.
use super::*;

const MAGIC: &[u8; 8] = b"XMRCUS23";
const DOMAIN: &[u8] = b"DOM-INTEROP/XMR-ACTUATOR/REMOTE-CUSTODY/V23\0";
const LENGTH: usize = 329;

/// Exact wire and authenticated DSC1 ancestry retained with the raw sweep.
/// Construction validates shape only; callers must obtain these commitments
/// from the complete Store/Monero verification boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XmrRemoteCustodyDigestsV23 {
    request_wire: Digest32,
    response_wire: Digest32,
    request_message: Digest32,
    response_message: Digest32,
}
impl XmrRemoteCustodyDigestsV23 {
    /// Validate four nonzero commitments; this does not authenticate a peer.
    pub fn new(
        request_wire: Digest32,
        response_wire: Digest32,
        request_message: Digest32,
        response_message: Digest32,
    ) -> Result<Self> {
        if [
            request_wire,
            response_wire,
            request_message,
            response_message,
        ]
        .contains(&[0; 32])
            || request_message == response_message
        {
            return Err(XmrActuatorErrorV1::InvalidInput);
        }
        Ok(Self {
            request_wire,
            response_wire,
            request_message,
            response_message,
        })
    }
    /// Canonical request payload commitment.
    pub const fn request_wire_digest(&self) -> Digest32 {
        self.request_wire
    }
    /// Canonical response payload commitment.
    pub const fn response_wire_digest(&self) -> Digest32 {
        self.response_wire
    }
    /// Authenticated DSC1 request message commitment.
    pub const fn request_message_digest(&self) -> Digest32 {
        self.request_message
    }
    /// Authenticated DSC1 response message commitment.
    pub const fn response_message_digest(&self) -> Digest32 {
        self.response_message
    }
}

fn table_exists(connection: &Connection) -> Result<bool> {
    connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='xmr_remote_custody_v23')", [], |row| row.get(0))
        .map_err(|_| XmrActuatorErrorV1::Corrupt)
}

fn encode(
    locator: XmrOperationLocatorV1,
    network: Digest32,
    tx_hash: Digest32,
    key_image: Digest32,
    raw_digest: Digest32,
    digests: XmrRemoteCustodyDigestsV23,
) -> Result<Vec<u8>> {
    XmrRemoteCustodyDigestsV23::new(
        digests.request_wire,
        digests.response_wire,
        digests.request_message,
        digests.response_message,
    )?;
    let mut out = MAGIC.to_vec();
    out.push(locator.kind.tag());
    for part in [
        locator.settlement_id,
        network,
        tx_hash,
        key_image,
        raw_digest,
        digests.request_wire,
        digests.response_wire,
        digests.request_message,
        digests.response_message,
    ] {
        if part == [0; 32] {
            return Err(XmrActuatorErrorV1::Corrupt);
        }
        out.extend_from_slice(&part);
    }
    let checksum = digest_parts(DOMAIN, &[&out])?;
    out.extend_from_slice(&checksum);
    Ok(out)
}

pub(super) fn read(
    connection: &Connection,
    locator: XmrOperationLocatorV1,
    network: Digest32,
    tx_hash: Digest32,
    key_image: Digest32,
    raw_digest: Digest32,
) -> Result<Option<XmrRemoteCustodyDigestsV23>> {
    // Existing legacy stores remain readable without silently migrating them.
    if !table_exists(connection)? {
        return Ok(None);
    }
    let bytes: Option<Vec<u8>> = connection
        .query_row(
            "SELECT marker FROM xmr_remote_custody_v23 WHERE settlement_id=?1 AND kind=?2",
            params![
                locator.settlement_id.as_slice(),
                i64::from(locator.kind.tag())
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| XmrActuatorErrorV1::Corrupt)?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    if bytes.len() != LENGTH {
        return Err(XmrActuatorErrorV1::Corrupt);
    }
    let word = |offset: usize| -> Result<Digest32> {
        bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| XmrActuatorErrorV1::Corrupt)
    };
    let digests = XmrRemoteCustodyDigestsV23::new(word(169)?, word(201)?, word(233)?, word(265)?)
        .map_err(|_| XmrActuatorErrorV1::Corrupt)?;
    if encode(locator, network, tx_hash, key_image, raw_digest, digests)? != bytes {
        return Err(XmrActuatorErrorV1::Corrupt);
    }
    Ok(Some(digests))
}

pub(super) fn insert(
    connection: &Connection,
    locator: XmrOperationLocatorV1,
    network: Digest32,
    tx_hash: Digest32,
    key_image: Digest32,
    raw_digest: Digest32,
    digests: XmrRemoteCustodyDigestsV23,
) -> Result<()> {
    let bytes = encode(locator, network, tx_hash, key_image, raw_digest, digests)?;
    connection
        .execute(
            "INSERT INTO xmr_remote_custody_v23(settlement_id,kind,marker) VALUES(?1,?2,?3)",
            params![
                locator.settlement_id.as_slice(),
                i64::from(locator.kind.tag()),
                bytes
            ],
        )
        .map_err(|_| XmrActuatorErrorV1::Corrupt)?;
    Ok(())
}

impl XmrOperationStoreV1 {
    /// Retain raw bytes and remote ancestry in one transaction. Existing local
    /// rows cannot be upgraded, and existing remote rows require exact replay.
    /// A legacy database lacking the V23 table is not migrated here: the
    /// insertion fails closed and rolls back the raw row in the same transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_signed_remote_v23(
        &self,
        lease: &XmrActuatorLeaseV1,
        locator: XmrOperationLocatorV1,
        tx_hash: Digest32,
        key_image: Digest32,
        raw_transaction: &[u8],
        digests: XmrRemoteCustodyDigestsV23,
        now_unix_ms: u64,
    ) -> Result<XmrOperationViewV1> {
        self.prepare_signed_scoped_v23(
            lease,
            locator,
            tx_hash,
            key_image,
            raw_transaction,
            Some(digests),
            now_unix_ms,
        )
    }

    /// Read-only, fenced requirement for a remote path. Missing markers are
    /// corruption, never permission to downgrade or reimport without ancestry.
    pub fn require_remote_custody_v23(
        &self,
        lease: &XmrActuatorLeaseV1,
        locator: XmrOperationLocatorV1,
        now_unix_ms: u64,
    ) -> Result<XmrRemoteCustodyDigestsV23> {
        if now_unix_ms == 0 || !lease.is_live_at(now_unix_ms) {
            return Err(XmrActuatorErrorV1::LeaseExpired);
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        self.require_mutation_owner_v12(&transaction, lease.fencing_epoch)?;
        let row = read_row(&transaction, locator)?.ok_or(XmrActuatorErrorV1::NotFound)?;
        if row.network_id != lease.network_id || lease.fencing_epoch < row.view.fencing_epoch {
            return Err(XmrActuatorErrorV1::Conflict);
        }
        let digests = read(
            &transaction,
            locator,
            row.network_id,
            row.view.tx_hash,
            row.view.key_image,
            row.custody_digest,
        )?
        .ok_or(XmrActuatorErrorV1::Corrupt)?;
        transaction
            .commit()
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        Ok(digests)
    }
}
