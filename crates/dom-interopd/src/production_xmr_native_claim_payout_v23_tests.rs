//! Deterministic OFFLINE payout wallet: spend=83, view=89 (little endian).
//! These fixture-owned test keys are unrelated to T/U and are never production
//! credentials. The payout is fixed before terms/C-D/setup; funding stays at
//! the independently verified combined-spend address.
use super::*;

pub(super) struct NativeClaimPayoutV23 {
    spend: xmr_crypto::XmrSpendShare,
    view: Zeroizing<[u8; 32]>,
    address: String,
    pub(super) max_fee: u64,
    refund_spend: xmr_crypto::XmrSpendShare,
    refund_view: Zeroizing<[u8; 32]>,
    refund_address: String,
}
impl NativeClaimPayoutV23 {
    pub(super) fn new(max_fee: u64) -> Result<Self> {
        Self::new_for_position_v23(max_fee, 0)
    }
    pub(super) fn new_for_position_v23(max_fee: u64, position: usize) -> Result<Self> {
        Self::new_for_network_v23(max_fee, position, xmr_setup_profile::XmrNetwork::Stagenet)
    }
    pub(super) fn new_for_network_v23(
        max_fee: u64,
        position: usize,
        network: xmr_setup_profile::XmrNetwork,
    ) -> Result<Self> {
        let tag = match network {
            xmr_setup_profile::XmrNetwork::Mainnet => 1,
            xmr_setup_profile::XmrNetwork::Stagenet => 3,
            _ => return Err("unsupported payout fixture network".into()),
        };
        if position > 1 {
            return Err("payout fixture position".into());
        }
        let offset = 32 * u8::try_from(position)?;
        if max_fee == 0 {
            return Err("payout requires frozen fee cap".into());
        }
        let mut spend = [0; 32];
        spend[0] = 83 + offset;
        let spend = xmr_crypto::XmrSpendShare::from_canonical_bytes(spend)?;
        let mut view = Zeroizing::new([0; 32]);
        view[0] = 89 + offset;
        let address =
            xmr_raw_tx_verify::standard_funding_address_v12(tag, spend.public_share()?, &view)?;
        // Independent offline refund recipient, frozen at the same boundary.
        let mut refund_spend = [0; 32];
        refund_spend[0] = 97 + offset;
        let refund_spend = xmr_crypto::XmrSpendShare::from_canonical_bytes(refund_spend)?;
        let mut refund_view = Zeroizing::new([0; 32]);
        refund_view[0] = 101 + offset;
        let refund_address = xmr_raw_tx_verify::standard_funding_address_v12(
            tag,
            refund_spend.public_share()?,
            &refund_view,
        )?;
        Ok(Self {
            refund_spend,
            refund_view,
            refund_address,
            spend,
            view,
            address,
            max_fee,
        })
    }
    pub(super) fn refund_address(&self) -> &str {
        &self.refund_address
    }
    pub(super) fn verify_refund_payment(
        &self,
        raw: &[u8],
        hash: [u8; 32],
        amount: u64,
    ) -> Result<()> {
        xmr_raw_tx_verify::verify_exact_raw_funding_v12(
            raw,
            hash,
            self.refund_spend.public_share()?,
            &self.refund_view,
            amount,
            self.max_fee,
        )?;
        Ok(())
    }
    pub(super) fn address(&self) -> &str {
        &self.address
    }
    pub(super) fn verify_payment(&self, raw: &[u8], hash: [u8; 32], amount: u64) -> Result<()> {
        xmr_raw_tx_verify::verify_exact_raw_funding_v12(
            raw,
            hash,
            self.spend.public_share()?,
            &self.view,
            amount,
            self.max_fee,
        )?;
        Ok(())
    }
}
