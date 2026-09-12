//! Production plan persistence: one owner retains the authenticated plan
//! authority and the durable funding-time authority. Claim/refund recovery
//! bypasses only the expiring new-funding gate; clock and plan checks remain.

use crate::production_materializer::ProductionAuthenticatedSettlementPlanAuthorityV1;
use crate::production_time_guard::ProductionTimeGuardedPlanPersistenceV2;

pub(crate) type ProductionSettlementPlanPersistenceOwnerV1 =
    ProductionTimeGuardedPlanPersistenceV2<ProductionAuthenticatedSettlementPlanAuthorityV1>;

#[cfg(test)]
mod tests {
    use static_assertions::assert_not_impl_any;

    use super::*;

    assert_not_impl_any!(ProductionSettlementPlanPersistenceOwnerV1: Clone, Copy, Default);
}
