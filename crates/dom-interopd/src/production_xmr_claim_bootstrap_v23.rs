//! Native Claim startup from the already admitted bounded XMR graph.
//! No legacy M.8 grant, second secret owner, or fabricated child funding id.
use super::*;

impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    pub(crate) fn step_native_xmr_claim_v23(
        &mut self,
        material: &mut crate::production_dom_shared_bootstrap_v12::ProductionBoundDomSharedOutputV12,
        binding: DomSessionBindingV1,
        chain: TrustedChainIdV1,
        scanner: Rc<ProductionDomF7ScannerAuthorityV1>,
        observer: &mut Option<ProductionSelectedF7ObserverV12>,
        provisioner: &crate::production_dom_vaults_v12::ProductionXmrGraphVaultProvisionerV23,
        now: u64,
    ) -> Result<(), ProductionF7RuntimeErrorV12> {
        use ProductionF7RuntimeErrorV12 as Error;
        self.validate_dom_binding(binding)
            .map_err(|_| Error::Scope)?;
        if chain.as_bytes() != &binding.chain_id() {
            return Err(Error::Scope);
        }
        let head = self.store.load_session(binding.session_id()).map_err(|e| {
            eprintln!("DOM_REFUSAL_ORIGIN_V26 site=claim_bootstrap line=22 err={e:?}");
            e
        })?;
        if head.irreversible().adaptor_secret_exposed
            || matches!(
                head.phase(),
                dom_scriptless_store::SessionPhaseV1::RefundBroadcast
                    | dom_scriptless_store::SessionPhaseV1::Refunded
                    | dom_scriptless_store::SessionPhaseV1::FailedClosed
            )
        {
            return Ok(());
        }
        if let Some(facts) = self.store.f7_claim_verification_facts_v15(
            chain,
            binding.session_id(),
            self.local_participant,
        )? {
            // Some(facts) authenticates the accepted 0x0f (or its retained
            // observation/exposure), not merely six signing messages. The
            // receiver now needs the final-Claim scanner, which accepts C spent
            // by that exact Claim. Requiring C unspent here would strand it on
            // restart, or race the sender's publication before pump.completed.
            if facts.receiver_id() == self.local_participant {
                return Ok(());
            }
            // Not being this observation's receiver does not make the local
            // opening the claim sender: the frozen sender is named by the
            // gate role, and `f7_final_claim_progress_v14` refuses anyone
            // else with `InvalidTransition`. Round 93 died exactly there --
            // the refusal is not in `retryable_v20`, so a legitimate
            // non-sender opening killed the route. `f7_claim_receiver_state_v25`
            // is the query written for this decision; its own documentation
            // says to select receiver handling before a sender-only
            // publication. No check is dropped: a non-sender simply does not
            // ask a sender-only question, and continues exactly as a sender
            // whose claim still needs adaptation does.
            let local_is_claim_sender = match self
                .store
                .retained_f7_funding_gate_v19(chain, binding.session_id())?
            {
                Some(gate) => match self.store.f7_claim_receiver_state_v25(
                    &gate,
                    chain,
                    self.local_participant,
                ) {
                    Ok(state) => {
                        matches!(state, dom_scriptless_store::F7ClaimReceiverStateV25::Sender)
                    }
                    // The query answers Sender, AwaitingObservation or Observed,
                    // and refuses with InvalidTransition for an opening that is
                    // neither the frozen claim sender nor the frozen final-claim
                    // receiver of this leg. That refusal is the answer to the only
                    // question asked here -- "am I the sender?" -- and is not a
                    // broken route: nothing was authorized, signed or staged.
                    // Round 96 died propagating it as fatal. Every other refusal
                    // (Quarantined, a Store failure, any other variant) still
                    // propagates unchanged.
                    Err(dom_scriptless_store::SessionStoreError::InvalidTransition) => {
                        eprintln!(
                            "DOM_REFUSAL_ORIGIN_V26 site=claim_bootstrap.receiver_state refusal=not_sender"
                        );
                        false
                    }
                    Err(error) => return Err(error.into()),
                },
                None => false,
            };
            if local_is_claim_sender
                && self
                    .store
                    .f7_final_claim_progress_v14(chain, binding.session_id())?
                    != dom_scriptless_store::F7FinalClaimProgressV14::NeedsAdaptation
            {
                return Ok(());
            }
        }
        let shared = Rc::clone(&self.claim_owner_v21);
        let mut owner = shared.try_borrow_mut().map_err(|_| Error::Scope)?;
        if owner.native_xmr_start_failed_v23 {
            return Err(Error::RequiresRestart(None));
        }
        if owner.pump.is_none() {
            // Pending funding keeps observation and private resources in place.
            let Some(selected) = observer.as_mut() else {
                return Ok(());
            };
            if !matches!(&selected.selected, SelectedObserverV12::Monero(inputs)
                if matches!(&inputs.graph, ProductionXmrF7GraphV23::Native(_)))
            {
                return Err(Error::Scope);
            }
            let gate = self
                .store
                .resume_f7_funding_gate_v12(chain, self.session_id)
                .map_err(|e| {
                    eprintln!("DOM_REFUSAL_ORIGIN_V26 site=claim_bootstrap line=114 err={e:?}");
                    e
                })?;
            let request = self
                .store
                .f7_anchor_request_binding_v12(&gate, chain)
                .map_err(|e| {
                    eprintln!("DOM_REFUSAL_ORIGIN_V26 site=claim_bootstrap line=115 err={e:?}");
                    e
                })?;
            let anchors = match selected.observe(scanner.as_ref(), &request)? {
                ProductionF7ObservationV12::Verified(value) => value,
                ProductionF7ObservationV12::FundingAbsent
                | ProductionF7ObservationV12::AwaitingFinality
                | ProductionF7ObservationV12::TemporarilyUnavailable => return Ok(()),
            };
            if material.funding_signer_v20.is_some()
                || material.refund_signer_v18.is_some()
                || material.xmr_graph_shares_v22.is_none()
                || owner.m8.is_some()
            {
                return Err(Error::Scope);
            }
            let authorization = self
                .store
                .consume_f7_claim_authorization_v12(&gate, anchors)
                .map_err(|e| {
                    eprintln!("DOM_REFUSAL_ORIGIN_V26 site=claim_bootstrap line=131 err={e:?}");
                    e
                })?;
            self.store
                .bind_retained_f7_claim_signing_session_v12(&authorization, chain)
                .map_err(|e| {
                    eprintln!("DOM_REFUSAL_ORIGIN_V26 site=claim_bootstrap line=133 err={e:?}");
                    e
                })?;
            if material.claim_vault_v23.is_none() {
                material.claim_vault_v23 = Some(
                    provisioner
                        .provision_claim_v23(&self.store, binding, chain)
                        .map_err(|_| Error::Custody)?,
                );
            }
            // First-time physical vault provisioning may outlive the external
            // anchor's recency window. Reobserve through the concrete scanner
            // only when the consumed authority actually aged out.
            if !authorization.can_reuse_observation_v12() {
                let fresh_anchors = match selected.observe(scanner.as_ref(), &request)? {
                    ProductionF7ObservationV12::Verified(value) => value,
                    ProductionF7ObservationV12::FundingAbsent
                    | ProductionF7ObservationV12::AwaitingFinality
                    | ProductionF7ObservationV12::TemporarilyUnavailable => return Ok(()),
                };
                self.store
                    .revalidate_consumed_f7_claim_authorization_v12(&authorization, fresh_anchors)
                    .map_err(|e| {
                        eprintln!("DOM_REFUSAL_ORIGIN_V26 site=claim_bootstrap line=154 err={e:?}");
                        e
                    })?;
            }
            // From this point any failure requires authenticated reopen. Do not
            // recreate a share or silently retry with a partially moved owner.
            owner.native_xmr_start_failed_v23 = true;
            let share = material
                .xmr_graph_shares_v22
                .as_mut()
                .ok_or(Error::Consumed)?
                .take_claim_share_v23(&self.store, &authorization)
                .map_err(|_| Error::RequiresRestart(None))?;
            let vault = material
                .claim_vault_v23
                .take()
                .ok_or(Error::RequiresRestart(None))
                .map_err(|e| {
                    eprintln!("DOM_REFUSAL_ORIGIN_V26 site=claim_bootstrap line=168 err={e:?}");
                    e
                })?;
            let claim = self
                .start_dom_claim_runtime_consumed_v23(binding, chain, vault, share, authorization)
                .map_err(|error| Error::RequiresRestart(Some(error)))?;
            owner.pump = Some(ProductionF7RuntimeV12 {
                store: Rc::clone(&self.store),
                binding,
                chain,
                gate,
                scanner,
                observer: observer.take().ok_or(Error::RequiresRestart(None))?,
                initial_signer: None,
                claim: Some(claim),
                completion: None,
                completed: false,
                restart_required: false,
            });
            owner.native_xmr_start_failed_v23 = false;
            return Ok(());
        }
        let pump = owner.pump.as_mut().ok_or(Error::Consumed).map_err(|e| {
            eprintln!("DOM_REFUSAL_ORIGIN_V26 site=claim_bootstrap line=188 err={e:?}");
            e
        })?;
        if !matches!(&pump.observer.selected, SelectedObserverV12::Monero(inputs)
            if matches!(&inputs.graph, ProductionXmrF7GraphV23::Native(_)))
        {
            return Err(Error::Scope);
        }
        let expiry = TimelockSpec::TimestampSeconds {
            value: now
                .checked_add(3600)
                .filter(|_| now != 0)
                .ok_or(Error::Scope)?,
        };
        // The pump recollects both anchors before each private operation and
        // the existing child exposure path checks them again before revealing T.
        let _progress = pump.step(self, expiry).map_err(|e| {
            eprintln!("DOM_REFUSAL_ORIGIN_V26 site=claim_bootstrap line=202 err={e:?}");
            e
        })?;
        Ok(())
    }
}
