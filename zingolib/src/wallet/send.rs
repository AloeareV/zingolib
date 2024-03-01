use crate::wallet::data::SpendableSaplingNote;
use crate::wallet::notes::NoteInterface;

use futures::Future;

use log::{error, info};

use orchard::note_encryption::OrchardDomain;

use rand::rngs::OsRng;

use sapling_crypto::note_encryption::SaplingDomain;
use sapling_crypto::prover::{OutputProver, SpendProver};

use shardtree::error::{QueryError, ShardTreeError};

use std::convert::Infallible;
use std::sync::mpsc::channel;

use zcash_client_backend::address;

use zcash_primitives::memo::MemoBytes;
use zcash_primitives::transaction::builder::{BuildResult, Progress};
use zcash_primitives::transaction::components::amount::NonNegativeAmount;
use zcash_primitives::transaction::fees::fixed::FeeRule as FixedFeeRule;
use zcash_primitives::transaction::{self, Transaction};
use zcash_primitives::{
    consensus::BlockHeight,
    legacy::Script,
    memo::Memo,
    transaction::{
        builder::Builder,
        components::{Amount, OutPoint, TxOut},
        fees::zip317::MINIMUM_FEE,
    },
};
use zingo_memo::create_wallet_internal_memo_version_0;
use zingo_status::confirmation_status::ConfirmationStatus;

use super::utils::get_price;
use super::{
    data::{SpendableOrchardNote, WitnessTrees},
    notes, now, LightWallet, NoteSelectionPolicy, Pool, Receivers, TxBuilder,
};
use crate::wallet::traits::SpendableNote;

#[derive(Debug, Clone)]
pub struct SendProgress {
    pub id: u32,
    pub is_send_in_progress: bool,
    pub progress: u32,
    pub total: u32,
    pub last_error: Option<String>,
    pub last_transaction_id: Option<String>,
}

impl LightWallet {
    // Reset the send progress status to blank
    async fn reset_send_progress(&self) {
        let mut g = self.send_progress.write().await;
        let next_id = g.id + 1;

        // Discard the old value, since we are replacing it
        let _ = std::mem::replace(&mut *g, SendProgress::new(next_id));
    }
    // Get the current sending status.
    pub async fn get_send_progress(&self) -> SendProgress {
        self.send_progress.read().await.clone()
    }

    async fn select_notes_and_utxos(
        &self,
        target_amount: Amount,
        policy: &NoteSelectionPolicy,
    ) -> Result<
        (
            Vec<SpendableOrchardNote>,
            Vec<SpendableSaplingNote>,
            Vec<notes::TransparentNote>,
            u64,
        ),
        u64,
    > {
        let mut all_transparent_value_in_wallet = Amount::zero();
        let mut utxos = Vec::new(); //utxo stands for Unspent Transaction Output
        let mut sapling_value_selected = Amount::zero();
        let mut sapling_notes = Vec::new();
        let mut orchard_value_selected = Amount::zero();
        let mut orchard_notes = Vec::new();
        // Correctness of this loop depends on:
        //    * uniqueness
        for pool in policy {
            match pool {
                // Transparent: This opportunistic shielding sweeps all transparent value leaking identifying information to
                // a funder of the wallet's transparent value. We should change this.
                Pool::Transparent => {
                    utxos = self
                        .get_utxos()
                        .await
                        .iter()
                        .filter(|utxo| utxo.unconfirmed_spent.is_none() && !utxo.is_spent())
                        .cloned()
                        .collect::<Vec<_>>();
                    all_transparent_value_in_wallet =
                        utxos.iter().fold(Amount::zero(), |prev, utxo| {
                            (prev + Amount::from_u64(utxo.value).unwrap()).unwrap()
                        });
                }
                Pool::Sapling => {
                    let sapling_candidates = self
                        .get_all_domain_specific_notes::<SaplingDomain>()
                        .await
                        .into_iter()
                        .filter(|note| note.spend_key().is_some())
                        .collect();
                    (sapling_notes, sapling_value_selected) = Self::add_notes_to_total::<
                        SaplingDomain,
                    >(
                        sapling_candidates,
                        (target_amount - orchard_value_selected - all_transparent_value_in_wallet)
                            .unwrap(),
                    );
                }
                Pool::Orchard => {
                    let orchard_candidates = self
                        .get_all_domain_specific_notes::<OrchardDomain>()
                        .await
                        .into_iter()
                        .filter(|note| note.spend_key().is_some())
                        .collect();
                    (orchard_notes, orchard_value_selected) = Self::add_notes_to_total::<
                        OrchardDomain,
                    >(
                        orchard_candidates,
                        (target_amount - all_transparent_value_in_wallet - sapling_value_selected)
                            .unwrap(),
                    );
                }
            }
            // Check how much we've selected
            if (all_transparent_value_in_wallet + sapling_value_selected + orchard_value_selected)
                .unwrap()
                >= target_amount
            {
                return Ok((
                    orchard_notes,
                    sapling_notes,
                    utxos,
                    u64::try_from(
                        (all_transparent_value_in_wallet
                            + sapling_value_selected
                            + orchard_value_selected)
                            .unwrap(),
                    )
                    .expect("u64 representable."),
                ));
            }
        }

        // If we can't select enough, then we need to return empty handed
        Err(u64::try_from(
            (all_transparent_value_in_wallet + sapling_value_selected + orchard_value_selected)
                .unwrap(),
        )
        .expect("u64 representable"))
    }

    async fn create_and_populate_tx_builder(
        &self,
        submission_height: BlockHeight,
        witness_trees: &WitnessTrees,
        start_time: u64,
        receivers: Receivers,
        policy: NoteSelectionPolicy,
    ) -> Result<(TxBuilder<'_>, u32), String> {
        let fee_rule =
            &zcash_primitives::transaction::fees::fixed::FeeRule::non_standard(MINIMUM_FEE); // Start building tx
        let mut total_shielded_receivers;
        let mut orchard_notes;
        let mut sapling_notes;
        let mut utxos;
        let mut tx_builder;
        let mut proposed_fee = MINIMUM_FEE;
        let mut total_value_covered_by_selected;
        let total_earmarked_for_recipients: u64 = receivers.iter().map(|to| u64::from(to.1)).sum();
        info!(
            "0: Creating transaction sending {} zatoshis to {} addresses",
            total_earmarked_for_recipients,
            receivers.len()
        );
        loop {
            tx_builder = match self
                .create_tx_builder(submission_height, witness_trees)
                .await
            {
                Err(ShardTreeError::Query(QueryError::NotContained(addr))) => Err(format!(
                    "could not create anchor, missing address {addr:?}. \
                    If you are fully synced, you may need to rescan to proceed"
                )),
                Err(ShardTreeError::Query(QueryError::CheckpointPruned)) => {
                    let blocks = self.blocks.read().await.len();
                    let offset = self.transaction_context.config.reorg_buffer_offset;
                    Err(format!(
                        "The reorg buffer offset has been set to {} \
                        but there are only {} blocks in the wallet. \
                        Please sync at least {} more blocks before trying again",
                        offset,
                        blocks,
                        offset + 1 - blocks as u32
                    ))
                }
                Err(ShardTreeError::Query(QueryError::TreeIncomplete(addrs))) => Err(format!(
                    "could not create anchor, missing addresses {addrs:?}. \
                    If you are fully synced, you may need to rescan to proceed"
                )),
                Err(ShardTreeError::Insert(_)) => unreachable!(),
                Err(ShardTreeError::Storage(_infallible)) => unreachable!(),
                Ok(v) => Ok(v),
            }?;

            // Select notes to cover the target value
            info!("{}: Adding outputs", now() - start_time);
            (total_shielded_receivers, tx_builder) = self
                .add_consumer_specified_outputs_to_builder(tx_builder, receivers.clone())
                .expect("To add outputs");

            let earmark_total_plus_default_fee =
                total_earmarked_for_recipients + u64::from(proposed_fee);
            // Select notes as a fn of target amount

            let _proposal = (
                orchard_notes,
                sapling_notes,
                utxos,
                total_value_covered_by_selected,
            ) = match self
                .select_notes_and_utxos(
                    Amount::from_u64(earmark_total_plus_default_fee)
                        .expect("Valid amount, from u64."),
                    &policy,
                )
                .await
            {
                Ok(notes) => notes,
                Err(insufficient_amount) => {
                    let e = format!(
                "Insufficient verified shielded funds. Have {} zats, need {} zats. NOTE: funds need at least {} confirmations before they can be spent. Transparent funds must be shielded before they can be spent. If you are trying to spend transparent funds, please use the shield button and try again in a few minutes.",
                insufficient_amount, earmark_total_plus_default_fee, self.transaction_context.config
                .reorg_buffer_offset + 1
            );
                    error!("{}", e);
                    return Err(e);
                }
            };

            info!("Selected notes worth {}", total_value_covered_by_selected);

            info!(
                "{}: Adding {} sapling notes, {} orchard notes, and {} utxos",
                now() - start_time,
                &sapling_notes.len(),
                &orchard_notes.len(),
                &utxos.len()
            );

            let temp_tx_builder = match self.add_change_output_to_builder(
                tx_builder,
                Amount::from_u64(earmark_total_plus_default_fee).expect("valid value of u64"),
                Amount::from_u64(total_value_covered_by_selected).unwrap(),
                &mut total_shielded_receivers,
                &receivers,
            ) {
                Ok(txb) => txb,
                Err(r) => {
                    return Err(r);
                }
            };
            info!("{}: selecting notes", now() - start_time);
            tx_builder = match self
                .add_spends_to_builder(
                    temp_tx_builder,
                    witness_trees,
                    &orchard_notes,
                    &sapling_notes,
                    &utxos,
                )
                .await
            {
                Ok(tx_builder) => tx_builder,

                Err(s) => {
                    return Err(s);
                }
            };
            proposed_fee = tx_builder.get_fee(fee_rule).unwrap();
            if u64::from(proposed_fee) + total_earmarked_for_recipients
                <= total_value_covered_by_selected
            {
                break;
            }
        }
        Ok((tx_builder, total_shielded_receivers))
    }

    pub async fn send_to_addresses<F, Fut, P: SpendProver + OutputProver>(
        &self,
        sapling_prover: P,
        policy: NoteSelectionPolicy,
        receivers: Receivers,
        submission_height: BlockHeight,
        broadcast_fn: F,
    ) -> Result<(String, Vec<u8>), String>
    where
        F: Fn(Box<[u8]>) -> Fut,
        Fut: Future<Output = Result<String, String>>,
    {
        // Reset the progress to start. Any errors will get recorded here
        self.reset_send_progress().await;

        // Sanity check that this is a spending wallet.  Why isn't this done earlier?
        if !self.wallet_capability().can_spend_from_all_pools() {
            // Creating transactions in context of all possible combinations
            // of wallet capabilities requires a rigorous case study
            // and can have undesired effects if not implemented properly.
            //
            // Thus we forbid spending for wallets without complete spending capability for now
            return Err("Wallet is in watch-only mode and thus it cannot spend.".to_string());
        }
        // Create the transaction
        let start_time = now();
        let build_result = self
            .create_publication_ready_transaction(
                submission_height,
                start_time,
                receivers,
                policy,
                sapling_prover,
            )
            .await?;

        // Call the internal function
        match self
            .send_to_addresses_inner(build_result.transaction(), submission_height, broadcast_fn)
            .await
        {
            Ok((transaction_id, raw_transaction)) => {
                self.set_send_success(transaction_id.clone()).await;
                Ok((transaction_id, raw_transaction))
            }
            Err(e) => {
                self.set_send_error(e.to_string()).await;
                Err(e)
            }
        }
    }

    async fn create_tx_builder(
        &self,
        submission_height: BlockHeight,
        witness_trees: &WitnessTrees,
    ) -> Result<TxBuilder, ShardTreeError<Infallible>> {
        let orchard_anchor = self
            .get_orchard_anchor(&witness_trees.witness_tree_orchard)
            .await?;
        let sapling_anchor = self
            .get_sapling_anchor(&witness_trees.witness_tree_sapling)
            .await?;
        Ok(Builder::new(
            self.transaction_context.config.chain,
            submission_height,
            transaction::builder::BuildConfig::Standard {
                // TODO: We probably need this
                sapling_anchor: Some(sapling_anchor),
                orchard_anchor: Some(orchard_anchor),
            },
        ))
    }

    async fn add_spends_to_builder<'a>(
        &'a self,
        mut tx_builder: TxBuilder<'a>,
        witness_trees: &WitnessTrees,
        orchard_notes: &[SpendableOrchardNote],
        sapling_notes: &[SpendableSaplingNote],
        utxos: &[notes::TransparentNote],
    ) -> Result<TxBuilder<'_>, String> {
        // Add all tinputs
        // Create a map from address -> sk for all taddrs, so we can spend from the
        // right address
        let address_to_sk = self
            .wallet_capability()
            .get_taddr_to_secretkey_map(&self.transaction_context.config)
            .unwrap();

        utxos
            .iter()
            .map(|utxo| {
                let outpoint: OutPoint = utxo.to_outpoint();

                let coin = TxOut {
                    value: NonNegativeAmount::from_u64(utxo.value).unwrap(),
                    script_pubkey: Script(utxo.script.clone()),
                };

                match address_to_sk.get(&utxo.address) {
                    Some(sk) => tx_builder
                        .add_transparent_input(*sk, outpoint, coin)
                        .map_err(|e| {
                            transaction::builder::Error::<Infallible>::TransparentBuild(e)
                        }),
                    None => {
                        // Something is very wrong
                        let e = format!("Couldn't find the secretkey for taddr {}", utxo.address);
                        error!("{}", e);

                        Err(transaction::builder::Error::<Infallible>::TransparentBuild(
                            transaction::components::transparent::builder::Error::InvalidAddress,
                        ))
                    }
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{:?}", e))?;

        for selected in sapling_notes.iter() {
            info!("Adding sapling spend");
            // Turbofish only needed for error type
            if let Err(e) = tx_builder.add_sapling_spend::<FixedFeeRule>(
                &selected.extsk.clone().unwrap(),
                selected.note.clone(),
                witness_trees
                    .witness_tree_sapling
                    .witness_at_checkpoint_depth(
                        selected.witnessed_position,
                        self.transaction_context.config.reorg_buffer_offset as usize,
                    )
                    .map_err(|e| format!("failed to compute sapling witness: {e}"))?,
            ) {
                let e = format!("Error adding note: {:?}", e);
                error!("{}", e);
                return Err(e);
            }
        }

        for selected in orchard_notes.iter() {
            info!("Adding orchard spend");
            if let Err(e) = tx_builder.add_orchard_spend::<transaction::fees::fixed::FeeRule>(
                &selected.spend_key.unwrap(),
                selected.note,
                orchard::tree::MerklePath::from(
                    witness_trees
                        .witness_tree_orchard
                        .witness_at_checkpoint_depth(
                            selected.witnessed_position,
                            self.transaction_context.config.reorg_buffer_offset as usize,
                        )
                        .map_err(|e| format!("failed to compute orchard witness: {e}"))?,
                ),
            ) {
                let e = format!("Error adding note: {:?}", e);
                error!("{}", e);
                return Err(e);
            }
        }
        Ok(tx_builder)
    }
    fn add_consumer_specified_outputs_to_builder<'a>(
        &'a self,
        mut tx_builder: TxBuilder<'a>,
        receivers: Receivers,
    ) -> Result<(u32, TxBuilder<'_>), String> {
        // Convert address (str) to RecipientAddress and value to Amount

        // We'll use the first ovk to encrypt outgoing transactions
        let sapling_ovk =
            sapling_crypto::keys::OutgoingViewingKey::try_from(&*self.wallet_capability()).unwrap();
        let orchard_ovk =
            orchard::keys::OutgoingViewingKey::try_from(&*self.wallet_capability()).unwrap();

        let mut total_shielded_receivers = 0u32;
        for (recipient_address, value, memo) in receivers {
            // Compute memo if it exists
            let validated_memo = match memo {
                None => MemoBytes::from(Memo::Empty),
                Some(s) => s,
            };

            if let Err(e) = match recipient_address {
                address::Address::Transparent(to) => tx_builder
                    .add_transparent_output(&to, value)
                    .map_err(transaction::builder::Error::TransparentBuild),
                address::Address::Sapling(to) => {
                    total_shielded_receivers += 1;
                    tx_builder.add_sapling_output(Some(sapling_ovk), to, value, validated_memo)
                }
                address::Address::Unified(ua) => {
                    if let Some(orchard_addr) = ua.orchard() {
                        total_shielded_receivers += 1;
                        tx_builder.add_orchard_output::<FixedFeeRule>(
                            Some(orchard_ovk.clone()),
                            *orchard_addr,
                            u64::from(value),
                            validated_memo,
                        )
                    } else if let Some(sapling_addr) = ua.sapling() {
                        total_shielded_receivers += 1;
                        tx_builder.add_sapling_output(
                            Some(sapling_ovk),
                            *sapling_addr,
                            value,
                            validated_memo,
                        )
                    } else {
                        return Err("Received UA with no Orchard or Sapling receiver".to_string());
                    }
                }
            } {
                let e = format!("Error adding output: {:?}", e);
                error!("{}", e);
                return Err(e);
            }
        }
        Ok((total_shielded_receivers, tx_builder))
    }

    fn add_change_output_to_builder<'a>(
        &self,
        mut tx_builder: TxBuilder<'a>,
        target_amount: Amount,
        selected_value: Amount,
        total_shielded_receivers: &mut u32,
        receivers: &Receivers,
    ) -> Result<TxBuilder<'a>, String> {
        let destination_uas = receivers
            .iter()
            .filter_map(|receiver| match receiver.0 {
                address::Address::Sapling(_) => None,
                address::Address::Transparent(_) => None,
                address::Address::Unified(ref ua) => Some(ua.clone()),
            })
            .collect::<Vec<_>>();
        let uas_bytes = match create_wallet_internal_memo_version_0(destination_uas.as_slice()) {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!(
                    "Could not write uas to memo field: {e}\n\
        Your wallet will display an incorrect sent-to address. This is a visual error only.\n\
        The correct address was sent to."
                );
                [0; 511]
            }
        };
        let orchard_ovk =
            orchard::keys::OutgoingViewingKey::try_from(&*self.wallet_capability()).unwrap();
        *total_shielded_receivers += 1;
        if let Err(e) = tx_builder.add_orchard_output::<FixedFeeRule>(
            Some(orchard_ovk.clone()),
            *self.wallet_capability().addresses()[0].orchard().unwrap(),
            u64::try_from(selected_value).expect("u64 representable")
                - u64::try_from(target_amount).expect("u64 representable"),
            // Here we store the uas we sent to in the memo field.
            // These are used to recover the full UA we sent to.
            MemoBytes::from(Memo::Arbitrary(Box::new(uas_bytes))),
        ) {
            let e = format!("Error adding change output: {:?}", e);
            error!("{}", e);
            return Err(e);
        };
        Ok(tx_builder)
    }

    async fn create_publication_ready_transaction<P: SpendProver + OutputProver>(
        &self,
        submission_height: BlockHeight,
        start_time: u64,
        receivers: Receivers,
        policy: NoteSelectionPolicy,
        sapling_prover: P,
        // We only care about the transaction...but it can now only be aquired by reference
        // from the build result, so we need to return the whole thing
    ) -> Result<BuildResult, String> {
        // Start building transaction with spends and outputs set by:
        //  * target amount
        //  * selection policy
        //  * recipient list
        let txmds_readlock = self.transaction_context.arc_ledger.read().await;
        let witness_trees = txmds_readlock
            .witness_trees
            .as_ref()
            .expect("If we have spend capability we have trees");
        let (tx_builder, total_shielded_receivers) = match self
            .create_and_populate_tx_builder(
                submission_height,
                witness_trees,
                start_time,
                receivers,
                policy,
            )
            .await
        {
            Ok(tx_builder) => tx_builder,
            Err(s) => {
                return Err(s);
            }
        };

        drop(txmds_readlock);
        // The builder now has the correct set of inputs and outputs

        // Set up a channel to receive updates on the progress of building the transaction.
        // This progress monitor, the channel monitoring it, and the types necessary for its
        // construction are unnecessary for sending.
        let (transmitter, receiver) = channel::<Progress>();
        let progress = self.send_progress.clone();

        // Use a separate thread to handle sending from std::mpsc to tokio::sync::mpsc
        let (transmitter2, mut receiver2) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || {
            while let Ok(r) = receiver.recv() {
                transmitter2.send(r.cur()).unwrap();
            }
        });

        let progress_handle = tokio::spawn(async move {
            while let Some(r) = receiver2.recv().await {
                info!("{}: Progress: {r}", now() - start_time);
                progress.write().await.progress = r;
            }

            progress.write().await.is_send_in_progress = false;
        });

        {
            let mut p = self.send_progress.write().await;
            p.is_send_in_progress = true;
            p.progress = 0;
            p.total = total_shielded_receivers;
        }

        info!("{}: Building transaction", now() - start_time);

        let tx_builder = tx_builder.with_progress_notifier(transmitter);
        let build_result = match tx_builder.build(
            OsRng,
            &sapling_prover,
            &sapling_prover,
            &transaction::fees::fixed::FeeRule::non_standard(MINIMUM_FEE),
        ) {
            Ok(res) => res,
            Err(e) => {
                let e = format!("Error creating transaction: {:?}", e);
                error!("{}", e);
                self.send_progress.write().await.is_send_in_progress = false;
                return Err(e);
            }
        };
        progress_handle.await.unwrap();
        Ok(build_result)
    }
    async fn send_to_addresses_inner<F, Fut>(
        &self,
        transaction: &Transaction,
        submission_height: BlockHeight,
        broadcast_fn: F,
    ) -> Result<(String, Vec<u8>), String>
    where
        F: Fn(Box<[u8]>) -> Fut,
        Fut: Future<Output = Result<String, String>>,
    {
        {
            self.send_progress.write().await.is_send_in_progress = false;
        }

        // Create the transaction bytes
        let mut raw_transaction = vec![];
        transaction.write(&mut raw_transaction).unwrap();

        let transaction_id = broadcast_fn(raw_transaction.clone().into_boxed_slice()).await?;

        // Add this transaction to the mempool structure
        {
            let price = self.price.read().await.clone();

            let status = ConfirmationStatus::Broadcast(submission_height);
            self.transaction_context
                .scan_full_tx(transaction, status, now() as u32, get_price(now(), &price))
                .await;
        }

        Ok((transaction_id, raw_transaction))
    }
}