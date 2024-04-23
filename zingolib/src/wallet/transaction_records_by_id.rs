//! The lookup for transaction id indexed data.  Currently this provides the
//! transaction record.

use std::collections::HashMap;

use orchard::note_encryption::OrchardDomain;
use sapling_crypto::note_encryption::SaplingDomain;
use zcash_note_encryption::Domain;
use zcash_primitives::consensus::BlockHeight;
use zcash_primitives::transaction::TxId;

use crate::wallet::{
    notes::{interface::ShieldedNoteInterface, OutputInterface, ShNoteId},
    traits::{DomainWalletExt, Recipient},
    transaction_record::TransactionRecord,
};

/// A convenience wrapper, to impl behavior on.
#[derive(Debug)]
pub struct TransactionRecordsById(pub HashMap<TxId, TransactionRecord>);

impl std::ops::Deref for TransactionRecordsById {
    type Target = HashMap<TxId, TransactionRecord>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for TransactionRecordsById {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Constructors
impl TransactionRecordsById {
    /// Constructs a new TransactionRecordsById with an empty map.
    pub fn new() -> Self {
        TransactionRecordsById(HashMap::new())
    }
    /// Constructs a TransactionRecordsById from a HashMap
    pub fn from_map(map: HashMap<TxId, TransactionRecord>) -> Self {
        TransactionRecordsById(map)
    }
}

pub mod trait_inputsource {
    use orchard::note_encryption::OrchardDomain;
    use sapling_crypto::note_encryption::SaplingDomain;
    use zcash_client_backend::data_api::{InputSource, SpendableNotes};
    use zcash_client_backend::wallet::{ReceivedNote, WalletTransparentOutput};
    use zcash_client_backend::ShieldedProtocol;
    use zcash_primitives::legacy::Script;
    use zcash_primitives::transaction::components::amount::NonNegativeAmount;
    use zcash_primitives::transaction::components::TxOut;
    use zip32::AccountId;

    use crate::{
        error::{ZingoLibError, ZingoLibResult},
        wallet::notes::ShNoteId,
    };

    use super::TransactionRecordsById;

    impl InputSource for TransactionRecordsById {
        type Error = ZingoLibError;
        type AccountId = zcash_primitives::zip32::AccountId;
        type NoteRef = ShNoteId;

        /// Fetches a spendable note by indexing into a transaction's shielded outputs for the
        /// specified shielded protocol.
        ///
        /// Returns `Ok(None)` if the note is not known to belong to the wallet or if the note
        /// is not spendable.
        fn get_spendable_note(
            &self,
            txid: &zcash_primitives::transaction::TxId,
            protocol: zcash_client_backend::ShieldedProtocol,
            index: u32,
        ) -> Result<
            Option<
                zcash_client_backend::wallet::ReceivedNote<
                    Self::NoteRef,
                    zcash_client_backend::wallet::Note,
                >,
            >,
            Self::Error,
        > {
            let note_record_reference: <Self as InputSource>::NoteRef = ShNoteId {
                txid: *txid,
                shpool: protocol,
                index,
            };
            match protocol {
                ShieldedProtocol::Sapling => Ok(self
                    .get_received_note_from_identifier::<SaplingDomain>(note_record_reference)
                    .map(|note| {
                        note.map_note(|note_inner| {
                            zcash_client_backend::wallet::Note::Sapling(note_inner)
                        })
                    })),
                ShieldedProtocol::Orchard => Ok(self
                    .get_received_note_from_identifier::<OrchardDomain>(note_record_reference)
                    .map(|note| {
                        note.map_note(|note_inner| {
                            zcash_client_backend::wallet::Note::Orchard(note_inner)
                        })
                    })),
            }
        }

        fn select_spendable_notes(
            &self,
            account: Self::AccountId,
            target_value: zcash_primitives::transaction::components::amount::NonNegativeAmount,
            sources: &[zcash_client_backend::ShieldedProtocol],
            anchor_height: zcash_primitives::consensus::BlockHeight,
            exclude: &[Self::NoteRef],
        ) -> Result<SpendableNotes<ShNoteId>, ZingoLibError> {
            if account != AccountId::ZERO {
                return Err(ZingoLibError::Error(
                    "we don't use non-zero accounts (yet?)".to_string(),
                ));
            }
            let mut sapling_note_noteref_pairs: Vec<(sapling_crypto::Note, ShNoteId)> = Vec::new();
            let mut orchard_note_noteref_pairs: Vec<(orchard::Note, ShNoteId)> = Vec::new();
            for transaction_record in self.values().filter(|transaction_record| {
                transaction_record
                    .status
                    .is_confirmed_before_or_at(&anchor_height)
            }) {
                if sources.contains(&ShieldedProtocol::Sapling) {
                    sapling_note_noteref_pairs.extend(
                        transaction_record
                            .select_unspent_shnotes_and_ids::<SaplingDomain>()
                            .into_iter()
                            .filter(|note_ref_pair| !exclude.contains(&note_ref_pair.1)),
                    );
                }
                if sources.contains(&ShieldedProtocol::Orchard) {
                    orchard_note_noteref_pairs.extend(
                        transaction_record
                            .select_unspent_shnotes_and_ids::<OrchardDomain>()
                            .into_iter()
                            .filter(|note_ref_pair| !exclude.contains(&note_ref_pair.1)),
                    );
                }
            }
            let mut sapling_notes = Vec::<ReceivedNote<ShNoteId, sapling_crypto::Note>>::new();
            let mut orchard_notes = Vec::<ReceivedNote<ShNoteId, orchard::Note>>::new();
            if let Some(missing_value_after_sapling) = sapling_note_noteref_pairs.into_iter().rev(/*biggest first*/).try_fold(
            Some(target_value),
            |rolling_target, (note, noteref)| match rolling_target {
                Some(targ) => {
                    sapling_notes.push(
                        self.get(&noteref.txid).and_then(|tr| tr.get_received_note::<SaplingDomain>(noteref.index))
                            .ok_or_else(|| ZingoLibError::Error("missing note".to_string()))?
                    );
                    Ok(targ
                        - NonNegativeAmount::from_u64(note.value().inner())
                            .map_err(|e| ZingoLibError::Error(e.to_string()))?)
                }
                None => Ok(None),
            },
        )? {
                if let Some(missing_value_after_orchard) = orchard_note_noteref_pairs.into_iter().rev(/*biggest first*/).try_fold(
            Some(missing_value_after_sapling),
            |rolling_target, (note, noteref)| match rolling_target {
                Some(targ) => {
                    orchard_notes.push(
                        self.get(&noteref.txid).and_then(|tr| tr.get_received_note::<OrchardDomain>(noteref.index))
                            .ok_or_else(|| ZingoLibError::Error("missing note".to_string()))?
                    );
                    Ok(targ
                        - NonNegativeAmount::from_u64(note.value().inner())
                            .map_err(|e| ZingoLibError::Error(e.to_string()))?)
                }
                None => Ok(None),
            },
        )? {
                    return ZingoLibResult::Err(ZingoLibError::Error(format!(
                        "insufficient funds, short {}",
                        missing_value_after_orchard.into_u64()
                    )));
                };
            };

            Ok(SpendableNotes::new(sapling_notes, orchard_notes))
        }

        fn get_unspent_transparent_output(
            &self,
            outpoint: &zcash_primitives::transaction::components::OutPoint,
        ) -> Result<Option<zcash_client_backend::wallet::WalletTransparentOutput>, Self::Error>
        {
            let Some((height, tnote)) = self.values().find_map(|transaction_record| {
                transaction_record
                    .transparent_outputs
                    .iter()
                    .find_map(|output| {
                        if &output.to_outpoint() == outpoint {
                            transaction_record
                                .status
                                .get_confirmed_height()
                                .map(|height| (height, output))
                        } else {
                            None
                        }
                    })
            }) else {
                return Ok(None);
            };
            let value = NonNegativeAmount::from_u64(tnote.value)
                .map_err(|e| ZingoLibError::Error(e.to_string()))?;

            let script_pubkey = Script::read(tnote.script.as_slice())
                .map_err(|e| ZingoLibError::Error(e.to_string()))?;

            Ok(WalletTransparentOutput::from_parts(
                outpoint.clone(),
                TxOut {
                    value,
                    script_pubkey,
                },
                height,
            ))
        }
        fn get_unspent_transparent_outputs(
            &self,
            // I don't understand what this argument is for. Is the Trait's intent to only shield
            // utxos from one address at a time? Is this needed?
            _address: &zcash_primitives::legacy::TransparentAddress,
            max_height: zcash_primitives::consensus::BlockHeight,
            exclude: &[zcash_primitives::transaction::components::OutPoint],
        ) -> Result<Vec<zcash_client_backend::wallet::WalletTransparentOutput>, Self::Error>
        {
            self.values()
                .filter_map(|transaction_record| {
                    transaction_record
                        .status
                        .get_confirmed_height()
                        .map(|height| (transaction_record, height))
                        .filter(|(_, height)| height <= &max_height)
                })
                .flat_map(|(transaction_record, confirmed_height)| {
                    transaction_record
                        .transparent_outputs
                        .iter()
                        .filter(|output| {
                            exclude
                                .iter()
                                .any(|excluded| excluded == &output.to_outpoint())
                        })
                        .filter_map(move |output| {
                            let value = match NonNegativeAmount::from_u64(output.value)
                                .map_err(|e| ZingoLibError::Error(e.to_string()))
                            {
                                Ok(v) => v,
                                Err(e) => return Some(Err(e)),
                            };

                            let script_pubkey = match Script::read(output.script.as_slice())
                                .map_err(|e| ZingoLibError::Error(e.to_string()))
                            {
                                Ok(v) => v,
                                Err(e) => return Some(Err(e)),
                            };
                            Ok(WalletTransparentOutput::from_parts(
                                output.to_outpoint(),
                                TxOut {
                                    value,
                                    script_pubkey,
                                },
                                confirmed_height,
                            ))
                            .transpose()
                        })
                })
                .collect()
        }
    }
}

/// Methods to query and modify the map.
impl TransactionRecordsById {
    pub fn get_received_note_from_identifier<D: DomainWalletExt>(
        &self,
        note_record_reference: ShNoteId,
    ) -> Option<
        zcash_client_backend::wallet::ReceivedNote<
            ShNoteId,
            <D as zcash_note_encryption::Domain>::Note,
        >,
    >
    where
        <D as zcash_note_encryption::Domain>::Note: PartialEq + Clone,
        <D as zcash_note_encryption::Domain>::Recipient: super::traits::Recipient,
    {
        let transaction = self.get(&note_record_reference.txid);
        transaction.and_then(|transaction_record| {
            if note_record_reference.shpool == D::SHIELDED_PROTOCOL {
                transaction_record.get_received_note::<D>(note_record_reference.index)
            } else {
                None
            }
        })
    }
    /// Adds a TransactionRecord to the hashmap, using its TxId as a key.
    pub fn insert_transaction_record(&mut self, transaction_record: TransactionRecord) {
        self.insert(transaction_record.txid, transaction_record);
    }
    /// Invalidates all transactions from a given height including the block with block height `reorg_height`
    ///
    /// All information above a certain height is invalidated during a reorg.
    pub fn invalidate_all_transactions_after_or_at_height(&mut self, reorg_height: BlockHeight) {
        // First, collect txids that need to be removed
        let txids_to_remove = self
            .values()
            .filter_map(|transaction_metadata| {
                if transaction_metadata
                    .status
                    .is_confirmed_after_or_at(&reorg_height)
                    || transaction_metadata
                        .status
                        .is_broadcast_after_or_at(&reorg_height)
                // tODo: why dont we only remove confirmed transactions. unconfirmed transactions may still be valid in the mempool and may later confirm or expire.
                {
                    Some(transaction_metadata.txid)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        self.invalidate_transactions(txids_to_remove);
    }
    /// Invalidiates a vec of txids by removing them and then all references to them.
    ///
    /// A transaction can be invalidated either by a reorg or if it was never confirmed by a miner.
    /// This is required in the case that a note was spent in a invalidated transaction.
    /// Takes a slice of txids corresponding to the invalidated transactions, searches all notes for being spent in one of those txids, and resets them to unspent.
    pub(crate) fn invalidate_transactions(&mut self, txids_to_remove: Vec<TxId>) {
        for txid in &txids_to_remove {
            self.remove(txid);
        }

        self.invalidate_transaction_specific_transparent_spends(&txids_to_remove);
        // roll back any sapling spends in each invalidated tx
        self.invalidate_transaction_specific_domain_spends::<SaplingDomain>(&txids_to_remove);
        // roll back any orchard spends in each invalidated tx
        self.invalidate_transaction_specific_domain_spends::<OrchardDomain>(&txids_to_remove);
    }
    /// Reverts any spent transparent notes in the given transactions to unspent.
    pub(crate) fn invalidate_transaction_specific_transparent_spends(
        &mut self,
        invalidated_txids: &[TxId],
    ) {
        self.values_mut().for_each(|transaction_metadata| {
            // Update UTXOs to roll back any spent utxos
            transaction_metadata
                .transparent_outputs
                .iter_mut()
                .for_each(|utxo| {
                    if utxo.is_spent() && invalidated_txids.contains(&utxo.spent().unwrap().0) {
                        *utxo.spent_mut() = None;
                    }

                    if utxo.unconfirmed_spent.is_some()
                        && invalidated_txids.contains(&utxo.unconfirmed_spent.unwrap().0)
                    {
                        utxo.unconfirmed_spent = None;
                    }
                })
        });
    }
    /// Reverts any spent shielded notes in the given transactions to unspent.
    pub(crate) fn invalidate_transaction_specific_domain_spends<D: DomainWalletExt>(
        &mut self,
        invalidated_txids: &[TxId],
    ) where
        <D as Domain>::Recipient: Recipient,
        <D as Domain>::Note: PartialEq + Clone,
    {
        self.values_mut().for_each(|transaction_metadata| {
            // Update notes to rollback any spent notes
            D::to_notes_vec_mut(transaction_metadata)
                .iter_mut()
                .for_each(|nd| {
                    // Mark note as unspent if the txid being removed spent it.
                    if nd.spent().is_some() && invalidated_txids.contains(&nd.spent().unwrap().0) {
                        *nd.spent_mut() = None;
                    }

                    // Remove unconfirmed spends too
                    if nd.pending_spent().is_some()
                        && invalidated_txids.contains(&nd.pending_spent().unwrap().0)
                    {
                        *nd.pending_spent_mut() = None;
                    }
                });
        });
    }
}

/// This impl was extracted from:
/// [`crate::wallet::transactions::recording::TxMapAndMaybeTrees`]
impl crate::wallet::transaction_records_by_id::TransactionRecordsById {
    /// Invalidates all those transactions which were broadcast but never 'confirmed' accepted by a miner.
    pub(crate) fn clear_expired_mempool(&mut self, latest_height: u64) {
        let cutoff = BlockHeight::from_u32(
            (latest_height.saturating_sub(zingoconfig::MAX_REORG as u64)) as u32,
        );

        let txids_to_remove = self
            .iter()
            .filter(|(_, transaction_metadata)| {
                transaction_metadata.status.is_broadcast_before(&cutoff)
            }) // this transaction was submitted to the mempool before the cutoff and has not been confirmed. we deduce that it has expired.
            .map(|(_, transaction_metadata)| transaction_metadata.txid)
            .collect::<Vec<_>>();

        txids_to_remove
            .iter()
            .for_each(|t| println!("Removing expired mempool tx {}", t));

        self.invalidate_transactions(txids_to_remove);
    }
    pub fn total_funds_spent_in(&self, txid: &TxId) -> u64 {
        self.get(txid)
            .map(TransactionRecord::total_value_spent)
            .unwrap_or(0)
    }
    // Check this transaction to see if it is an outgoing transaction, and if it is, mark all received notes with non-textual memos in this
    // transaction as change. i.e., If any funds were spent in this transaction, all received notes without user-specified memos are change.
    //
    // TODO: When we start working on multi-sig, this could cause issues about hiding sends-to-self
    pub fn check_notes_mark_change(&mut self, txid: &TxId) {
        //TODO: Incorrect with a 0-value fee somehow
        if self.total_funds_spent_in(txid) > 0 {
            if let Some(transaction_metadata) = self.get_mut(txid) {
                Self::mark_notes_as_change_for_pool(&mut transaction_metadata.sapling_notes);
                Self::mark_notes_as_change_for_pool(&mut transaction_metadata.orchard_notes);
            }
        }
    }
    fn mark_notes_as_change_for_pool<Note: crate::wallet::notes::ShieldedNoteInterface>(
        notes: &mut [Note],
    ) {
        notes.iter_mut().for_each(|n| {
            *n.is_change_mut() = match n.memo() {
                Some(zcash_primitives::memo::Memo::Text(_)) => false,
                Some(
                    zcash_primitives::memo::Memo::Empty
                    | zcash_primitives::memo::Memo::Arbitrary(_)
                    | zcash_primitives::memo::Memo::Future(_),
                )
                | None => true,
            }
        });
    }
    pub(crate) fn create_modify_get_transaction_metadata(
        &mut self,
        txid: &TxId,
        status: zingo_status::confirmation_status::ConfirmationStatus,
        datetime: u64,
    ) -> &'_ mut TransactionRecord {
        self.entry(*txid)
            // if we already have the transaction metadata, it may be newly confirmed. update confirmation_status
            .and_modify(|transaction_metadata| {
                transaction_metadata.status = status;
                transaction_metadata.datetime = datetime;
            })
            // if this transaction is new to our data, insert it
            .or_insert_with(|| TransactionRecord::new(status, datetime, txid))
    }

    pub fn add_taddr_spent(
        &mut self,
        txid: TxId,
        status: zingo_status::confirmation_status::ConfirmationStatus,
        timestamp: u64,
        total_transparent_value_spent: u64,
    ) {
        let transaction_metadata =
            self.create_modify_get_transaction_metadata(&txid, status, timestamp);

        transaction_metadata.total_transparent_value_spent = total_transparent_value_spent;

        self.check_notes_mark_change(&txid);
    }

    pub fn mark_txid_utxo_spent(
        &mut self,
        spent_txid: TxId,
        output_num: u32,
        source_txid: TxId,
        spending_tx_status: zingo_status::confirmation_status::ConfirmationStatus,
    ) -> u64 {
        // Find the UTXO
        let value = if let Some(utxo_transacion_metadata) = self.get_mut(&spent_txid) {
            if let Some(spent_utxo) = utxo_transacion_metadata
                .transparent_outputs
                .iter_mut()
                .find(|u| u.txid == spent_txid && u.output_index == output_num as u64)
            {
                if spending_tx_status.is_confirmed() {
                    // Mark this utxo as spent
                    *spent_utxo.spent_mut() =
                        Some((source_txid, spending_tx_status.get_height().into()));
                    spent_utxo.unconfirmed_spent = None;
                } else {
                    spent_utxo.unconfirmed_spent =
                        Some((source_txid, u32::from(spending_tx_status.get_height())));
                }

                spent_utxo.value
            } else {
                log::error!("Couldn't find UTXO that was spent");
                0
            }
        } else {
            log::error!("Couldn't find TxID that was spent!");
            0
        };

        // Return the value of the note that was spent.
        value
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_new_taddr_output(
        &mut self,
        txid: TxId,
        taddr: String,
        status: zingo_status::confirmation_status::ConfirmationStatus,
        timestamp: u64,
        vout: &zcash_primitives::transaction::components::TxOut,
        output_num: u32,
    ) {
        // Read or create the current TxId
        let transaction_metadata =
            self.create_modify_get_transaction_metadata(&txid, status, timestamp);

        // Add this UTXO if it doesn't already exist
        if transaction_metadata
            .transparent_outputs
            .iter_mut()
            .any(|utxo| utxo.txid == txid && utxo.output_index == output_num as u64)
        {
            // If it already exists, it is likely an mempool tx, so update the height
        } else {
            transaction_metadata.transparent_outputs.push(
                crate::wallet::notes::TransparentOutput::from_parts(
                    taddr,
                    txid,
                    output_num as u64,
                    vout.script_pubkey.0.clone(),
                    u64::from(vout.value),
                    None,
                    None,
                ),
            );
        }
    }
    /// witness tree requirement:
    ///
    pub(crate) fn add_pending_note<D>(
        &mut self,
        txid: TxId,
        height: BlockHeight,
        timestamp: u64,
        note: D::Note,
        to: D::Recipient,
        output_index: usize,
    ) where
        D: DomainWalletExt,
        D::Note: PartialEq + Clone,
        D::Recipient: Recipient,
    {
        let status = zingo_status::confirmation_status::ConfirmationStatus::Broadcast(height);
        let transaction_metadata =
            self.create_modify_get_transaction_metadata(&txid, status, timestamp);

        match D::to_notes_vec_mut(transaction_metadata)
            .iter_mut()
            .find(|n| n.note() == &note)
        {
            None => {
                let nd = D::WalletNote::from_parts(
                    to.diversifier(),
                    note,
                    None,
                    None,
                    None,
                    None,
                    None,
                    // if this is change, we'll mark it later in check_notes_mark_change
                    false,
                    false,
                    Some(output_index as u32),
                );

                D::WalletNote::transaction_metadata_notes_mut(transaction_metadata).push(nd);
            }
            Some(_) => {}
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_new_note<D: DomainWalletExt>(
        &mut self,
        txid: TxId,
        status: zingo_status::confirmation_status::ConfirmationStatus,
        timestamp: u64,
        note: <D::WalletNote as crate::wallet::notes::ShieldedNoteInterface>::Note,
        to: D::Recipient,
        have_spending_key: bool,
        nullifier: Option<
            <D::WalletNote as crate::wallet::notes::ShieldedNoteInterface>::Nullifier,
        >,
        output_index: u32,
        position: incrementalmerkletree::Position,
    ) where
        D::Note: PartialEq + Clone,
        D::Recipient: Recipient,
    {
        let transaction_metadata =
            self.create_modify_get_transaction_metadata(&txid, status, timestamp);

        let nd = D::WalletNote::from_parts(
            D::Recipient::diversifier(&to),
            note.clone(),
            Some(position),
            nullifier,
            None,
            None,
            None,
            // if this is change, we'll mark it later in check_notes_mark_change
            false,
            have_spending_key,
            Some(output_index),
        );
        match D::WalletNote::transaction_metadata_notes_mut(transaction_metadata)
            .iter_mut()
            .find(|n| n.note() == &note)
        {
            None => {
                D::WalletNote::transaction_metadata_notes_mut(transaction_metadata).push(nd);

                D::WalletNote::transaction_metadata_notes_mut(transaction_metadata)
                    .retain(|n| n.nullifier().is_some());
            }
            #[allow(unused_mut)]
            Some(mut n) => {
                // An overwrite should be safe here: TODO: test that confirms this
                *n = nd;
            }
        }
    }

    // Update the memo for a note if it already exists. If the note doesn't exist, then nothing happens.
    pub(crate) fn add_memo_to_note_metadata<Nd: crate::wallet::notes::ShieldedNoteInterface>(
        &mut self,
        txid: &TxId,
        note: Nd::Note,
        memo: zcash_primitives::memo::Memo,
    ) {
        if let Some(transaction_metadata) = self.get_mut(txid) {
            if let Some(n) = Nd::transaction_metadata_notes_mut(transaction_metadata)
                .iter_mut()
                .find(|n| n.note() == &note)
            {
                *n.memo_mut() = Some(memo);
            }
        }
    }

    pub fn add_outgoing_metadata(
        &mut self,
        txid: &TxId,
        outgoing_metadata: Vec<crate::wallet::data::OutgoingTxData>,
    ) {
        // println!("        adding outgoing metadata to txid {}", txid);
        if let Some(transaction_metadata) = self.get_mut(txid) {
            transaction_metadata.outgoing_tx_data = outgoing_metadata
        } else {
            log::error!(
                "TxId {} should be present while adding metadata, but wasn't",
                txid
            );
        }
    }

    pub fn set_price(&mut self, txid: &TxId, price: Option<f64>) {
        price.map(|p| self.get_mut(txid).map(|tx| tx.price = Some(p)));
    }
}
impl Default for TransactionRecordsById {
    /// Default constructor
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet::{
        notes::{
            sapling::mocks::SaplingNoteBuilder, transparent::mocks::TransparentOutputBuilder,
            ShNoteId,
        },
        transaction_record::mocks::TransactionRecordBuilder,
    };

    use super::TransactionRecordsById;

    use zcash_client_backend::{
        data_api::{InputSource, SpendableNotes},
        ShieldedProtocol,
    };
    use zcash_primitives::{
        consensus::BlockHeight, legacy::TransparentAddress,
        transaction::components::amount::NonNegativeAmount,
    };
    use zingo_status::confirmation_status::ConfirmationStatus::Confirmed;
    use zip32::AccountId;

    #[test]
    fn invalidated_note_is_deleted() {
        let mut transaction_record_early = TransactionRecordBuilder::default()
            .randomize_txid()
            .status(Confirmed(5.into()))
            .build();
        transaction_record_early
            .transparent_outputs
            .push(TransparentOutputBuilder::default().build());

        let mut transaction_record_later = TransactionRecordBuilder::default()
            .randomize_txid()
            .status(Confirmed(15.into()))
            .build();
        transaction_record_later
            .sapling_notes
            .push(SaplingNoteBuilder::default().build());

        let mut transaction_records_by_id = TransactionRecordsById::default();
        transaction_records_by_id.insert_transaction_record(transaction_record_early);
        transaction_records_by_id.insert_transaction_record(transaction_record_later);

        let reorg_height: BlockHeight = 10.into();

        transaction_records_by_id.invalidate_all_transactions_after_or_at_height(reorg_height);

        assert_eq!(transaction_records_by_id.len(), 1);
    }
    #[test]
    fn sapling_note_is_selected() {
        // WIP
        let mut transaction_record = TransactionRecordBuilder::default().build();
        transaction_record
            .sapling_notes
            .push(SaplingNoteBuilder::default().build());

        let mut transaction_records_by_id = TransactionRecordsById::new();
        transaction_records_by_id.insert(transaction_record.txid, transaction_record);

        let target_value = NonNegativeAmount::const_from_u64(20000);
        let anchor_height: BlockHeight = 10.into();
        let spendable_notes: SpendableNotes<ShNoteId> =
            zcash_client_backend::data_api::InputSource::select_spendable_notes(
                &transaction_records_by_id,
                AccountId::ZERO,
                target_value,
                &[ShieldedProtocol::Sapling, ShieldedProtocol::Orchard],
                anchor_height,
                &[],
            )
            .unwrap();
        assert_eq!(
            spendable_notes
                .sapling()
                .first()
                .unwrap()
                .note()
                .value()
                .inner(),
            // Default mock sapling note value
            1_000_000
        )
    }

    #[test]
    fn select_transparent_outputs() {
        let mut transaction_record = TransactionRecordBuilder::default().build();
        let transparent_output = TransparentOutputBuilder::default().build();
        transaction_record
            .transparent_outputs
            .push(transparent_output);
        let mut transaction_records_by_id = TransactionRecordsById::new();
        transaction_records_by_id.insert_transaction_record(transaction_record);

        let selected_outputs = transaction_records_by_id
            .get_unspent_transparent_outputs(
                &TransparentAddress::ScriptHash([0; 20]),
                BlockHeight::from_u32(10),
                &[],
            )
            .unwrap();
        dbg!(selected_outputs);
    }
}
