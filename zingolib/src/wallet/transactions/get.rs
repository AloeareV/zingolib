use zcash_note_encryption::Domain;
use zcash_primitives::{consensus::BlockHeight, transaction::TxId};

use crate::wallet::{
    data::{PoolNullifier, TransactionRecord},
    notes::ShieldedNoteInterface,
    traits::{DomainWalletExt, Recipient},
};

use super::TransactionMetadataSet;

impl TransactionMetadataSet {
    pub fn get_notes_for_updating(
        &self,
        before_block: u64,
    ) -> Vec<(TxId, PoolNullifier, Option<u32>)> {
        let before_block = BlockHeight::from_u32(before_block as u32);

        self.current
            .iter()
            .filter(|(_, transaction_metadata)| transaction_metadata.status.is_confirmed_before_or_at(&before_block)) // Update only confirmed notes
            .flat_map(|(txid, transaction_metadata)| {
                // Fetch notes that are before the before_block.
                transaction_metadata
                    .sapling_notes
                    .iter()
                    .filter_map(move |sapling_note_description| {
                        if sapling_note_description.have_spending_key
                            && sapling_note_description.spent.is_none()
                        {
                            Some((
                                *txid,
                                PoolNullifier::Sapling(
                                    sapling_note_description.nullifier.unwrap_or_else(|| {
                                        todo!("Do something about note even with missing nullifier")
                                    }),
                                ),
                                sapling_note_description.output_index
                            ))
                        } else {
                            None
                        }
                    })
                    .chain(transaction_metadata.orchard_notes.iter().filter_map(
                        move |orchard_note_description| {
                            if orchard_note_description.have_spending_key
                                && orchard_note_description.spent.is_none()
                            {
                                Some((
                                    *txid,
                                    PoolNullifier::Orchard(orchard_note_description.nullifier.unwrap_or_else(|| {
                                        todo!("Do something about note even with missing nullifier")
                                    }))
                                    , orchard_note_description.output_index
,                                ))
                            } else {
                                None
                            }
                        },
                    ))
            })
            .collect()
    }

    pub fn total_funds_spent_in(&self, txid: &TxId) -> u64 {
        self.current
            .get(txid)
            .map(TransactionRecord::total_value_spent)
            .unwrap_or(0)
    }

    #[allow(clippy::type_complexity)]
    pub fn get_nullifier_value_txid_outputindex_of_unspent_notes<D: DomainWalletExt>(
        &self,
    ) -> Vec<(
        <<D as DomainWalletExt>::WalletNote as ShieldedNoteInterface>::Nullifier,
        u64,
        TxId,
        Option<u32>,
    )>
    where
        <D as Domain>::Note: PartialEq + Clone,
        <D as Domain>::Recipient: Recipient,
    {
        self.current
            .iter()
            .flat_map(|(_, transaction_metadata)| {
                D::to_notes_vec(transaction_metadata)
                    .iter()
                    .filter(|unspent_note_data| unspent_note_data.spent().is_none())
                    .filter_map(move |unspent_note_data| {
                        unspent_note_data.nullifier().map(|unspent_nullifier| {
                            (
                                unspent_nullifier,
                                unspent_note_data.value(),
                                transaction_metadata.txid,
                                *unspent_note_data.output_index(),
                            )
                        })
                    })
            })
            .collect()
    }

    /// This returns an _arbitrary_ confirmed txid from the latest block the wallet is aware of.
    pub fn get_some_txid_from_highest_wallet_block(&self) -> Option<TxId> {
        self.current
            .values()
            .fold(
                None,
                |highest: Option<(TxId, BlockHeight)>, w: &TransactionRecord| match w
                    .status
                    .get_confirmed_height()
                {
                    None => highest,
                    Some(w_height) => match highest {
                        None => Some((w.txid, w_height)),
                        Some(highest_tuple) => {
                            if highest_tuple.1 > w_height {
                                highest
                            } else {
                                Some((w.txid, w_height))
                            }
                        }
                    },
                },
            )
            .map(|v| v.0)
    }
}

#[test]
fn test_get_some_txid_from_highest_wallet_block() {
    let mut tms = TransactionMetadataSet::new_treeless();
    assert_eq!(tms.get_some_txid_from_highest_wallet_block(), None);
    let txid_bytes_1 = [0u8; 32];
    let txid_bytes_2 = [1u8; 32];
    let txid_bytes_3 = [2u8; 32];
    let txid_1 = TxId::from_bytes(txid_bytes_1);
    let txid_2 = TxId::from_bytes(txid_bytes_2);
    let txid_3 = TxId::from_bytes(txid_bytes_3);
    tms.current.insert(
        txid_1,
        TransactionRecord::new(
            zingo_status::confirmation_status::ConfirmationStatus::Broadcast(
                BlockHeight::from_u32(3_200_000),
            ),
            100,
            &txid_1,
        ),
    );
    tms.current.insert(
        txid_2,
        TransactionRecord::new(
            zingo_status::confirmation_status::ConfirmationStatus::Confirmed(
                BlockHeight::from_u32(3_000_069),
            ),
            0,
            &txid_2,
        ),
    );
    tms.current.insert(
        txid_3,
        TransactionRecord::new(
            zingo_status::confirmation_status::ConfirmationStatus::Confirmed(
                BlockHeight::from_u32(2_650_000),
            ),
            0,
            &txid_3,
        ),
    );
    let highest = tms.get_some_txid_from_highest_wallet_block();
    assert_eq!(highest, Some(txid_2));
}

#[cfg(feature = "lightclient-deprecated")]
impl TransactionMetadataSet {
    pub fn get_fee_by_txid(&self, txid: &TxId) -> u64 {
        match self
            .current
            .get(txid)
            .expect("To have the requested txid")
            .get_transaction_fee()
        {
            Ok(tx_fee) => tx_fee,
            Err(e) => panic!("{:?} for txid {}", e, txid,),
        }
    }
}

#[cfg(test)]
mod unit {
    use std::time::UNIX_EPOCH;

    use proptest::{
        strategy::{Strategy, ValueTree},
        test_runner::TestRunner,
    };
    use rand::Rng;
    use zcash_primitives::sapling::{note_encryption::SaplingDomain, value::NoteValue};
    use zingo_status::confirmation_status::ConfirmationStatus;
    use zingoconfig::ChainType;

    use crate::test_framework::ShieldedNoteBuilder;

    use super::*;

    #[test]
    fn nullifier_value_txid_unspent_notes() {
        let mut determinstic_rng = rand::rngs::mock::StepRng::new(0, u64::MAX - 23);
        let note_value = 70;
        let nullifier =
            zcash_primitives::sapling::Nullifier::from_slice(&determinstic_rng.gen::<[u8; 32]>())
                .unwrap();
        let mut tmds = TransactionMetadataSet::new_treeless();
        let mut first_sapling_note = ShieldedNoteBuilder::new();
        first_sapling_note.nullifier(Some(nullifier));
        let mock_note =
            zcash_primitives::sapling::testing::arb_note(NoteValue::from_raw(note_value))
                .new_tree(&mut TestRunner::deterministic())
                .unwrap()
                .current();
        first_sapling_note.note(mock_note);
        let mock_txid = TxId::from_bytes(determinstic_rng.gen());
        let mut mock_transaction = TransactionRecord::new(
            ConfirmationStatus::Confirmed(BlockHeight::from_u32(5)),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            &mock_txid,
        );
        mock_transaction
            .sapling_notes
            .push(first_sapling_note.build());
        tmds.current.insert(mock_txid, mock_transaction);
        let nvto_vec = tmds
            .get_nullifier_value_txid_outputindex_of_unspent_notes::<SaplingDomain<ChainType>>();
        assert_eq!(nvto_vec.len(), 1);
        let found_note = nvto_vec.first().unwrap();
        assert_eq!(found_note.0, nullifier);
        assert_eq!(found_note.1, note_value);
        assert_eq!(found_note.2, mock_txid);
    }
}
