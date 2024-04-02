use std::iter::repeat;

use zcash_client_backend::{data_api::InputSource, wallet::WalletTransparentOutput};
use zcash_primitives::{
    consensus::BlockHeight,
    legacy::TransparentAddress,
    transaction::components::{amount::NonNegativeAmount, OutPoint, TxOut},
};

use crate::{
    error::ZingoLibError,
    wallet::{
        keys::address_from_pubkeyhash, notes::NoteInterface, record_book::NoteRecordIdentifier,
    },
};

use super::SpendKit;

impl InputSource for SpendKit<'_, '_> {
    type Error = ZingoLibError;
    type AccountId = zcash_primitives::zip32::AccountId;
    type NoteRef = NoteRecordIdentifier;

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
        self.record_book.get_spendable_note(txid, protocol, index)
    }

    fn select_spendable_notes(
        &self,
        account: Self::AccountId,
        target_value: zcash_primitives::transaction::components::amount::NonNegativeAmount,
        sources: &[zcash_client_backend::ShieldedProtocol],
        anchor_height: zcash_primitives::consensus::BlockHeight,
        exclude: &[Self::NoteRef],
    ) -> Result<
        Vec<
            zcash_client_backend::wallet::ReceivedNote<
                Self::NoteRef,
                zcash_client_backend::wallet::Note,
            >,
        >,
        Self::Error,
    > {
        self.record_book.select_spendable_notes(
            account,
            target_value,
            sources,
            anchor_height,
            exclude,
        )
    }
    fn get_unspent_transparent_outputs(
        &self,
        address: &TransparentAddress,
        max_height: BlockHeight,
        exclude: &[OutPoint],
    ) -> Result<Vec<WalletTransparentOutput>, Self::Error> {
        self.spend_cap
            .get_all_taddrs(&self.params)
            .iter()
            .find_map(|wallet_addr| {
                if &address_from_pubkeyhash(&self.params, *address) == wallet_addr {
                    Some(
                        self.record_book
                            .get_remote_txid_hashmap()
                            .values()
                            .into_iter()
                            .flat_map(|transaction| {
                                transaction
                                    .transparent_notes
                                    .iter()
                                    .filter(|utxo| {
                                        !utxo.is_spent_or_pending_spent()
                                            && !exclude.contains(&utxo.to_outpoint())
                                    })
                                    .zip(repeat(transaction.status.get_confirmed_height()))
                            })
                            .filter_map(|(utxo, height)| {
                                height.map(|h| {
                                    WalletTransparentOutput::from_parts(
                                        utxo.to_outpoint(),
                                        TxOut {
                                            value: NonNegativeAmount::from_u64(utxo.value).unwrap(), //review!
                                            script_pubkey: zcash_primitives::legacy::Script(
                                                utxo.script.clone(),
                                            ),
                                        },
                                        h,
                                    )
                                })
                            })
                            .collect::<Vec<_>>(),
                    )
                } else {
                    None
                }
            })
            .ok_or_else(|| ZingoLibError::Error("can't find taddr in wallet".to_string()))
    }
}
