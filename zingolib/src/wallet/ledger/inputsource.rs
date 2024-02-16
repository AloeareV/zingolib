use zcash_client_backend::data_api::InputSource;

use crate::error::ZingoLibError;

use super::ZingoLedger;

impl InputSource for ZingoLedger {
    type Error = ZingoLibError;

    type NoteRef = ();

    fn get_unspent_transparent_output(
        &self,
        _outpoint: &zcash_primitives::transaction::components::OutPoint,
    ) -> Result<Option<zcash_client_backend::wallet::WalletTransparentOutput>, Self::Error> {
        Ok(None)
    }

    fn get_unspent_transparent_outputs(
        &self,
        _address: &zcash_primitives::legacy::TransparentAddress,
        _max_height: zcash_primitives::consensus::BlockHeight,
        _exclude: &[zcash_primitives::transaction::components::OutPoint],
    ) -> Result<Vec<zcash_client_backend::wallet::WalletTransparentOutput>, Self::Error> {
        Ok(vec![])
    }

    fn get_spendable_note(
        &self,
        _txid: &zcash_primitives::transaction::TxId,
        _protocol: zcash_client_backend::ShieldedProtocol,
        _index: u32,
    ) -> Result<
        Option<
            zcash_client_backend::wallet::ReceivedNote<
                Self::NoteRef,
                zcash_client_backend::wallet::Note,
            >,
        >,
        Self::Error,
    > {
        todo!()
    }

    fn select_spendable_notes(
        &self,
        _account: zcash_primitives::zip32::AccountId,
        _target_value: zcash_primitives::transaction::components::Amount,
        _sources: &[zcash_client_backend::ShieldedProtocol],
        _anchor_height: zcash_primitives::consensus::BlockHeight,
        _exclude: &[Self::NoteRef],
    ) -> Result<
        Vec<
            zcash_client_backend::wallet::ReceivedNote<
                Self::NoteRef,
                zcash_client_backend::wallet::Note,
            >,
        >,
        Self::Error,
    > {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    // #[test]
    // fn
}
