use crate::{error::ZingoLibError, utils::address_from_str, wallet::Pool};

use super::*;

impl LightClient {
    /// TODO: Add Doc Comment Here!
    pub async fn new_client_from_save_buffer(&self) -> Result<Self, ZingoLibError> {
        self.save_internal_buffer().await?;

        LightClient::read_wallet_from_buffer_async(
            &self.config,
            self.save_buffer.buffer.read().await.as_slice(),
        )
        .await
        .map_err(ZingoLibError::CantReadWallet)
    }

    /// Test only lightclient method for calling `do_send` with primitive rust types
    ///
    /// # Panics
    ///
    /// Panics if the address, amount or memo conversion fails.
    /// ignores secondary
    pub async fn do_send_test_only(
        &self,
        address_amount_memo_tuples: Vec<(&str, u64, Option<&str>)>,
    ) -> Result<String, String> {
        self.do_quick_send(
            self.raw_to_transaction_request(
                address_amount_memo_tuples
                    .into_iter()
                    .map(|(address, amount, memo)| {
                        (
                            address.to_string(),
                            amount as u32,
                            memo.map(|memo| memo.to_string()),
                        )
                    })
                    .collect(),
            )
            .unwrap(),
        )
        .await
        .map(|txid| txid.first().to_string())
    }

    /// Test only lightclient method for calling `do_shield` with an address as &str
    ///
    /// # Panics
    ///
    /// Panics if the address conversion fails.
    #[cfg(feature = "test-features")]
    pub async fn do_shield_test_only(
        &self,
        pools_to_shield: &[Pool],
        address: Option<&str>,
    ) -> Result<String, String> {
        let address = address.map(|addr| {
            address_from_str(addr, &self.config().chain).expect("should be a valid address")
        });
        self.do_shield(pools_to_shield, address)
            .await
            .map(|txid| txid.to_string())
    }
}
