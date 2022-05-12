use crate::utxo::rpc_clients::{UnspentInfo, UtxoRpcClientEnum, UtxoRpcClientOps, UtxoRpcError, UtxoRpcFut,
                               UtxoRpcResult};
use crate::utxo::utxo_builder::{UtxoCoinBuilderCommonOps, UtxoCoinWithIguanaPrivKeyBuilder,
                                UtxoFieldsWithIguanaPrivKeyBuilder};
use crate::utxo::utxo_common::{big_decimal_from_sat_unsigned, payment_script};
use crate::utxo::{sat_from_big_decimal, utxo_common, ActualTxFee, AdditionalTxData, Address, BroadcastTxErr,
                  FeePolicy, HistoryUtxoTx, HistoryUtxoTxMap, RecentlySpentOutPoints, UtxoActivationParams,
                  UtxoAddressFormat, UtxoArc, UtxoCoinFields, UtxoCommonOps, UtxoFeeDetails, UtxoTxBroadcastOps,
                  UtxoTxGenerationOps, UtxoWeak, VerboseTransactionFrom};
use crate::{BalanceFut, CoinBalance, FeeApproxStage, FoundSwapTxSpend, HistorySyncState, MarketCoinOps, MmCoin,
            NegotiateSwapContractAddrErr, NumConversError, RawTransactionFut, RawTransactionRequest, SwapOps,
            TradeFee, TradePreimageFut, TradePreimageResult, TradePreimageValue, TransactionDetails, TransactionEnum,
            TransactionFut, TxFeeDetails, UnexpectedDerivationMethod, ValidateAddressResult, ValidatePaymentInput,
            WithdrawFut, WithdrawRequest};
use crate::{Transaction, WithdrawError};
use async_trait::async_trait;
use bitcrypto::dhash160;
use chain::constants::SEQUENCE_FINAL;
use chain::{Transaction as UtxoTx, TransactionOutput};
use common::executor::{spawn, Timer};
use common::mm_ctx::MmArc;
use common::mm_error::prelude::*;
use common::mm_number::{BigDecimal, MmNumber};
use common::privkey::key_pair_from_secret;
use common::{log, now_ms};
use db_common::sqlite::rusqlite::types::Type;
use db_common::sqlite::rusqlite::{Connection, Error as SqliteError, Row, ToSql, NO_PARAMS};
use futures::compat::Future01CompatExt;
use futures::lock::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use futures::{FutureExt, TryFutureExt};
use futures01::Future;
use keys::hash::H256;
use keys::{KeyPair, Public};
use primitives::bytes::Bytes;
use rpc::v1::types::{Bytes as BytesJson, ToTxHash, Transaction as RpcTransaction, H256 as H256Json};
use script::{Builder as ScriptBuilder, Opcode, Script, TransactionInputSigner};
use serde_json::Value as Json;
use serialization::{deserialize, serialize_list, CoinVariant, Reader};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use zcash_client_backend::decrypt_transaction;
use zcash_client_backend::encoding::{decode_payment_address, encode_extended_spending_key, encode_payment_address};
use zcash_client_backend::wallet::AccountId;
use zcash_primitives::consensus::{BlockHeight, NetworkUpgrade, H0};
use zcash_primitives::memo::MemoBytes;
use zcash_primitives::merkle_tree::{CommitmentTree, Hashable, IncrementalWitness};
use zcash_primitives::sapling::keys::OutgoingViewingKey;
use zcash_primitives::sapling::note_encryption::try_sapling_output_recovery;
use zcash_primitives::sapling::{Node, Note};
use zcash_primitives::transaction::builder::Builder as ZTxBuilder;
use zcash_primitives::transaction::components::{Amount, TxOut};
use zcash_primitives::transaction::Transaction as ZTransaction;
use zcash_primitives::{consensus, constants::mainnet as z_mainnet_constants, sapling::PaymentAddress,
                       zip32::ExtendedFullViewingKey, zip32::ExtendedSpendingKey};
use zcash_proofs::prover::LocalTxProver;
use crate::z_coin::{GenTxError, GetUnspentWitnessErr, SendOutputsErr};

#[derive(Debug, Clone)]
pub struct ARRRConsensusParams {}

impl consensus::Parameters for ARRRConsensusParams {
    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Sapling => Some(BlockHeight::from_u32(1)),
            _ => None,
        }
    }

    fn coin_type(&self) -> u32 { z_mainnet_constants::COIN_TYPE }

    fn hrp_sapling_extended_spending_key(&self) -> &str { z_mainnet_constants::HRP_SAPLING_EXTENDED_SPENDING_KEY }

    fn hrp_sapling_extended_full_viewing_key(&self) -> &str {
        z_mainnet_constants::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY
    }

    fn hrp_sapling_payment_address(&self) -> &str { z_mainnet_constants::HRP_SAPLING_PAYMENT_ADDRESS }

    fn b58_pubkey_address_prefix(&self) -> [u8; 2] { z_mainnet_constants::B58_PUBKEY_ADDRESS_PREFIX }

    fn b58_script_address_prefix(&self) -> [u8; 2] { z_mainnet_constants::B58_SCRIPT_ADDRESS_PREFIX }
}

const DEX_FEE_OVK: OutgoingViewingKey = OutgoingViewingKey([7; 32]);

pub struct ZCoinFields {
    z_spending_key: ExtendedSpendingKey,
    z_tx_prover: LocalTxProver,
    /// Mutex preventing concurrent transaction generation/same input usage
    z_unspent_mutex: AsyncMutex<()>,
    /// SQLite connection that is used to cache Sapling data for shielded transactions creation
    sqlite: Mutex<Connection>,
}

impl Transaction for ZTransaction {
    fn tx_hex(&self) -> Vec<u8> {
        let mut hex = Vec::with_capacity(1024);
        self.write(&mut hex).expect("Writing should not fail");
        hex
    }

    fn tx_hash(&self) -> BytesJson {
        let mut bytes = self.txid().0.to_vec();
        bytes.reverse();
        bytes.into()
    }
}

#[derive(Clone, Debug)]
pub struct ZCoin {
    utxo_arc: UtxoArc,
    z_fields: Arc<ZCoinFields>,
}

pub struct ZOutput {
    pub amount: Amount,
    pub viewing_key: Option<OutgoingViewingKey>,
    pub memo: Option<MemoBytes>,
}

impl ZCoin {

    #[inline(always)]
    fn sqlite_conn(&self) -> MutexGuard<'_, Connection> { self.z_fields.sqlite.lock().unwrap() }

    fn tx_enum_from_bytes(&self, bytes: &[u8]) -> Result<TransactionEnum, String> {
        ZTransaction::read(bytes).map(|tx| tx.into()).map_err(|e| e.to_string())
    }

    fn validate_fee(
        &self,
        fee_tx: &TransactionEnum,
        _fee_addr: &[u8],
        amount: &BigDecimal,
        min_block_number: u64,
        uuid: &[u8],
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        let z_tx = match fee_tx {
            TransactionEnum::ZTransaction(t) => t.clone(),
            _ => panic!("Unexpected tx {:?}", fee_tx),
        };
        let amount_sat = try_fus!(sat_from_big_decimal(amount, self.utxo_arc.decimals));
        let expected_memo = MemoBytes::from_bytes(uuid).expect("Uuid length < 512");

        let coin = self.clone();
        let fut = async move {
            let tx_hash = H256::from(z_tx.txid().0).reversed();
            let tx_from_rpc = try_s!(
                coin.rpc_client()
                    .get_verbose_transaction(&tx_hash.into())
                    .compat()
                    .await
            );
            let mut encoded = Vec::with_capacity(1024);
            z_tx.write(&mut encoded).expect("Writing should not fail");
            if encoded != tx_from_rpc.hex.0 {
                return ERR!(
                    "Encoded transaction {:?} does not match the tx {:?} from RPC",
                    encoded,
                    tx_from_rpc
                );
            }

            let block_height = match tx_from_rpc.height {
                Some(h) => {
                    if h < min_block_number {
                        return ERR!("Dex fee tx {:?} confirmed before min block {}", z_tx, min_block_number);
                    } else {
                        BlockHeight::from_u32(h as u32)
                    }
                },
                None => H0,
            };

            for shielded_out in z_tx.shielded_outputs.iter() {
                if let Some((note, address, memo)) =
                try_sapling_output_recovery(&ARRRConsensusParams {}, block_height, &DEX_FEE_OVK, shielded_out)
                {
                    if address != coin.z_fields.dex_fee_addr {
                        let encoded =
                            encode_payment_address(z_mainnet_constants::HRP_SAPLING_PAYMENT_ADDRESS, &address);
                        let expected = encode_payment_address(
                            z_mainnet_constants::HRP_SAPLING_PAYMENT_ADDRESS,
                            &coin.z_fields.dex_fee_addr,
                        );
                        return ERR!(
                            "Dex fee was sent to the invalid address {}, expected {}",
                            encoded,
                            expected
                        );
                    }

                    if note.value != amount_sat {
                        return ERR!("Dex fee has invalid amount {}, expected {}", note.value, amount_sat);
                    }

                    if memo != expected_memo {
                        return ERR!("Dex fee has invalid memo {:?}, expected {:?}", memo, expected_memo);
                    }

                    return Ok(());
                }
            }

            ERR!(
                "The dex fee tx {:?} has no shielded outputs or outputs decryption failed",
                z_tx
            )
        };

        Box::new(fut.boxed().compat())
    }
}