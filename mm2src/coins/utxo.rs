/******************************************************************************
 * Copyright © 2014-2019 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/
//
//  utxo.rs
//  marketmaker
//
//  Copyright © 2017-2019 SuperNET. All rights reserved.
//

pub mod bch;
pub mod bch_and_slp_tx_history;
mod bchd_grpc;
#[allow(clippy::all)]
#[rustfmt::skip]
#[path = "utxo/pb.rs"]
mod bchd_pb;
pub mod qtum;
pub mod rpc_clients;
pub mod slp;
pub mod utxo_block_header_storage;
pub mod utxo_builder;
pub mod utxo_common;
pub mod utxo_standard;
pub mod utxo_withdraw;

use async_trait::async_trait;
use bigdecimal::BigDecimal;
use bitcoin::network::constants::Network as BitcoinNetwork;
pub use bitcrypto::{dhash160, sha256, ChecksumType};
pub use chain::Transaction as UtxoTx;
use chain::{OutPoint, TransactionOutput, TxHashAlgo};
#[cfg(not(target_arch = "wasm32"))]
use common::first_char_to_upper;
use common::jsonrpc_client::JsonRpcError;
use common::mm_ctx::MmArc;
use common::mm_error::prelude::*;
use common::mm_metrics::MetricsArc;
use common::now_ms;
use crypto::trezor::utxo::TrezorUtxoCoin;
use crypto::{Bip32DerPathOps, Bip32Error, Bip44Chain, Bip44DerPathError, Bip44PathToAccount, Bip44PathToCoin,
             ChildNumber, DerivationPath, Secp256k1ExtendedPublicKey};
use derive_more::Display;
#[cfg(not(target_arch = "wasm32"))] use dirs::home_dir;
use futures::channel::mpsc;
use futures::compat::Future01CompatExt;
use futures::lock::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use futures01::Future;
use keys::bytes::Bytes;
pub use keys::{Address, AddressFormat as UtxoAddressFormat, AddressHashEnum, KeyPair, Private, Public, Secret,
               Type as ScriptType};
use lightning_invoice::Currency as LightningCurrency;
#[cfg(test)] use mocktopus::macros::*;
use num_traits::ToPrimitive;
use primitives::hash::{H256, H264};
use rpc::v1::types::{Bytes as BytesJson, Transaction as RpcTransaction, H256 as H256Json};
use script::{Builder, Script, SignatureVersion, TransactionInputSigner};
use serde_json::{self as json, Value as Json};
use serialization::{serialize, serialize_with_flags, SERIALIZE_TRANSACTION_WITNESS};
use spv_validation::types::SPVError;
use std::array::TryFromSliceError;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::hash::Hash;
use std::num::NonZeroU64;
use std::ops::Deref;
#[cfg(not(target_arch = "wasm32"))] use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex, Weak};
use utxo_builder::UtxoConfBuilder;
use utxo_common::{big_decimal_from_sat, UtxoTxBuilder};
use utxo_signer::with_key_pair::sign_tx;
use utxo_signer::{TxProvider, TxProviderError, UtxoSignTxError, UtxoSignTxResult};

use self::rpc_clients::{electrum_script_hash, ElectrumClient, ElectrumRpcRequest, EstimateFeeMethod, EstimateFeeMode,
                        NativeClient, UnspentInfo, UtxoRpcClientEnum, UtxoRpcError, UtxoRpcFut, UtxoRpcResult};
use super::{BalanceError, BalanceFut, BalanceResult, CoinsContext, DerivationMethod, FeeApproxStage, FoundSwapTxSpend,
            HistorySyncState, KmdRewardsDetails, MarketCoinOps, MmCoin, NumConversError, NumConversResult,
            PrivKeyActivationPolicy, PrivKeyNotAllowed, PrivKeyPolicy, RawTransactionFut, RawTransactionRequest,
            RawTransactionResult, RpcTransportEventHandler, RpcTransportEventHandlerShared, TradeFee,
            TradePreimageError, TradePreimageFut, TradePreimageResult, Transaction, TransactionDetails,
            TransactionEnum, TransactionFut, UnexpectedDerivationMethod, WithdrawError, WithdrawRequest};
use crate::coin_balance::{EnableCoinScanPolicy, HDAddressBalanceScanner};
use crate::hd_wallet::{HDAccountOps, HDAccountsMutex, HDAddress, HDWalletCoinOps, HDWalletOps, InvalidBip44ChainError};
use crate::hd_wallet_storage::{HDAccountStorageItem, HDWalletCoinStorage, HDWalletStorageError, HDWalletStorageResult};
use crate::utxo::utxo_block_header_storage::BlockHeaderStorageError;
use utxo_block_header_storage::BlockHeaderStorage;
#[cfg(not(target_arch = "wasm32"))] pub mod tx_cache;
#[cfg(target_arch = "wasm32")]
pub mod utxo_indexedb_block_header_storage;
#[cfg(not(target_arch = "wasm32"))]
pub mod utxo_sql_block_header_storage;

#[cfg(test)] pub mod utxo_tests;
#[cfg(target_arch = "wasm32")] pub mod utxo_wasm_tests;

const KILO_BYTE: u64 = 1000;
/// https://bitcoin.stackexchange.com/a/77192
const MAX_DER_SIGNATURE_LEN: usize = 72;
const COMPRESSED_PUBKEY_LEN: usize = 33;
const P2PKH_OUTPUT_LEN: u64 = 34;
const MATURE_CONFIRMATIONS_DEFAULT: u32 = 100;
const UTXO_DUST_AMOUNT: u64 = 1000;
/// Block count for KMD median time past calculation
///
/// # Safety
/// 11 > 0
const KMD_MTP_BLOCK_COUNT: NonZeroU64 = unsafe { NonZeroU64::new_unchecked(11u64) };
const DEFAULT_DYNAMIC_FEE_VOLATILITY_PERCENT: f64 = 0.5;
const DEFAULT_GAP_LIMIT: u32 = 20;

pub type GenerateTxResult = Result<(TransactionInputSigner, AdditionalTxData), MmError<GenerateTxError>>;
pub type HistoryUtxoTxMap = HashMap<H256Json, HistoryUtxoTx>;

#[cfg(windows)]
#[cfg(not(target_arch = "wasm32"))]
fn get_special_folder_path() -> PathBuf {
    use libc::c_char;
    use std::ffi::CStr;
    use std::mem::zeroed;
    use std::ptr::null_mut;
    use winapi::shared::minwindef::MAX_PATH;
    use winapi::um::shlobj::SHGetSpecialFolderPathA;
    use winapi::um::shlobj::CSIDL_APPDATA;

    let mut buf: [c_char; MAX_PATH + 1] = unsafe { zeroed() };
    // https://docs.microsoft.com/en-us/windows/desktop/api/shlobj_core/nf-shlobj_core-shgetspecialfolderpatha
    let rc = unsafe { SHGetSpecialFolderPathA(null_mut(), buf.as_mut_ptr(), CSIDL_APPDATA, 1) };
    if rc != 1 {
        panic!("!SHGetSpecialFolderPathA")
    }
    Path::new(unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap()).to_path_buf()
}

#[cfg(not(windows))]
#[cfg(not(target_arch = "wasm32"))]
fn get_special_folder_path() -> PathBuf { panic!("!windows") }

impl Transaction for UtxoTx {
    fn tx_hex(&self) -> Vec<u8> {
        if self.has_witness() {
            serialize_with_flags(self, SERIALIZE_TRANSACTION_WITNESS).into()
        } else {
            serialize(self).into()
        }
    }

    fn tx_hash(&self) -> BytesJson { self.hash().reversed().to_vec().into() }
}

impl From<JsonRpcError> for BalanceError {
    fn from(e: JsonRpcError) -> Self { BalanceError::Transport(e.to_string()) }
}

impl From<UtxoRpcError> for BalanceError {
    fn from(e: UtxoRpcError) -> Self {
        match e {
            UtxoRpcError::Internal(desc) => BalanceError::Internal(desc),
            _ => BalanceError::Transport(e.to_string()),
        }
    }
}

impl From<UtxoRpcError> for WithdrawError {
    fn from(e: UtxoRpcError) -> Self {
        match e {
            UtxoRpcError::Transport(transport) | UtxoRpcError::ResponseParseError(transport) => {
                WithdrawError::Transport(transport.to_string())
            },
            UtxoRpcError::InvalidResponse(resp) => WithdrawError::Transport(resp),
            UtxoRpcError::Internal(internal) => WithdrawError::InternalError(internal),
        }
    }
}

impl From<JsonRpcError> for TradePreimageError {
    fn from(e: JsonRpcError) -> Self { TradePreimageError::Transport(e.to_string()) }
}

impl From<UtxoRpcError> for TradePreimageError {
    fn from(e: UtxoRpcError) -> Self {
        match e {
            UtxoRpcError::Transport(transport) | UtxoRpcError::ResponseParseError(transport) => {
                TradePreimageError::Transport(transport.to_string())
            },
            UtxoRpcError::InvalidResponse(resp) => TradePreimageError::Transport(resp),
            UtxoRpcError::Internal(internal) => TradePreimageError::InternalError(internal),
        }
    }
}

impl From<UtxoRpcError> for TxProviderError {
    fn from(rpc: UtxoRpcError) -> Self {
        match rpc {
            resp @ UtxoRpcError::ResponseParseError(_) | resp @ UtxoRpcError::InvalidResponse(_) => {
                TxProviderError::InvalidResponse(resp.to_string())
            },
            UtxoRpcError::Transport(transport) => TxProviderError::Transport(transport.to_string()),
            UtxoRpcError::Internal(internal) => TxProviderError::Internal(internal),
        }
    }
}

impl From<Bip44DerPathError> for HDWalletStorageError {
    fn from(e: Bip44DerPathError) -> Self { HDWalletStorageError::ErrorDeserializing(e.to_string()) }
}

impl From<Bip32Error> for HDWalletStorageError {
    fn from(e: Bip32Error) -> Self { HDWalletStorageError::ErrorDeserializing(e.to_string()) }
}

#[async_trait]
impl TxProvider for UtxoRpcClientEnum {
    async fn get_rpc_transaction(&self, tx_hash: &H256Json) -> Result<RpcTransaction, MmError<TxProviderError>> {
        Ok(self.get_verbose_transaction(tx_hash).compat().await?)
    }
}

/// The `UtxoTx` with the block height transaction mined in.
pub struct HistoryUtxoTx {
    pub height: Option<u64>,
    pub tx: UtxoTx,
}

/// Additional transaction data that can't be easily got from raw transaction without calling
/// additional RPC methods, e.g. to get input amount we need to request all previous transactions
/// and check output values
#[derive(Debug)]
pub struct AdditionalTxData {
    pub received_by_me: u64,
    pub spent_by_me: u64,
    pub fee_amount: u64,
    pub unused_change: Option<u64>,
    pub kmd_rewards: Option<KmdRewardsDetails>,
}

/// The fee set from coins config
#[derive(Debug)]
pub enum TxFee {
    /// Tell the coin that it should request the fee from daemon RPC and calculate it relying on tx size
    Dynamic(EstimateFeeMethod),
    /// Tell the coin that it has fixed tx fee per kb.
    FixedPerKb(u64),
}

/// The actual "runtime" fee that is received from RPC in case of dynamic calculation
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ActualTxFee {
    /// fee amount per Kbyte received from coin RPC
    Dynamic(u64),
    /// Use specified amount per each 1 kb of transaction and also per each output less than amount.
    /// Used by DOGE, but more coins might support it too.
    FixedPerKb(u64),
}

/// Fee policy applied on transaction creation
pub enum FeePolicy {
    /// Send the exact amount specified in output(s), fee is added to spent input amount
    SendExact,
    /// Contains the index of output from which fee should be deducted
    DeductFromOutput(usize),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CachedUnspentInfo {
    pub outpoint: OutPoint,
    pub value: u64,
}

impl From<UnspentInfo> for CachedUnspentInfo {
    fn from(unspent: UnspentInfo) -> CachedUnspentInfo {
        CachedUnspentInfo {
            outpoint: unspent.outpoint,
            value: unspent.value,
        }
    }
}

impl From<CachedUnspentInfo> for UnspentInfo {
    fn from(cached: CachedUnspentInfo) -> UnspentInfo {
        UnspentInfo {
            outpoint: cached.outpoint,
            value: cached.value,
            height: None,
        }
    }
}

/// The cache of recently send transactions used to track the spent UTXOs and replace them with new outputs
/// The daemon needs some time to update the listunspent list for address which makes it return already spent UTXOs
/// This cache helps to prevent UTXO reuse in such cases
pub struct RecentlySpentOutPoints {
    /// Maps CachedUnspentInfo A to a set of CachedUnspentInfo which `spent` A
    input_to_output_map: HashMap<CachedUnspentInfo, HashSet<CachedUnspentInfo>>,
    /// Maps CachedUnspentInfo A to a set of CachedUnspentInfo that `were spent by` A
    output_to_input_map: HashMap<CachedUnspentInfo, HashSet<CachedUnspentInfo>>,
    /// Cache includes only outputs having script_pubkey == for_script_pubkey
    for_script_pubkey: Bytes,
}

impl RecentlySpentOutPoints {
    fn new(for_script_pubkey: Bytes) -> Self {
        RecentlySpentOutPoints {
            input_to_output_map: HashMap::new(),
            output_to_input_map: HashMap::new(),
            for_script_pubkey,
        }
    }

    pub fn add_spent(&mut self, inputs: Vec<UnspentInfo>, spend_tx_hash: H256, outputs: Vec<TransactionOutput>) {
        let inputs: HashSet<_> = inputs.into_iter().map(From::from).collect();
        let to_replace: HashSet<_> = outputs
            .iter()
            .enumerate()
            .filter_map(|(index, output)| {
                if output.script_pubkey == self.for_script_pubkey {
                    Some(CachedUnspentInfo {
                        outpoint: OutPoint {
                            hash: spend_tx_hash,
                            index: index as u32,
                        },
                        value: output.value,
                    })
                } else {
                    None
                }
            })
            .collect();

        let mut prev_inputs_spent = HashSet::new();

        // check if inputs are already in spending cached chain
        for input in &inputs {
            if let Some(prev_inputs) = self.output_to_input_map.get(input) {
                for prev_input in prev_inputs {
                    if let Some(outputs) = self.input_to_output_map.get_mut(prev_input) {
                        prev_inputs_spent.insert(prev_input.clone());
                        outputs.remove(input);
                        for replace in &to_replace {
                            outputs.insert(replace.clone());
                        }
                    }
                }
            }
        }

        prev_inputs_spent.extend(inputs.clone());
        for output in &to_replace {
            self.output_to_input_map
                .insert(output.clone(), prev_inputs_spent.clone());
        }

        for input in inputs {
            self.input_to_output_map.insert(input, to_replace.clone());
        }
    }

    pub fn replace_spent_outputs_with_cache(&self, mut outputs: HashSet<UnspentInfo>) -> HashSet<UnspentInfo> {
        let mut replacement_unspents = HashSet::new();
        outputs = outputs
            .into_iter()
            .filter(|unspent| {
                let outs = self.input_to_output_map.get(&unspent.clone().into());
                match outs {
                    Some(outs) => {
                        for out in outs.iter() {
                            if !replacement_unspents.contains(out) {
                                replacement_unspents.insert(out.clone());
                            }
                        }
                        false
                    },
                    None => true,
                }
            })
            .collect();
        if replacement_unspents.is_empty() {
            return outputs;
        }
        outputs.extend(replacement_unspents.into_iter().map(From::from));
        self.replace_spent_outputs_with_cache(outputs)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum BlockchainNetwork {
    #[serde(rename = "mainnet")]
    Mainnet,
    #[serde(rename = "testnet")]
    Testnet,
    #[serde(rename = "regtest")]
    Regtest,
}

impl From<BlockchainNetwork> for BitcoinNetwork {
    fn from(network: BlockchainNetwork) -> Self {
        match network {
            BlockchainNetwork::Mainnet => BitcoinNetwork::Bitcoin,
            BlockchainNetwork::Testnet => BitcoinNetwork::Testnet,
            BlockchainNetwork::Regtest => BitcoinNetwork::Regtest,
        }
    }
}

impl From<BlockchainNetwork> for LightningCurrency {
    fn from(network: BlockchainNetwork) -> Self {
        match network {
            BlockchainNetwork::Mainnet => LightningCurrency::Bitcoin,
            BlockchainNetwork::Testnet => LightningCurrency::BitcoinTestnet,
            BlockchainNetwork::Regtest => LightningCurrency::Regtest,
        }
    }
}

#[derive(Debug)]
pub struct UtxoCoinConf {
    pub ticker: String,
    /// https://en.bitcoin.it/wiki/List_of_address_prefixes
    /// https://github.com/jl777/coins/blob/master/coins
    pub pub_addr_prefix: u8,
    pub p2sh_addr_prefix: u8,
    pub wif_prefix: u8,
    pub pub_t_addr_prefix: u8,
    pub p2sh_t_addr_prefix: u8,
    pub sign_message_prefix: Option<String>,
    // https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#Segwit_address_format
    pub bech32_hrp: Option<String>,
    /// True if coins uses Proof of Stake consensus algo
    /// Proof of Work is expected by default
    /// https://en.bitcoin.it/wiki/Proof_of_Stake
    /// https://en.bitcoin.it/wiki/Proof_of_work
    /// The actual meaning of this is nTime field is used in transaction
    pub is_pos: bool,
    /// Special field for Zcash and it's forks
    /// Defines if Overwinter network upgrade was activated
    /// https://z.cash/upgrade/overwinter/
    pub overwintered: bool,
    /// The tx version used to detect the transaction ser/de/signing algo
    /// For now it's mostly used for Zcash and forks because they changed the algo in
    /// Overwinter and then Sapling upgrades
    /// https://github.com/zcash/zips/blob/master/zip-0243.rst
    pub tx_version: i32,
    /// If true - allow coins withdraw to P2SH addresses (Segwit).
    /// the flag will also affect the address that MM2 generates by default in the future
    /// will be the Segwit (starting from 3 for BTC case) instead of legacy
    /// https://en.bitcoin.it/wiki/Segregated_Witness
    pub segwit: bool,
    /// Does coin require transactions to be notarized to be considered as confirmed?
    /// https://komodoplatform.com/security-delayed-proof-of-work-dpow/
    pub requires_notarization: AtomicBool,
    /// The address format indicates the default address format from coin config file
    pub default_address_format: UtxoAddressFormat,
    /// Is current coin KMD asset chain?
    /// https://komodoplatform.atlassian.net/wiki/spaces/KPSD/pages/71729160/What+is+a+Parallel+Chain+Asset+Chain
    pub asset_chain: bool,
    /// Dynamic transaction fee volatility in percent. The value is used to predict a possible increase in dynamic fee.
    pub tx_fee_volatility_percent: f64,
    /// Transaction version group id for Zcash transactions since Overwinter: https://github.com/zcash/zips/blob/master/zip-0202.rst
    pub version_group_id: u32,
    /// Consensus branch id for Zcash transactions since Overwinter: https://github.com/zcash/zcash/blob/master/src/consensus/upgrades.cpp#L11
    /// used in transaction sig hash calculation
    pub consensus_branch_id: u32,
    /// Defines if coin uses Zcash transaction format
    pub zcash: bool,
    /// Address and privkey checksum type
    pub checksum_type: ChecksumType,
    /// Fork id used in sighash
    pub fork_id: u32,
    /// Signature version
    pub signature_version: SignatureVersion,
    pub required_confirmations: AtomicU64,
    /// if set to true MM2 will check whether calculated fee is lower than relay fee and use
    /// relay fee amount instead of calculated
    /// https://github.com/KomodoPlatform/atomicDEX-API/issues/617
    pub force_min_relay_fee: bool,
    /// Block count for median time past calculation
    pub mtp_block_count: NonZeroU64,
    pub estimate_fee_mode: Option<EstimateFeeMode>,
    /// The minimum number of confirmations at which a transaction is considered mature
    pub mature_confirmations: u32,
    /// The number of blocks used for estimate_fee/estimate_smart_fee RPC calls
    pub estimate_fee_blocks: u32,
    /// The name of the coin with which Trezor wallet associates this asset.
    pub trezor_coin: Option<TrezorUtxoCoin>,
}

#[derive(Debug)]
pub struct UtxoCoinFields {
    /// UTXO coin config
    pub conf: UtxoCoinConf,
    /// Default decimals amount is 8 (BTC and almost all other UTXO coins)
    /// But there are forks which have different decimals:
    /// Peercoin has 6
    /// Emercoin has 6
    /// Bitcoin Diamond has 7
    pub decimals: u8,
    pub tx_fee: TxFee,
    /// Minimum transaction value at which the value is not less than fee
    pub dust_amount: u64,
    /// RPC client
    pub rpc_client: UtxoRpcClientEnum,
    /// Either ECDSA key pair or a Hardware Wallet info.
    pub priv_key_policy: PrivKeyPolicy<KeyPair>,
    /// Either an Iguana address or an info about last derived account/address.
    pub derivation_method: DerivationMethod<Address, UtxoHDWallet>,
    pub history_sync_state: Mutex<HistorySyncState>,
    /// Path to the TX cache directory
    pub tx_cache_directory: Option<PathBuf>,
    pub block_headers_storage: Option<BlockHeaderStorage>,
    /// The cache of recently send transactions used to track the spent UTXOs and replace them with new outputs
    /// The daemon needs some time to update the listunspent list for address which makes it return already spent UTXOs
    /// This cache helps to prevent UTXO reuse in such cases
    pub recently_spent_outpoints: AsyncMutex<RecentlySpentOutPoints>,
    pub tx_hash_algo: TxHashAlgo,
    /// The flag determines whether to use mature unspent outputs *only* to generate transactions.
    /// https://github.com/KomodoPlatform/atomicDEX-API/issues/1181
    pub check_utxo_maturity: bool,
}

#[derive(Debug, Display)]
pub enum UnsupportedAddr {
    #[display(
        fmt = "{} address format activated for {}, but {} format used instead",
        activated_format,
        ticker,
        used_format
    )]
    FormatMismatch {
        ticker: String,
        activated_format: String,
        used_format: String,
    },
    #[display(fmt = "Expected a valid P2PKH or P2SH prefix for {}", _0)]
    PrefixError(String),
    #[display(fmt = "Address hrp {} is not a valid hrp for {}", hrp, ticker)]
    HrpError { ticker: String, hrp: String },
    #[display(fmt = "Segwit not activated in the config for {}", _0)]
    SegwitNotActivated(String),
}

impl From<UnsupportedAddr> for WithdrawError {
    fn from(e: UnsupportedAddr) -> Self { WithdrawError::InvalidAddress(e.to_string()) }
}

#[derive(Debug)]
pub enum GetTxHeightError {
    HeightNotFound,
}

impl From<GetTxHeightError> for SPVError {
    fn from(e: GetTxHeightError) -> Self {
        match e {
            GetTxHeightError::HeightNotFound => SPVError::InvalidHeight,
        }
    }
}

#[derive(Debug)]
pub enum GetBlockHeaderError {
    StorageError(BlockHeaderStorageError),
    RpcError(JsonRpcError),
    SerializationError(serialization::Error),
    InvalidResponse(String),
    SPVError(SPVError),
    NativeNotSupported(String),
    Internal(String),
}

impl From<JsonRpcError> for GetBlockHeaderError {
    fn from(err: JsonRpcError) -> Self { GetBlockHeaderError::RpcError(err) }
}

impl From<UtxoRpcError> for GetBlockHeaderError {
    fn from(e: UtxoRpcError) -> Self {
        match e {
            UtxoRpcError::Transport(e) | UtxoRpcError::ResponseParseError(e) => GetBlockHeaderError::RpcError(e),
            UtxoRpcError::InvalidResponse(e) => GetBlockHeaderError::InvalidResponse(e),
            UtxoRpcError::Internal(e) => GetBlockHeaderError::Internal(e),
        }
    }
}

impl From<SPVError> for GetBlockHeaderError {
    fn from(e: SPVError) -> Self { GetBlockHeaderError::SPVError(e) }
}

impl From<serialization::Error> for GetBlockHeaderError {
    fn from(err: serialization::Error) -> Self { GetBlockHeaderError::SerializationError(err) }
}

impl From<BlockHeaderStorageError> for GetBlockHeaderError {
    fn from(err: BlockHeaderStorageError) -> Self { GetBlockHeaderError::StorageError(err) }
}

impl UtxoCoinFields {
    pub fn transaction_preimage(&self) -> TransactionInputSigner {
        let lock_time = if self.conf.ticker == "KMD" {
            (now_ms() / 1000) as u32 - 3600 + 777 * 2
        } else {
            (now_ms() / 1000) as u32
        };

        let str_d_zeel = if self.conf.ticker == "NAV" {
            Some("".into())
        } else {
            None
        };

        let n_time = if self.conf.is_pos {
            Some((now_ms() / 1000) as u32)
        } else {
            None
        };

        TransactionInputSigner {
            version: self.conf.tx_version,
            n_time,
            overwintered: self.conf.overwintered,
            version_group_id: self.conf.version_group_id,
            consensus_branch_id: self.conf.consensus_branch_id,
            expiry_height: 0,
            value_balance: 0,
            inputs: vec![],
            outputs: vec![],
            lock_time,
            join_splits: vec![],
            shielded_spends: vec![],
            shielded_outputs: vec![],
            zcash: self.conf.zcash,
            str_d_zeel,
            hash_algo: self.tx_hash_algo.into(),
        }
    }
}

#[derive(Debug, Display)]
#[allow(clippy::large_enum_variant)]
pub enum BroadcastTxErr {
    /// RPC client error
    Rpc(UtxoRpcError),
    /// Other specific error
    Other(String),
}

impl From<UtxoRpcError> for BroadcastTxErr {
    fn from(err: UtxoRpcError) -> Self { BroadcastTxErr::Rpc(err) }
}

#[async_trait]
#[cfg_attr(test, mockable)]
pub trait UtxoTxBroadcastOps {
    async fn broadcast_tx(&self, tx: &UtxoTx) -> Result<H256Json, MmError<BroadcastTxErr>>;
}

#[async_trait]
#[cfg_attr(test, mockable)]
pub trait UtxoTxGenerationOps {
    async fn get_tx_fee(&self) -> UtxoRpcResult<ActualTxFee>;

    /// Calculates interest if the coin is KMD
    /// Adds the value to existing output to my_script_pub or creates additional interest output
    /// returns transaction and data as is if the coin is not KMD
    async fn calc_interest_if_required(
        &self,
        mut unsigned: TransactionInputSigner,
        mut data: AdditionalTxData,
        my_script_pub: Bytes,
    ) -> UtxoRpcResult<(TransactionInputSigner, AdditionalTxData)>;
}

/// The UTXO address balance scanner.
/// If the coin is initialized with a native RPC client, it's better to request the list of used addresses
/// right on `UtxoAddressBalanceScanner` initialization.
/// See [`NativeClientImpl::list_transactions`].
pub enum UtxoAddressScanner {
    Native { non_empty_addresses: HashSet<String> },
    Electrum(ElectrumClient),
}

#[async_trait]
impl HDAddressBalanceScanner for UtxoAddressScanner {
    type Address = Address;

    async fn is_address_used(&self, address: &Self::Address) -> BalanceResult<bool> {
        let is_used = match self {
            UtxoAddressScanner::Native { non_empty_addresses } => non_empty_addresses.contains(&address.to_string()),
            UtxoAddressScanner::Electrum(electrum_client) => {
                let script = output_script(address, ScriptType::P2PKH);
                let script_hash = electrum_script_hash(&script);

                let electrum_history = electrum_client
                    .scripthash_get_history(&hex::encode(script_hash))
                    .compat()
                    .await?;

                !electrum_history.is_empty()
            },
        };
        Ok(is_used)
    }
}

impl UtxoAddressScanner {
    pub async fn init(rpc_client: UtxoRpcClientEnum) -> UtxoRpcResult<UtxoAddressScanner> {
        match rpc_client {
            UtxoRpcClientEnum::Native(native) => UtxoAddressScanner::init_with_native_client(&native).await,
            UtxoRpcClientEnum::Electrum(electrum) => Ok(UtxoAddressScanner::Electrum(electrum)),
        }
    }

    pub async fn init_with_native_client(native: &NativeClient) -> UtxoRpcResult<UtxoAddressScanner> {
        const STEP: u64 = 100;

        let non_empty_addresses = native
            .list_all_transactions(STEP)
            .compat()
            .await?
            .into_iter()
            .map(|tx_item| tx_item.address)
            .collect();
        Ok(UtxoAddressScanner::Native { non_empty_addresses })
    }
}

#[async_trait]
#[cfg_attr(test, mockable)]
pub trait UtxoCommonOps:
    AsRef<UtxoCoinFields> + UtxoTxGenerationOps + UtxoTxBroadcastOps + Clone + Send + Sync + 'static
{
    async fn get_htlc_spend_fee(&self, tx_size: u64) -> UtxoRpcResult<u64>;

    fn addresses_from_script(&self, script: &Script) -> Result<Vec<Address>, String>;

    fn denominate_satoshis(&self, satoshi: i64) -> f64;

    /// Get a public key that matches [`PrivKeyPolicy::KeyPair`].
    ///
    /// # Fail
    ///
    /// The method is expected to fail if [`UtxoCoinFields::priv_key_policy`] is [`PrivKeyPolicy::HardwareWallet`].
    /// It's worth adding a method like `my_public_key_der_path`
    /// that takes a derivation path from which we derive the corresponding public key.
    fn my_public_key(&self) -> Result<&Public, MmError<UnexpectedDerivationMethod>>;

    /// Try to parse address from string using specified on asset enable format,
    /// and if it failed inform user that he used a wrong format.
    fn address_from_str(&self, address: &str) -> Result<Address, String>;

    async fn get_current_mtp(&self) -> UtxoRpcResult<u32>;

    /// Check if the output is spendable (is not coinbase or it has enough confirmations).
    fn is_unspent_mature(&self, output: &RpcTransaction) -> bool;

    /// Calculates interest of the specified transaction.
    /// Please note, this method has to be used for KMD transactions only.
    async fn calc_interest_of_tx(&self, tx: &UtxoTx, input_transactions: &mut HistoryUtxoTxMap) -> UtxoRpcResult<u64>;

    /// Try to get a `HistoryUtxoTx` transaction from `utxo_tx_map` or try to request it from Rpc client.
    async fn get_mut_verbose_transaction_from_map_or_rpc<'a, 'b>(
        &'a self,
        tx_hash: H256Json,
        utxo_tx_map: &'b mut HistoryUtxoTxMap,
    ) -> UtxoRpcResult<&'b mut HistoryUtxoTx>;

    #[allow(clippy::too_many_arguments)]
    async fn p2sh_spending_tx(
        &self,
        prev_transaction: UtxoTx,
        redeem_script: Bytes,
        outputs: Vec<TransactionOutput>,
        script_data: Script,
        sequence: u32,
        lock_time: u32,
        keypair: &KeyPair,
    ) -> Result<UtxoTx, String>;

    /// Returns available unspents in ascending order + RecentlySpentOutPoints MutexGuard for further interaction
    /// (e.g. to add new transaction to it).
    /// Please consider using [`UtxoCommonOps::list_unspent_ordered`] instead.
    async fn list_all_unspent_ordered<'a>(
        &'a self,
        address: &Address,
    ) -> UtxoRpcResult<(Vec<UnspentInfo>, AsyncMutexGuard<'a, RecentlySpentOutPoints>)>;

    /// Returns available mature unspents ascending order + RecentlySpentOutPoints MutexGuard for further interaction
    /// (e.g. to add new transaction to it).
    /// Please consider using [`UtxoCommonOps::list_unspent_ordered`] instead.
    async fn list_mature_unspent_ordered<'a>(
        &'a self,
        address: &Address,
    ) -> UtxoRpcResult<(Vec<UnspentInfo>, AsyncMutexGuard<'a, RecentlySpentOutPoints>)>;

    /// Try to load verbose transaction from cache or try to request it from Rpc client.
    fn get_verbose_transaction_from_cache_or_rpc(&self, txid: H256Json) -> UtxoRpcFut<VerboseTransactionFrom>;

    /// Cache transaction if the coin supports `TX_CACHE` and tx height is set and not zero.
    async fn cache_transaction_if_possible(&self, tx: &RpcTransaction) -> Result<(), String>;

    /// Returns available unspents in ascending order + RecentlySpentOutPoints MutexGuard for further interaction
    /// (e.g. to add new transaction to it).
    async fn list_unspent_ordered(
        &self,
        address: &Address,
    ) -> UtxoRpcResult<(Vec<UnspentInfo>, AsyncMutexGuard<'_, RecentlySpentOutPoints>)>;

    async fn preimage_trade_fee_required_to_send_outputs(
        &self,
        outputs: Vec<TransactionOutput>,
        fee_policy: FeePolicy,
        gas_fee: Option<u64>,
        stage: &FeeApproxStage,
    ) -> TradePreimageResult<BigDecimal>;

    /// Increase the given `dynamic_fee` according to the fee approximation `stage`.
    /// The method is used to predict a possible increase in dynamic fee.
    fn increase_dynamic_fee_by_stage(&self, dynamic_fee: u64, stage: &FeeApproxStage) -> u64;

    async fn p2sh_tx_locktime(&self, htlc_locktime: u32) -> Result<u32, MmError<UtxoRpcError>>;

    fn addr_format(&self) -> &UtxoAddressFormat;

    fn addr_format_for_standard_scripts(&self) -> UtxoAddressFormat;

    fn address_from_pubkey(&self, pubkey: &Public) -> Address;

    fn address_from_extended_pubkey(&self, extended_pubkey: &Secp256k1ExtendedPublicKey) -> Address {
        let pubkey = Public::Compressed(H264::from(extended_pubkey.public_key().serialize()));
        self.address_from_pubkey(&pubkey)
    }
}

#[async_trait]
pub trait UtxoStandardOps {
    /// Gets tx details by hash requesting the coin RPC if required.
    /// * `input_transactions` - the cache of the already requested transactions.
    async fn tx_details_by_hash(
        &self,
        hash: &[u8],
        input_transactions: &mut HistoryUtxoTxMap,
    ) -> Result<TransactionDetails, String>;

    async fn request_tx_history(&self, metrics: MetricsArc) -> RequestTxHistoryResult;

    /// Calculate the KMD rewards and re-calculate the transaction fee
    /// if the specified `tx_details` was generated without considering the KMD rewards.
    /// Please note, this method has to be used for KMD transactions only.
    async fn update_kmd_rewards(
        &self,
        tx_details: &mut TransactionDetails,
        input_transactions: &mut HistoryUtxoTxMap,
    ) -> UtxoRpcResult<()>;
}

#[derive(Clone, Debug)]
pub struct UtxoArc(Arc<UtxoCoinFields>);
impl Deref for UtxoArc {
    type Target = UtxoCoinFields;
    fn deref(&self) -> &UtxoCoinFields { &*self.0 }
}

impl From<UtxoCoinFields> for UtxoArc {
    fn from(coin: UtxoCoinFields) -> UtxoArc { UtxoArc::new(coin) }
}

impl From<Arc<UtxoCoinFields>> for UtxoArc {
    fn from(arc: Arc<UtxoCoinFields>) -> UtxoArc { UtxoArc(arc) }
}

impl UtxoArc {
    pub fn new(fields: UtxoCoinFields) -> UtxoArc { UtxoArc(Arc::new(fields)) }

    pub fn with_arc(inner: Arc<UtxoCoinFields>) -> UtxoArc { UtxoArc(inner) }

    /// Returns weak reference to the inner UtxoCoinFields
    pub fn downgrade(&self) -> UtxoWeak {
        let weak = Arc::downgrade(&self.0);
        UtxoWeak(weak)
    }
}

#[derive(Clone, Debug)]
pub struct UtxoWeak(Weak<UtxoCoinFields>);

impl From<Weak<UtxoCoinFields>> for UtxoWeak {
    fn from(weak: Weak<UtxoCoinFields>) -> Self { UtxoWeak(weak) }
}

impl UtxoWeak {
    pub fn upgrade(&self) -> Option<UtxoArc> { self.0.upgrade().map(UtxoArc::from) }
}

// We can use a shared UTXO lock for all UTXO coins at 1 time.
// It's highly likely that we won't experience any issues with it as we won't need to send "a lot" of transactions concurrently.
lazy_static! {
    pub static ref UTXO_LOCK: AsyncMutex<()> = AsyncMutex::new(());
}

#[derive(Debug, Display)]
pub enum GenerateTxError {
    #[display(
        fmt = "Couldn't generate tx from empty UTXOs set, required no less than {} satoshis",
        required
    )]
    EmptyUtxoSet { required: u64 },
    #[display(fmt = "Couldn't generate tx with empty output set")]
    EmptyOutputs,
    #[display(fmt = "Output value {} less than dust {}", value, dust)]
    OutputValueLessThanDust { value: u64, dust: u64 },
    #[display(
        fmt = "Output {} value {} is too small, required no less than {}",
        output_idx,
        output_value,
        required
    )]
    DeductFeeFromOutputFailed {
        output_idx: usize,
        output_value: u64,
        required: u64,
    },
    #[display(
        fmt = "Sum of input values {} is too small, required no less than {}",
        sum_utxos,
        required
    )]
    NotEnoughUtxos { sum_utxos: u64, required: u64 },
    #[display(fmt = "Transport error: {}", _0)]
    Transport(String),
    #[display(fmt = "Internal error: {}", _0)]
    Internal(String),
}

impl From<JsonRpcError> for GenerateTxError {
    fn from(rpc_err: JsonRpcError) -> Self { GenerateTxError::Transport(rpc_err.to_string()) }
}

impl From<UtxoRpcError> for GenerateTxError {
    fn from(e: UtxoRpcError) -> Self {
        match e {
            UtxoRpcError::Transport(rpc) | UtxoRpcError::ResponseParseError(rpc) => {
                GenerateTxError::Transport(rpc.to_string())
            },
            UtxoRpcError::InvalidResponse(error) => GenerateTxError::Transport(error),
            UtxoRpcError::Internal(error) => GenerateTxError::Internal(error),
        }
    }
}

impl From<NumConversError> for GenerateTxError {
    fn from(e: NumConversError) -> Self { GenerateTxError::Internal(e.to_string()) }
}

pub enum RequestTxHistoryResult {
    Ok(Vec<(H256Json, u64)>),
    Retry { error: String },
    HistoryTooLarge,
    CriticalError(String),
}

pub enum VerboseTransactionFrom {
    Cache(RpcTransaction),
    Rpc(RpcTransaction),
}

impl VerboseTransactionFrom {
    fn into_inner(self) -> RpcTransaction {
        match self {
            VerboseTransactionFrom::Rpc(tx) | VerboseTransactionFrom::Cache(tx) => tx,
        }
    }
}

pub fn compressed_key_pair_from_bytes(raw: &[u8], prefix: u8, checksum_type: ChecksumType) -> Result<KeyPair, String> {
    if raw.len() != 32 {
        return ERR!("Invalid raw priv key len {}", raw.len());
    }

    let private = Private {
        prefix,
        compressed: true,
        secret: Secret::from(raw),
        checksum_type,
    };
    Ok(try_s!(KeyPair::from_private(private)))
}

pub fn compressed_pub_key_from_priv_raw(raw_priv: &[u8], sum_type: ChecksumType) -> Result<H264, String> {
    let key_pair: KeyPair = try_s!(compressed_key_pair_from_bytes(raw_priv, 0, sum_type));
    Ok(H264::from(&**key_pair.public()))
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct UtxoFeeDetails {
    pub coin: Option<String>,
    pub amount: BigDecimal,
}

#[cfg(not(target_arch = "wasm32"))]
// https://github.com/KomodoPlatform/komodo/blob/master/zcutil/fetch-params.sh#L5
// https://github.com/KomodoPlatform/komodo/blob/master/zcutil/fetch-params.bat#L4
pub fn zcash_params_path() -> PathBuf {
    if cfg!(windows) {
        // >= Vista: c:\Users\$username\AppData\Roaming
        get_special_folder_path().join("ZcashParams")
    } else if cfg!(target_os = "macos") {
        home_dir()
            .unwrap()
            .join("Library")
            .join("Application Support")
            .join("ZcashParams")
    } else {
        home_dir().unwrap().join(".zcash-params")
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn coin_daemon_data_dir(name: &str, is_asset_chain: bool) -> PathBuf {
    // komodo/util.cpp/GetDefaultDataDir
    let mut data_dir = match dirs::home_dir() {
        Some(hd) => hd,
        None => Path::new("/").to_path_buf(),
    };

    if cfg!(windows) {
        // >= Vista: c:\Users\$username\AppData\Roaming
        data_dir = get_special_folder_path();
        if is_asset_chain {
            data_dir.push("Komodo");
        } else {
            data_dir.push(first_char_to_upper(name));
        }
    } else if cfg!(target_os = "macos") {
        data_dir.push("Library");
        data_dir.push("Application Support");
        if is_asset_chain {
            data_dir.push("Komodo");
        } else {
            data_dir.push(first_char_to_upper(name));
        }
    } else if is_asset_chain {
        data_dir.push(".komodo");
    } else {
        data_dir.push(format!(".{}", name));
    }

    if is_asset_chain {
        data_dir.push(name)
    };
    data_dir
}

/// Electrum protocol version verifier.
/// The structure is used to handle the `on_connected` event and notify `electrum_version_loop`.
struct ElectrumProtoVerifier {
    on_connect_tx: mpsc::UnboundedSender<String>,
}

impl ElectrumProtoVerifier {
    fn into_shared(self) -> RpcTransportEventHandlerShared { Arc::new(self) }
}

impl RpcTransportEventHandler for ElectrumProtoVerifier {
    fn debug_info(&self) -> String { "ElectrumProtoVerifier".into() }

    fn on_outgoing_request(&self, _data: &[u8]) {}

    fn on_incoming_response(&self, _data: &[u8]) {}

    fn on_connected(&self, address: String) -> Result<(), String> {
        try_s!(self.on_connect_tx.unbounded_send(address));
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UtxoMergeParams {
    pub merge_at: usize,
    #[serde(default = "ten_f64")]
    pub check_every: f64,
    #[serde(default = "one_hundred")]
    pub max_merge_at_once: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UtxoBlockHeaderVerificationParams {
    pub difficulty_check: bool,
    pub constant_difficulty: bool,
    pub blocks_limit_to_check: NonZeroU64,
    pub check_every: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UtxoActivationParams {
    pub mode: UtxoRpcMode,
    pub utxo_merge_params: Option<UtxoMergeParams>,
    #[serde(default)]
    pub tx_history: bool,
    pub required_confirmations: Option<u64>,
    pub requires_notarization: Option<bool>,
    pub address_format: Option<UtxoAddressFormat>,
    pub gap_limit: Option<u32>,
    #[serde(default)]
    pub scan_policy: EnableCoinScanPolicy,
    #[serde(default = "PrivKeyActivationPolicy::iguana_priv_key")]
    pub priv_key_policy: PrivKeyActivationPolicy,
    /// The flag determines whether to use mature unspent outputs *only* to generate transactions.
    /// https://github.com/KomodoPlatform/atomicDEX-API/issues/1181
    pub check_utxo_maturity: Option<bool>,
}

#[derive(Debug, Display)]
pub enum UtxoFromLegacyReqErr {
    UnexpectedMethod,
    InvalidElectrumServers(json::Error),
    InvalidMergeParams(json::Error),
    InvalidBlockHeaderVerificationParams(json::Error),
    InvalidRequiredConfs(json::Error),
    InvalidRequiresNota(json::Error),
    InvalidAddressFormat(json::Error),
    InvalidCheckUtxoMaturity(json::Error),
    InvalidScanPolicy(json::Error),
    InvalidPrivKeyPolicy(json::Error),
}

impl UtxoActivationParams {
    pub fn from_legacy_req(req: &Json) -> Result<Self, MmError<UtxoFromLegacyReqErr>> {
        let mode = match req["method"].as_str() {
            Some("enable") => UtxoRpcMode::Native,
            Some("electrum") => {
                let servers =
                    json::from_value(req["servers"].clone()).map_to_mm(UtxoFromLegacyReqErr::InvalidElectrumServers)?;
                UtxoRpcMode::Electrum { servers }
            },
            _ => return MmError::err(UtxoFromLegacyReqErr::UnexpectedMethod),
        };
        let utxo_merge_params =
            json::from_value(req["utxo_merge_params"].clone()).map_to_mm(UtxoFromLegacyReqErr::InvalidMergeParams)?;

        let tx_history = req["tx_history"].as_bool().unwrap_or_default();
        let required_confirmations = json::from_value(req["required_confirmations"].clone())
            .map_to_mm(UtxoFromLegacyReqErr::InvalidRequiredConfs)?;
        let requires_notarization = json::from_value(req["requires_notarization"].clone())
            .map_to_mm(UtxoFromLegacyReqErr::InvalidRequiresNota)?;
        let address_format =
            json::from_value(req["address_format"].clone()).map_to_mm(UtxoFromLegacyReqErr::InvalidAddressFormat)?;
        let check_utxo_maturity = json::from_value(req["check_utxo_maturity"].clone())
            .map_to_mm(UtxoFromLegacyReqErr::InvalidCheckUtxoMaturity)?;
        let scan_policy = json::from_value::<Option<EnableCoinScanPolicy>>(req["scan_policy"].clone())
            .map_to_mm(UtxoFromLegacyReqErr::InvalidScanPolicy)?
            .unwrap_or_default();
        let priv_key_policy = json::from_value::<Option<PrivKeyActivationPolicy>>(req["priv_key_policy"].clone())
            .map_to_mm(UtxoFromLegacyReqErr::InvalidPrivKeyPolicy)?
            .unwrap_or(PrivKeyActivationPolicy::IguanaPrivKey);

        Ok(UtxoActivationParams {
            mode,
            utxo_merge_params,
            tx_history,
            required_confirmations,
            requires_notarization,
            address_format,
            gap_limit: None,
            scan_policy,
            priv_key_policy,
            check_utxo_maturity,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "rpc", content = "rpc_data")]
pub enum UtxoRpcMode {
    Native,
    Electrum { servers: Vec<ElectrumRpcRequest> },
}

#[derive(Debug)]
pub struct ElectrumBuilderArgs {
    pub spawn_ping: bool,
    pub negotiate_version: bool,
    pub collect_metrics: bool,
}

impl Default for ElectrumBuilderArgs {
    fn default() -> Self {
        ElectrumBuilderArgs {
            spawn_ping: true,
            negotiate_version: true,
            collect_metrics: true,
        }
    }
}

#[derive(Debug)]
pub struct UtxoHDWallet {
    pub hd_wallet_storage: HDWalletCoinStorage,
    pub address_format: UtxoAddressFormat,
    /// Derivation path of the coin.
    /// This derivation path consists of `purpose` and `coin_type` only
    /// where the full `BIP44` address has the following structure:
    /// `m/purpose'/coin_type'/account'/change/address_index`.
    pub derivation_path: Bip44PathToCoin,
    /// User accounts.
    pub accounts: HDAccountsMutex<UtxoHDAccount>,
    pub gap_limit: u32,
}

impl HDWalletOps for UtxoHDWallet {
    type HDAccount = UtxoHDAccount;

    fn coin_type(&self) -> u32 { self.derivation_path.coin_type() }

    fn gap_limit(&self) -> u32 { self.gap_limit }

    fn get_accounts_mutex(&self) -> &HDAccountsMutex<Self::HDAccount> { &self.accounts }
}

#[derive(Clone, Debug, PartialEq)]
pub struct UtxoHDAccount {
    pub account_id: u32,
    /// [Extended public key](https://learnmeabitcoin.com/technical/extended-keys) that corresponds to the derivation path:
    /// `m/purpose'/coin_type'/account'`.
    pub extended_pubkey: Secp256k1ExtendedPublicKey,
    /// [`UtxoHDWallet::derivation_path`] derived by [`UtxoHDAccount::account_id`].
    pub account_derivation_path: Bip44PathToAccount,
    /// The number of addresses that we know have been used by the user.
    /// This is used in order not to check the transaction history for each address,
    /// but to request the balance of addresses whose index is less than `address_number`.
    pub external_addresses_number: u32,
    pub internal_addresses_number: u32,
}

impl HDAccountOps for UtxoHDAccount {
    fn known_addresses_number(&self, chain: Bip44Chain) -> MmResult<u32, InvalidBip44ChainError> {
        match chain {
            Bip44Chain::External => Ok(self.external_addresses_number),
            Bip44Chain::Internal => Ok(self.internal_addresses_number),
        }
    }

    fn account_derivation_path(&self) -> DerivationPath { self.account_derivation_path.to_derivation_path() }

    fn account_id(&self) -> u32 { self.account_id }
}

impl UtxoHDAccount {
    pub fn try_from_storage_item(
        wallet_der_path: &Bip44PathToCoin,
        account_info: &HDAccountStorageItem,
    ) -> HDWalletStorageResult<UtxoHDAccount> {
        const ACCOUNT_CHILD_HARDENED: bool = true;

        let account_child = ChildNumber::new(account_info.account_id, ACCOUNT_CHILD_HARDENED)?;
        let account_derivation_path = wallet_der_path
            .derive(account_child)
            .map_to_mm(Bip44DerPathError::from)?;
        let extended_pubkey = Secp256k1ExtendedPublicKey::from_str(&account_info.account_xpub)?;
        Ok(UtxoHDAccount {
            account_id: account_info.account_id,
            extended_pubkey,
            account_derivation_path,
            external_addresses_number: account_info.external_addresses_number,
            internal_addresses_number: account_info.internal_addresses_number,
        })
    }

    pub fn to_storage_item(&self) -> HDAccountStorageItem {
        HDAccountStorageItem {
            account_id: self.account_id,
            account_xpub: self.extended_pubkey.to_string(bip32::Prefix::XPUB),
            external_addresses_number: self.external_addresses_number,
            internal_addresses_number: self.internal_addresses_number,
        }
    }
}

/// Function calculating KMD interest
/// https://komodoplatform.atlassian.net/wiki/spaces/KPSD/pages/71729215/What+is+the+5+Komodo+Stake+Reward
/// https://github.com/KomodoPlatform/komodo/blob/master/src/komodo_interest.h
fn kmd_interest(
    height: Option<u64>,
    value: u64,
    lock_time: u64,
    current_time: u64,
) -> Result<u64, KmdRewardsNotAccruedReason> {
    const KOMODO_ENDOFERA: u64 = 7_777_777;
    const LOCKTIME_THRESHOLD: u64 = 500_000_000;

    // value must be at least 10 KMD
    if value < 1_000_000_000 {
        return Err(KmdRewardsNotAccruedReason::UtxoAmountLessThanTen);
    }
    // locktime must be set
    if lock_time == 0 {
        return Err(KmdRewardsNotAccruedReason::LocktimeNotSet);
    }
    // interest doesn't accrue for lock_time < 500_000_000
    if lock_time < LOCKTIME_THRESHOLD {
        return Err(KmdRewardsNotAccruedReason::LocktimeLessThanThreshold);
    }
    let height = match height {
        Some(h) => h,
        None => return Err(KmdRewardsNotAccruedReason::TransactionInMempool), // consider that the transaction is not mined yet
    };
    // interest will stop accrue after block 7_777_777
    if height >= KOMODO_ENDOFERA {
        return Err(KmdRewardsNotAccruedReason::UtxoHeightGreaterThanEndOfEra);
    };
    // current time must be greater than tx lock_time
    if current_time < lock_time {
        return Err(KmdRewardsNotAccruedReason::OneHourNotPassedYet);
    }

    let mut minutes = (current_time - lock_time) / 60;

    // at least 1 hour should pass
    if minutes < 60 {
        return Err(KmdRewardsNotAccruedReason::OneHourNotPassedYet);
    }

    // interest stop accruing after 1 year before block 1000000
    if minutes > 365 * 24 * 60 {
        minutes = 365 * 24 * 60
    };
    // interest stop accruing after 1 month past 1000000 block
    if height >= 1_000_000 && minutes > 31 * 24 * 60 {
        minutes = 31 * 24 * 60;
    }
    // next 2 lines ported as is from Komodo codebase
    minutes -= 59;
    let accrued = (value / 10_512_000) * minutes;

    Ok(accrued)
}

fn kmd_interest_accrue_stop_at(height: u64, lock_time: u64) -> u64 {
    let seconds = if height < 1_000_000 {
        // interest stop accruing after 1 year before block 1000000
        365 * 24 * 60 * 60
    } else {
        // interest stop accruing after 1 month past 1000000 block
        31 * 24 * 60 * 60
    };

    lock_time + seconds
}

fn kmd_interest_accrue_start_at(lock_time: u64) -> u64 {
    let one_hour = 60 * 60;
    lock_time + one_hour
}

#[derive(Debug, Serialize, Eq, PartialEq)]
enum KmdRewardsNotAccruedReason {
    LocktimeNotSet,
    LocktimeLessThanThreshold,
    UtxoHeightGreaterThanEndOfEra,
    UtxoAmountLessThanTen,
    OneHourNotPassedYet,
    TransactionInMempool,
}

#[derive(Serialize)]
enum KmdRewardsAccrueInfo {
    Accrued(BigDecimal),
    NotAccruedReason(KmdRewardsNotAccruedReason),
}

#[derive(Serialize)]
pub struct KmdRewardsInfoElement {
    tx_hash: H256Json,
    #[serde(skip_serializing_if = "Option::is_none")]
    height: Option<u64>,
    /// The zero-based index of the output in the transaction’s list of outputs.
    output_index: u32,
    amount: BigDecimal,
    locktime: u64,
    /// Amount of accrued rewards.
    accrued_rewards: KmdRewardsAccrueInfo,
    /// Rewards start to accrue at this time for the given transaction.
    /// None if the rewards will not be accrued.
    #[serde(skip_serializing_if = "Option::is_none")]
    accrue_start_at: Option<u64>,
    /// Rewards stop to accrue at this time for the given transaction.
    /// None if the rewards will not be accrued.
    #[serde(skip_serializing_if = "Option::is_none")]
    accrue_stop_at: Option<u64>,
}

/// Get rewards info of unspent outputs.
/// The list is ordered by the output value.
pub async fn kmd_rewards_info<T: UtxoCommonOps>(coin: &T) -> Result<Vec<KmdRewardsInfoElement>, String> {
    if coin.as_ref().conf.ticker != "KMD" {
        return ERR!("rewards info can be obtained for KMD only");
    }

    let utxo = coin.as_ref();
    let my_address = try_s!(utxo.derivation_method.iguana_or_err());
    let rpc_client = &utxo.rpc_client;
    let mut unspents = try_s!(rpc_client.list_unspent(my_address, utxo.decimals).compat().await);
    // list_unspent_ordered() returns ordered from lowest to highest by value unspent outputs.
    // reverse it to reorder from highest to lowest outputs.
    unspents.reverse();

    let mut result = Vec::with_capacity(unspents.len());
    for unspent in unspents {
        let tx_hash: H256Json = unspent.outpoint.hash.reversed().into();
        let tx_info = try_s!(rpc_client.get_verbose_transaction(&tx_hash).compat().await);

        let value = unspent.value;
        let locktime = tx_info.locktime as u64;
        let current_time = try_s!(coin.get_current_mtp().await) as u64;
        let accrued_rewards = match kmd_interest(tx_info.height, value, locktime, current_time) {
            Ok(interest) => {
                KmdRewardsAccrueInfo::Accrued(big_decimal_from_sat(interest as i64, coin.as_ref().decimals))
            },
            Err(reason) => KmdRewardsAccrueInfo::NotAccruedReason(reason),
        };

        // `accrue_start_at` and `accrue_stop_at` should be None if the rewards will never be obtained for the given transaction
        let (accrue_start_at, accrue_stop_at) = match &accrued_rewards {
            KmdRewardsAccrueInfo::Accrued(_)
            | KmdRewardsAccrueInfo::NotAccruedReason(KmdRewardsNotAccruedReason::TransactionInMempool)
            | KmdRewardsAccrueInfo::NotAccruedReason(KmdRewardsNotAccruedReason::OneHourNotPassedYet) => {
                let start_at = Some(kmd_interest_accrue_start_at(locktime));
                let stop_at = tx_info
                    .height
                    .map(|height| kmd_interest_accrue_stop_at(height, locktime));
                (start_at, stop_at)
            },
            _ => (None, None),
        };

        result.push(KmdRewardsInfoElement {
            tx_hash,
            height: tx_info.height,
            output_index: unspent.outpoint.index,
            amount: big_decimal_from_sat(value as i64, coin.as_ref().decimals),
            locktime,
            accrued_rewards,
            accrue_start_at,
            accrue_stop_at,
        });
    }

    Ok(result)
}

/// Denominate BigDecimal amount of coin units to satoshis
pub fn sat_from_big_decimal(amount: &BigDecimal, decimals: u8) -> NumConversResult<u64> {
    (amount * BigDecimal::from(10u64.pow(decimals as u32)))
        .to_u64()
        .or_mm_err(|| {
            let err = format!("Could not get sat from amount {} with decimals {}", amount, decimals);
            NumConversError::new(err)
        })
}

async fn send_outputs_from_my_address_impl<T>(coin: T, outputs: Vec<TransactionOutput>) -> Result<UtxoTx, String>
where
    T: UtxoCommonOps,
{
    let my_address = try_s!(coin.as_ref().derivation_method.iguana_or_err());
    let (unspents, recently_sent_txs) = try_s!(coin.list_unspent_ordered(my_address).await);
    generate_and_send_tx(&coin, unspents, None, FeePolicy::SendExact, recently_sent_txs, outputs).await
}

/// Generates and sends tx using unspents and outputs adding new record to the recently_spent in case of success
async fn generate_and_send_tx<T>(
    coin: &T,
    unspents: Vec<UnspentInfo>,
    required_inputs: Option<Vec<UnspentInfo>>,
    fee_policy: FeePolicy,
    mut recently_spent: AsyncMutexGuard<'_, RecentlySpentOutPoints>,
    outputs: Vec<TransactionOutput>,
) -> Result<UtxoTx, String>
where
    T: AsRef<UtxoCoinFields> + UtxoTxGenerationOps + UtxoTxBroadcastOps,
{
    let my_address = try_s!(coin.as_ref().derivation_method.iguana_or_err());
    let key_pair = try_s!(coin.as_ref().priv_key_policy.key_pair_or_err());

    let mut builder = UtxoTxBuilder::new(coin)
        .add_available_inputs(unspents)
        .add_outputs(outputs)
        .with_fee_policy(fee_policy);
    if let Some(required) = required_inputs {
        builder = builder.add_required_inputs(required);
    }
    let (unsigned, _) = try_s!(builder.build().await);

    let spent_unspents = unsigned
        .inputs
        .iter()
        .map(|input| UnspentInfo {
            outpoint: input.previous_output.clone(),
            value: input.amount,
            height: None,
        })
        .collect();

    let signature_version = match &my_address.addr_format {
        UtxoAddressFormat::Segwit => SignatureVersion::WitnessV0,
        _ => coin.as_ref().conf.signature_version,
    };

    let prev_script = Builder::build_p2pkh(&my_address.hash);
    let signed = try_s!(sign_tx(
        unsigned,
        key_pair,
        prev_script,
        signature_version,
        coin.as_ref().conf.fork_id
    ));

    try_s!(coin.broadcast_tx(&signed).await);

    recently_spent.add_spent(spent_unspents, signed.hash(), signed.outputs.clone());

    Ok(signed)
}

pub fn output_script(address: &Address, script_type: ScriptType) -> Script {
    match address.addr_format {
        UtxoAddressFormat::Segwit => Builder::build_witness_script(&address.hash),
        _ => match script_type {
            ScriptType::P2PKH => Builder::build_p2pkh(&address.hash),
            ScriptType::P2SH => Builder::build_p2sh(&address.hash),
            ScriptType::P2WPKH => Builder::build_witness_script(&address.hash),
            ScriptType::P2WSH => Builder::build_witness_script(&address.hash),
        },
    }
}

pub fn address_by_conf_and_pubkey_str(
    coin: &str,
    conf: &Json,
    pubkey: &str,
    addr_format: UtxoAddressFormat,
) -> Result<String, String> {
    // using a reasonable default here
    let params = UtxoActivationParams {
        mode: UtxoRpcMode::Native,
        utxo_merge_params: None,
        tx_history: false,
        required_confirmations: None,
        requires_notarization: None,
        address_format: None,
        gap_limit: None,
        scan_policy: EnableCoinScanPolicy::default(),
        priv_key_policy: PrivKeyActivationPolicy::IguanaPrivKey,
        check_utxo_maturity: None,
    };
    let conf_builder = UtxoConfBuilder::new(conf, &params, coin);
    let utxo_conf = try_s!(conf_builder.build());
    let pubkey_bytes = try_s!(hex::decode(pubkey));
    let hash = dhash160(&pubkey_bytes);

    let address = Address {
        prefix: utxo_conf.pub_addr_prefix,
        t_addr_prefix: utxo_conf.pub_t_addr_prefix,
        hash: hash.into(),
        checksum_type: utxo_conf.checksum_type,
        hrp: utxo_conf.bech32_hrp,
        addr_format,
    };
    address.display_address()
}

fn parse_hex_encoded_u32(hex_encoded: &str) -> Result<u32, MmError<String>> {
    let hex_encoded = hex_encoded.strip_prefix("0x").unwrap_or(hex_encoded);
    let bytes = hex::decode(hex_encoded).map_to_mm(|e| e.to_string())?;
    let be_bytes: [u8; 4] = bytes
        .as_slice()
        .try_into()
        .map_to_mm(|e: TryFromSliceError| e.to_string())?;
    Ok(u32::from_be_bytes(be_bytes))
}

fn ten_f64() -> f64 { 10. }

fn one_hundred() -> usize { 100 }

#[test]
fn test_parse_hex_encoded_u32() {
    assert_eq!(parse_hex_encoded_u32("0x892f2085"), Ok(2301567109));
    assert_eq!(parse_hex_encoded_u32("892f2085"), Ok(2301567109));
    assert_eq!(parse_hex_encoded_u32("0x7361707a"), Ok(1935765626));
}
