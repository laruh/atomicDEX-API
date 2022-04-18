//! The module implementing Simple Ledger Protocol (SLP) support.
//! It's a custom token format mostly used on the Bitcoin Cash blockchain.
//! Tracking issue: https://github.com/KomodoPlatform/atomicDEX-API/issues/701
//! More info about the protocol and implementation guides can be found at https://slp.dev/

use crate::utxo::bch::BchCoin;
use crate::utxo::bchd_grpc::{check_slp_transaction, validate_slp_utxos, ValidateSlpUtxosErr};
use crate::utxo::rpc_clients::{UnspentInfo, UtxoRpcClientEnum, UtxoRpcError, UtxoRpcResult};
use crate::utxo::utxo_common::{self, big_decimal_from_sat_unsigned, payment_script, UtxoTxBuilder};
use crate::utxo::{generate_and_send_tx, sat_from_big_decimal, ActualTxFee, AdditionalTxData, BroadcastTxErr,
                  FeePolicy, GenerateTxError, RecentlySpentOutPoints, UtxoCoinConf, UtxoCoinFields, UtxoCommonOps,
                  UtxoTx, UtxoTxBroadcastOps, UtxoTxGenerationOps};
use crate::{BalanceFut, CoinBalance, FeeApproxStage, FoundSwapTxSpend, HistorySyncState, MarketCoinOps, MmCoin,
            NegotiateSwapContractAddrErr, NumConversError, PrivKeyNotAllowed, RawTransactionFut,
            RawTransactionRequest, SignatureResult, SwapOps, TradeFee, TradePreimageError, TradePreimageFut,
            TradePreimageResult, TradePreimageValue, TransactionDetails, TransactionEnum, TransactionFut,
            TxFeeDetails, UnexpectedDerivationMethod, ValidateAddressResult, ValidatePaymentInput, VerificationResult,
            WithdrawError, WithdrawFee, WithdrawFut, WithdrawRequest};
use async_trait::async_trait;
use bitcrypto::dhash160;
use chain::constants::SEQUENCE_FINAL;
use chain::{OutPoint, TransactionOutput};
use common::log::warn;
use common::mm_ctx::MmArc;
use common::mm_error::prelude::*;
use common::mm_number::{BigDecimal, MmNumber};
use common::now_ms;
use common::privkey::key_pair_from_secret;
use derive_more::Display;
use futures::compat::Future01CompatExt;
use futures::lock::MutexGuard as AsyncMutexGuard;
use futures::{FutureExt, TryFutureExt};
use futures01::Future;
use hex::FromHexError;
use keys::hash::H160;
use keys::{AddressHashEnum, CashAddrType, CashAddress, KeyPair, NetworkPrefix as CashAddrPrefix, Public};
use primitives::hash::H256;
use rpc::v1::types::{Bytes as BytesJson, ToTxHash, H256 as H256Json};
use script::bytes::Bytes;
use script::{Builder as ScriptBuilder, Opcode, Script, TransactionInputSigner};
use serde_json::Value as Json;
use serialization::{deserialize, serialize, Deserializable, Error, Reader};
use serialization_derive::Deserializable;
use std::convert::TryInto;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use utxo_signer::with_key_pair::{p2pkh_spend, p2sh_spend, sign_tx, UtxoSignWithKeyPairError};

const SLP_SWAP_VOUT: usize = 1;
const SLP_FEE_VOUT: usize = 1;
const SLP_HTLC_SPEND_SIZE: u64 = 555;
const SLP_LOKAD_ID: &str = "SLP\x00";
const SLP_FUNGIBLE: u8 = 1;
const SLP_SEND: &str = "SEND";
const SLP_MINT: &str = "MINT";
const SLP_GENESIS: &str = "GENESIS";

#[derive(Debug)]
pub struct SlpTokenConf {
    decimals: u8,
    ticker: String,
    token_id: H256,
    required_confirmations: AtomicU64,
}

/// Minimalistic info that is used to be stored outside of the token's context
/// E.g. in the platform BCHCoin
#[derive(Debug)]
pub struct SlpTokenInfo {
    pub token_id: H256,
    pub decimals: u8,
}

#[derive(Clone, Debug)]
pub struct SlpToken {
    conf: Arc<SlpTokenConf>,
    platform_coin: BchCoin,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SlpUnspent {
    pub bch_unspent: UnspentInfo,
    pub slp_amount: u64,
}

#[derive(Clone, Debug)]
pub struct SlpOutput {
    pub amount: u64,
    pub script_pubkey: Bytes,
}

/// The SLP transaction preimage
struct SlpTxPreimage {
    slp_inputs: Vec<SlpUnspent>,
    available_bch_inputs: Vec<UnspentInfo>,
    outputs: Vec<TransactionOutput>,
}

#[derive(Debug, Display)]
enum ValidateHtlcError {
    TxLackOfOutputs,
    #[display(fmt = "TxParseError: {:?}", _0)]
    TxParseError(Error),
    #[display(fmt = "OpReturnParseError: {:?}", _0)]
    OpReturnParseError(ParseSlpScriptError),
    InvalidSlpDetails,
    InvalidSlpUtxo(ValidateSlpUtxosErr),
    NumConversionErr(NumConversError),
    ValidatePaymentError(String),
    UnexpectedDerivationMethod(UnexpectedDerivationMethod),
}

impl From<NumConversError> for ValidateHtlcError {
    fn from(err: NumConversError) -> ValidateHtlcError { ValidateHtlcError::NumConversionErr(err) }
}

impl From<ParseSlpScriptError> for ValidateHtlcError {
    fn from(err: ParseSlpScriptError) -> Self { ValidateHtlcError::OpReturnParseError(err) }
}

impl From<ValidateSlpUtxosErr> for ValidateHtlcError {
    fn from(err: ValidateSlpUtxosErr) -> Self { ValidateHtlcError::InvalidSlpUtxo(err) }
}

impl From<UnexpectedDerivationMethod> for ValidateHtlcError {
    fn from(e: UnexpectedDerivationMethod) -> Self { ValidateHtlcError::UnexpectedDerivationMethod(e) }
}

#[derive(Debug, Display)]
enum ValidateDexFeeError {
    TxLackOfOutputs,
    #[display(fmt = "OpReturnParseError: {:?}", _0)]
    OpReturnParseError(ParseSlpScriptError),
    InvalidSlpDetails,
    NumConversionErr(NumConversError),
    ValidatePaymentError(String),
}

impl From<NumConversError> for ValidateDexFeeError {
    fn from(err: NumConversError) -> ValidateDexFeeError { ValidateDexFeeError::NumConversionErr(err) }
}

impl From<ParseSlpScriptError> for ValidateDexFeeError {
    fn from(err: ParseSlpScriptError) -> Self { ValidateDexFeeError::OpReturnParseError(err) }
}

#[allow(clippy::upper_case_acronyms, clippy::large_enum_variant)]
#[derive(Debug, Display)]
pub enum SpendP2SHError {
    GenerateTxErr(GenerateTxError),
    Rpc(UtxoRpcError),
    SignTxErr(UtxoSignWithKeyPairError),
    PrivKeyNotAllowed(PrivKeyNotAllowed),
    UnexpectedDerivationMethod(UnexpectedDerivationMethod),
    String(String),
}

impl From<GenerateTxError> for SpendP2SHError {
    fn from(err: GenerateTxError) -> SpendP2SHError { SpendP2SHError::GenerateTxErr(err) }
}

impl From<UtxoRpcError> for SpendP2SHError {
    fn from(err: UtxoRpcError) -> SpendP2SHError { SpendP2SHError::Rpc(err) }
}

impl From<UtxoSignWithKeyPairError> for SpendP2SHError {
    fn from(sign: UtxoSignWithKeyPairError) -> SpendP2SHError { SpendP2SHError::SignTxErr(sign) }
}

impl From<PrivKeyNotAllowed> for SpendP2SHError {
    fn from(e: PrivKeyNotAllowed) -> Self { SpendP2SHError::PrivKeyNotAllowed(e) }
}

impl From<UnexpectedDerivationMethod> for SpendP2SHError {
    fn from(e: UnexpectedDerivationMethod) -> Self { SpendP2SHError::UnexpectedDerivationMethod(e) }
}

impl From<String> for SpendP2SHError {
    fn from(err: String) -> SpendP2SHError { SpendP2SHError::String(err) }
}

#[derive(Debug, Display)]
pub enum SpendHtlcError {
    TxLackOfOutputs,
    #[display(fmt = "DeserializationErr: {:?}", _0)]
    DeserializationErr(Error),
    #[display(fmt = "PubkeyParseError: {:?}", _0)]
    PubkeyParseErr(keys::Error),
    InvalidSlpDetails,
    NumConversionErr(NumConversError),
    RpcErr(UtxoRpcError),
    #[allow(clippy::upper_case_acronyms)]
    SpendP2SHErr(SpendP2SHError),
    OpReturnParseError(ParseSlpScriptError),
    UnexpectedDerivationMethod(UnexpectedDerivationMethod),
}

impl From<UnexpectedDerivationMethod> for SpendHtlcError {
    fn from(e: UnexpectedDerivationMethod) -> Self { SpendHtlcError::UnexpectedDerivationMethod(e) }
}

impl From<NumConversError> for SpendHtlcError {
    fn from(err: NumConversError) -> SpendHtlcError { SpendHtlcError::NumConversionErr(err) }
}

impl From<Error> for SpendHtlcError {
    fn from(err: Error) -> SpendHtlcError { SpendHtlcError::DeserializationErr(err) }
}

impl From<keys::Error> for SpendHtlcError {
    fn from(err: keys::Error) -> SpendHtlcError { SpendHtlcError::PubkeyParseErr(err) }
}

impl From<SpendP2SHError> for SpendHtlcError {
    fn from(err: SpendP2SHError) -> SpendHtlcError { SpendHtlcError::SpendP2SHErr(err) }
}

impl From<UtxoRpcError> for SpendHtlcError {
    fn from(err: UtxoRpcError) -> SpendHtlcError { SpendHtlcError::RpcErr(err) }
}

impl From<ParseSlpScriptError> for SpendHtlcError {
    fn from(err: ParseSlpScriptError) -> Self { SpendHtlcError::OpReturnParseError(err) }
}

fn slp_send_output(token_id: &H256, amounts: &[u64]) -> TransactionOutput {
    let mut script_builder = ScriptBuilder::default()
        .push_opcode(Opcode::OP_RETURN)
        .push_data(SLP_LOKAD_ID.as_bytes())
        .push_data(&[SLP_FUNGIBLE])
        .push_data(SLP_SEND.as_bytes())
        .push_data(token_id.as_slice());
    for amount in amounts {
        script_builder = script_builder.push_data(&amount.to_be_bytes());
    }
    TransactionOutput {
        value: 0,
        script_pubkey: script_builder.into_bytes(),
    }
}

pub fn slp_genesis_output(
    ticker: &str,
    name: &str,
    token_document_url: Option<&str>,
    token_document_hash: Option<H256>,
    decimals: u8,
    mint_baton_vout: Option<u8>,
    initial_token_mint_quantity: u64,
) -> TransactionOutput {
    let mut script_builder = ScriptBuilder::default()
        .push_opcode(Opcode::OP_RETURN)
        .push_data(SLP_LOKAD_ID.as_bytes())
        .push_data(&[SLP_FUNGIBLE])
        .push_data(SLP_GENESIS.as_bytes())
        .push_data(ticker.as_bytes())
        .push_data(name.as_bytes());

    script_builder = match token_document_url {
        Some(url) => script_builder.push_data(url.as_bytes()),
        None => script_builder
            .push_opcode(Opcode::OP_PUSHDATA1)
            .push_opcode(Opcode::OP_0),
    };

    script_builder = match token_document_hash {
        Some(hash) => script_builder.push_data(hash.as_slice()),
        None => script_builder
            .push_opcode(Opcode::OP_PUSHDATA1)
            .push_opcode(Opcode::OP_0),
    };

    script_builder = script_builder.push_data(&[decimals]);
    script_builder = match mint_baton_vout {
        Some(vout) => script_builder.push_data(&[vout]),
        None => script_builder
            .push_opcode(Opcode::OP_PUSHDATA1)
            .push_opcode(Opcode::OP_0),
    };

    script_builder = script_builder.push_data(&initial_token_mint_quantity.to_be_bytes());
    TransactionOutput {
        value: 0,
        script_pubkey: script_builder.into_bytes(),
    }
}

#[derive(Debug)]
pub struct SlpProtocolConf {
    pub platform_coin_ticker: String,
    pub token_id: H256,
    pub decimals: u8,
    pub required_confirmations: Option<u64>,
}

#[derive(Debug)]
pub struct ValidateHtlcInput {
    tx: Vec<u8>,
    other_pub: Public,
    my_pub: Public,
    time_lock: u32,
    secret_hash: Vec<u8>,
    amount: BigDecimal,
    confirmations: u64,
}

impl SlpToken {
    pub fn new(
        decimals: u8,
        ticker: String,
        token_id: H256,
        platform_coin: BchCoin,
        required_confirmations: u64,
    ) -> SlpToken {
        let conf = Arc::new(SlpTokenConf {
            decimals,
            ticker,
            token_id,
            required_confirmations: AtomicU64::new(required_confirmations),
        });
        SlpToken { conf, platform_coin }
    }

    /// Returns the OP_RETURN output for SLP Send transaction
    fn send_op_return_output(&self, amounts: &[u64]) -> TransactionOutput {
        slp_send_output(&self.conf.token_id, amounts)
    }

    fn rpc(&self) -> &UtxoRpcClientEnum { &self.platform_coin.as_ref().rpc_client }

    /// Returns unspents of the SLP token plus plain BCH UTXOs plus RecentlySpentOutPoints mutex guard
    async fn slp_unspents_for_spend(
        &self,
    ) -> UtxoRpcResult<(
        Vec<SlpUnspent>,
        Vec<UnspentInfo>,
        AsyncMutexGuard<'_, RecentlySpentOutPoints>,
    )> {
        self.platform_coin.get_token_utxos_for_spend(&self.conf.token_id).await
    }

    async fn slp_unspents_for_display(&self) -> UtxoRpcResult<(Vec<SlpUnspent>, Vec<UnspentInfo>)> {
        self.platform_coin
            .get_token_utxos_for_display(&self.conf.token_id)
            .await
    }

    /// Generates the tx preimage that spends the SLP from my address to the desired destinations (script pubkeys)
    async fn generate_slp_tx_preimage(
        &self,
        slp_outputs: Vec<SlpOutput>,
    ) -> Result<(SlpTxPreimage, AsyncMutexGuard<'_, RecentlySpentOutPoints>), MmError<GenSlpSpendErr>> {
        // the limit is 19, but we may require the change to be added
        if slp_outputs.len() > 18 {
            return MmError::err(GenSlpSpendErr::TooManyOutputs);
        }
        let (slp_unspents, bch_unspents, recently_spent) = self.slp_unspents_for_spend().await?;
        let total_slp_output = slp_outputs.iter().fold(0, |cur, slp_out| cur + slp_out.amount);
        let mut total_slp_input = 0;

        let mut inputs = vec![];
        for slp_utxo in slp_unspents {
            if total_slp_input >= total_slp_output {
                break;
            }

            total_slp_input += slp_utxo.slp_amount;
            inputs.push(slp_utxo);
        }

        if total_slp_input < total_slp_output {
            return MmError::err(GenSlpSpendErr::InsufficientSlpBalance {
                coin: self.ticker().into(),
                required: big_decimal_from_sat_unsigned(total_slp_output, self.decimals()),
                available: big_decimal_from_sat_unsigned(total_slp_input, self.decimals()),
            });
        }
        let change = total_slp_input - total_slp_output;

        let mut amounts_for_op_return: Vec<_> = slp_outputs.iter().map(|spend_to| spend_to.amount).collect();
        if change > 0 {
            amounts_for_op_return.push(change);
        }

        let op_return_out_mm = self.send_op_return_output(&amounts_for_op_return);
        let mut outputs = vec![op_return_out_mm];

        outputs.extend(slp_outputs.into_iter().map(|spend_to| TransactionOutput {
            value: self.platform_dust(),
            script_pubkey: spend_to.script_pubkey,
        }));

        if change > 0 {
            let my_public_key = self.platform_coin.my_public_key()?;
            let slp_change_out = TransactionOutput {
                value: self.platform_dust(),
                script_pubkey: ScriptBuilder::build_p2pkh(&my_public_key.address_hash().into()).to_bytes(),
            };
            outputs.push(slp_change_out);
        }

        validate_slp_utxos(self.platform_coin.bchd_urls(), &inputs, self.token_id()).await?;
        let preimage = SlpTxPreimage {
            slp_inputs: inputs,
            available_bch_inputs: bch_unspents,
            outputs,
        };
        Ok((preimage, recently_spent))
    }

    pub async fn send_slp_outputs(&self, slp_outputs: Vec<SlpOutput>) -> Result<UtxoTx, String> {
        let (preimage, recently_spent) = try_s!(self.generate_slp_tx_preimage(slp_outputs).await);
        generate_and_send_tx(
            self,
            preimage.available_bch_inputs,
            Some(preimage.slp_inputs.into_iter().map(|slp| slp.bch_unspent).collect()),
            FeePolicy::SendExact,
            recently_spent,
            preimage.outputs,
        )
        .await
    }

    async fn send_htlc(
        &self,
        my_pub: &Public,
        other_pub: &Public,
        time_lock: u32,
        secret_hash: &[u8],
        amount: u64,
    ) -> Result<UtxoTx, String> {
        let payment_script = payment_script(time_lock, secret_hash, my_pub, other_pub);
        let script_pubkey = ScriptBuilder::build_p2sh(&dhash160(&payment_script).into()).to_bytes();
        let slp_out = SlpOutput { amount, script_pubkey };
        let (preimage, recently_spent) = try_s!(self.generate_slp_tx_preimage(vec![slp_out]).await);
        generate_and_send_tx(
            self,
            preimage.available_bch_inputs,
            Some(preimage.slp_inputs.into_iter().map(|slp| slp.bch_unspent).collect()),
            FeePolicy::SendExact,
            recently_spent,
            preimage.outputs,
        )
        .await
    }

    async fn validate_htlc(&self, input: ValidateHtlcInput) -> Result<(), MmError<ValidateHtlcError>> {
        let mut tx: UtxoTx = deserialize(input.tx.as_slice()).map_to_mm(ValidateHtlcError::TxParseError)?;
        tx.tx_hash_algo = self.platform_coin.as_ref().tx_hash_algo;
        if tx.outputs.len() < 2 {
            return MmError::err(ValidateHtlcError::TxLackOfOutputs);
        }

        let slp_satoshis = sat_from_big_decimal(&input.amount, self.decimals())?;

        let slp_unspent = SlpUnspent {
            bch_unspent: UnspentInfo {
                outpoint: OutPoint {
                    hash: tx.hash(),
                    index: 1,
                },
                value: 0,
                height: None,
            },
            slp_amount: slp_satoshis,
        };
        validate_slp_utxos(self.platform_coin.bchd_urls(), &[slp_unspent], self.token_id()).await?;

        let slp_tx: SlpTxDetails = parse_slp_script(tx.outputs[0].script_pubkey.as_slice())?;

        match slp_tx.transaction {
            SlpTransaction::Send { token_id, amounts } => {
                if token_id != self.token_id() {
                    return MmError::err(ValidateHtlcError::InvalidSlpDetails);
                }

                if amounts.is_empty() {
                    return MmError::err(ValidateHtlcError::InvalidSlpDetails);
                }

                if amounts[0] != slp_satoshis {
                    return MmError::err(ValidateHtlcError::InvalidSlpDetails);
                }
            },
            _ => return MmError::err(ValidateHtlcError::InvalidSlpDetails),
        }

        let validate_fut = utxo_common::validate_payment(
            self.platform_coin.clone(),
            tx,
            SLP_SWAP_VOUT,
            &input.other_pub,
            &input.my_pub,
            &input.secret_hash,
            self.platform_dust_dec(),
            input.time_lock,
            input.confirmations,
        );

        validate_fut
            .compat()
            .await
            .map_to_mm(ValidateHtlcError::ValidatePaymentError)?;

        Ok(())
    }

    pub async fn refund_htlc(
        &self,
        htlc_tx: &[u8],
        other_pub: &Public,
        time_lock: u32,
        secret_hash: &[u8],
        htlc_keypair: &KeyPair,
    ) -> Result<UtxoTx, MmError<SpendHtlcError>> {
        let tx: UtxoTx = deserialize(htlc_tx)?;
        if tx.outputs.is_empty() {
            return MmError::err(SpendHtlcError::TxLackOfOutputs);
        }

        let slp_tx: SlpTxDetails = parse_slp_script(tx.outputs[0].script_pubkey.as_slice())?;

        let other_pub = Public::from_slice(other_pub)?;
        let my_public_key = self.platform_coin.my_public_key()?;
        let redeem_script = payment_script(time_lock, secret_hash, my_public_key, &other_pub);

        let slp_amount = match slp_tx.transaction {
            SlpTransaction::Send { token_id, amounts } => {
                if token_id != self.token_id() {
                    return MmError::err(SpendHtlcError::InvalidSlpDetails);
                }
                *amounts.get(0).ok_or(SpendHtlcError::InvalidSlpDetails)?
            },
            _ => return MmError::err(SpendHtlcError::InvalidSlpDetails),
        };
        let slp_utxo = SlpUnspent {
            bch_unspent: UnspentInfo {
                outpoint: OutPoint {
                    hash: tx.hash(),
                    index: SLP_SWAP_VOUT as u32,
                },
                value: tx.outputs[1].value,
                height: None,
            },
            slp_amount,
        };

        let tx_locktime = self.platform_coin.p2sh_tx_locktime(time_lock).await?;
        let script_data = ScriptBuilder::default().push_opcode(Opcode::OP_1).into_script();
        let tx = self
            .spend_p2sh(
                slp_utxo,
                tx_locktime,
                SEQUENCE_FINAL - 1,
                script_data,
                redeem_script,
                htlc_keypair,
            )
            .await?;
        Ok(tx)
    }

    pub async fn spend_htlc(
        &self,
        htlc_tx: &[u8],
        other_pub: &Public,
        time_lock: u32,
        secret: &[u8],
        keypair: &KeyPair,
    ) -> Result<UtxoTx, MmError<SpendHtlcError>> {
        let tx: UtxoTx = deserialize(htlc_tx)?;
        let slp_tx: SlpTxDetails = deserialize(tx.outputs[0].script_pubkey.as_slice())?;

        let other_pub = Public::from_slice(other_pub)?;
        let redeem = payment_script(time_lock, &*dhash160(secret), &other_pub, keypair.public());

        let slp_amount = match slp_tx.transaction {
            SlpTransaction::Send { token_id, amounts } => {
                if token_id != self.token_id() {
                    return MmError::err(SpendHtlcError::InvalidSlpDetails);
                }
                *amounts.get(0).ok_or(SpendHtlcError::InvalidSlpDetails)?
            },
            _ => return MmError::err(SpendHtlcError::InvalidSlpDetails),
        };
        let slp_utxo = SlpUnspent {
            bch_unspent: UnspentInfo {
                outpoint: OutPoint {
                    hash: tx.hash(),
                    index: SLP_SWAP_VOUT as u32,
                },
                value: tx.outputs[1].value,
                height: None,
            },
            slp_amount,
        };

        let tx_locktime = self.platform_coin.p2sh_tx_locktime(time_lock).await?;
        let script_data = ScriptBuilder::default()
            .push_data(secret)
            .push_opcode(Opcode::OP_0)
            .into_script();
        let tx = self
            .spend_p2sh(slp_utxo, tx_locktime, SEQUENCE_FINAL, script_data, redeem, keypair)
            .await?;
        Ok(tx)
    }

    pub async fn spend_p2sh(
        &self,
        p2sh_utxo: SlpUnspent,
        tx_locktime: u32,
        input_sequence: u32,
        script_data: Script,
        redeem_script: Script,
        htlc_keypair: &KeyPair,
    ) -> Result<UtxoTx, MmError<SpendP2SHError>> {
        let op_return_out_mm = self.send_op_return_output(&[p2sh_utxo.slp_amount]);
        let mut outputs = Vec::with_capacity(3);
        outputs.push(op_return_out_mm);

        let my_public_key = self.platform_coin.my_public_key()?;
        let my_script_pubkey = ScriptBuilder::build_p2pkh(&my_public_key.address_hash().into());
        let slp_output = TransactionOutput {
            value: self.platform_dust(),
            script_pubkey: my_script_pubkey.to_bytes(),
        };
        outputs.push(slp_output);

        let (_, bch_inputs, _recently_spent) = self.slp_unspents_for_spend().await?;
        let (mut unsigned, _) = UtxoTxBuilder::new(&self.platform_coin)
            .add_required_inputs(std::iter::once(p2sh_utxo.bch_unspent))
            .add_available_inputs(bch_inputs)
            .add_outputs(outputs)
            .build()
            .await?;

        unsigned.lock_time = tx_locktime;
        unsigned.inputs[0].sequence = input_sequence;

        let my_key_pair = self.platform_coin.as_ref().priv_key_policy.key_pair_or_err()?;
        let signed_p2sh_input = p2sh_spend(
            &unsigned,
            0,
            htlc_keypair,
            script_data,
            redeem_script,
            self.platform_coin.as_ref().conf.signature_version,
            self.platform_coin.as_ref().conf.fork_id,
        )?;

        let signed_inputs: Result<Vec<_>, _> = unsigned
            .inputs
            .iter()
            .enumerate()
            .skip(1)
            .map(|(i, _)| {
                p2pkh_spend(
                    &unsigned,
                    i,
                    my_key_pair,
                    my_script_pubkey.clone(),
                    self.platform_coin.as_ref().conf.signature_version,
                    self.platform_coin.as_ref().conf.fork_id,
                )
            })
            .collect();

        let mut signed_inputs = signed_inputs?;

        signed_inputs.insert(0, signed_p2sh_input);

        let signed = UtxoTx {
            version: unsigned.version,
            n_time: unsigned.n_time,
            overwintered: unsigned.overwintered,
            version_group_id: unsigned.version_group_id,
            inputs: signed_inputs,
            outputs: unsigned.outputs,
            lock_time: unsigned.lock_time,
            expiry_height: unsigned.expiry_height,
            shielded_spends: unsigned.shielded_spends,
            shielded_outputs: unsigned.shielded_outputs,
            join_splits: unsigned.join_splits,
            value_balance: unsigned.value_balance,
            join_split_pubkey: Default::default(),
            join_split_sig: Default::default(),
            binding_sig: Default::default(),
            zcash: unsigned.zcash,
            str_d_zeel: unsigned.str_d_zeel,
            tx_hash_algo: self.platform_coin.as_ref().tx_hash_algo,
        };

        let _broadcast = self
            .rpc()
            .send_raw_transaction(serialize(&signed).into())
            .compat()
            .await?;
        Ok(signed)
    }

    async fn validate_dex_fee(
        &self,
        tx: UtxoTx,
        expected_sender: &[u8],
        fee_addr: &[u8],
        amount: BigDecimal,
        min_block_number: u64,
    ) -> Result<(), MmError<ValidateDexFeeError>> {
        if tx.outputs.len() < 2 {
            return MmError::err(ValidateDexFeeError::TxLackOfOutputs);
        }

        let slp_tx: SlpTxDetails = parse_slp_script(tx.outputs[0].script_pubkey.as_slice())?;

        match slp_tx.transaction {
            SlpTransaction::Send { token_id, amounts } => {
                if token_id != self.token_id() {
                    return MmError::err(ValidateDexFeeError::InvalidSlpDetails);
                }

                if amounts.is_empty() {
                    return MmError::err(ValidateDexFeeError::InvalidSlpDetails);
                }

                let expected = sat_from_big_decimal(&amount, self.decimals())?;

                if amounts[0] != expected {
                    return MmError::err(ValidateDexFeeError::InvalidSlpDetails);
                }
            },
            _ => return MmError::err(ValidateDexFeeError::InvalidSlpDetails),
        }

        let validate_fut = utxo_common::validate_fee(
            self.platform_coin.clone(),
            tx,
            SLP_FEE_VOUT,
            expected_sender,
            &self.platform_dust_dec(),
            min_block_number,
            fee_addr,
        );

        validate_fut
            .compat()
            .await
            .map_to_mm(ValidateDexFeeError::ValidatePaymentError)?;

        Ok(())
    }

    pub fn platform_dust(&self) -> u64 { self.platform_coin.as_ref().dust_amount }

    pub fn platform_decimals(&self) -> u8 { self.platform_coin.as_ref().decimals }

    pub fn platform_dust_dec(&self) -> BigDecimal {
        big_decimal_from_sat_unsigned(self.platform_dust(), self.platform_decimals())
    }

    pub fn decimals(&self) -> u8 { self.conf.decimals }

    pub fn token_id(&self) -> &H256 { &self.conf.token_id }

    fn platform_conf(&self) -> &UtxoCoinConf { &self.platform_coin.as_ref().conf }

    async fn my_balance_sat(&self) -> UtxoRpcResult<u64> {
        let (slp_unspents, _) = self.slp_unspents_for_display().await?;
        let satoshi = slp_unspents.iter().fold(0, |cur, unspent| cur + unspent.slp_amount);
        Ok(satoshi)
    }

    pub async fn my_coin_balance(&self) -> UtxoRpcResult<CoinBalance> {
        let balance_sat = self.my_balance_sat().await?;
        let spendable = big_decimal_from_sat_unsigned(balance_sat, self.decimals());
        Ok(CoinBalance {
            spendable,
            unspendable: 0.into(),
        })
    }

    fn slp_prefix(&self) -> &CashAddrPrefix { self.platform_coin.slp_prefix() }

    pub fn get_info(&self) -> SlpTokenInfo {
        SlpTokenInfo {
            token_id: self.conf.token_id,
            decimals: self.conf.decimals,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct SlpGenesisParams {
    pub(super) token_ticker: String,
    token_name: String,
    token_document_url: String,
    token_document_hash: Vec<u8>,
    pub(super) decimals: Vec<u8>,
    pub(super) mint_baton_vout: Option<u8>,
    pub(super) initial_token_mint_quantity: u64,
}

/// https://slp.dev/specs/slp-token-type-1/#transaction-detail
#[derive(Debug, Eq, PartialEq)]
pub enum SlpTransaction {
    /// https://slp.dev/specs/slp-token-type-1/#genesis-token-genesis-transaction
    Genesis(SlpGenesisParams),
    /// https://slp.dev/specs/slp-token-type-1/#mint-extended-minting-transaction
    Mint {
        token_id: H256,
        mint_baton_vout: Option<u8>,
        additional_token_quantity: u64,
    },
    /// https://slp.dev/specs/slp-token-type-1/#send-spend-transaction
    Send { token_id: H256, amounts: Vec<u64> },
}

impl SlpTransaction {
    pub fn token_id(&self) -> Option<H256> {
        match self {
            SlpTransaction::Send { token_id, .. } | SlpTransaction::Mint { token_id, .. } => Some(*token_id),
            SlpTransaction::Genesis(_) => None,
        }
    }
}

impl Deserializable for SlpTransaction {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, Error>
    where
        Self: Sized,
        T: std::io::Read,
    {
        let transaction_type: String = reader.read()?;
        match transaction_type.as_str() {
            SLP_GENESIS => {
                let token_ticker = reader.read()?;
                let token_name = reader.read()?;
                let maybe_push_op_code: u8 = reader.read()?;
                let token_document_url = if maybe_push_op_code == Opcode::OP_PUSHDATA1 as u8 {
                    reader.read()?
                } else {
                    let mut url = vec![0; maybe_push_op_code as usize];
                    reader.read_slice(&mut url)?;
                    String::from_utf8(url).map_err(|e| Error::Custom(e.to_string()))?
                };

                let maybe_push_op_code: u8 = reader.read()?;
                let token_document_hash = if maybe_push_op_code == Opcode::OP_PUSHDATA1 as u8 {
                    reader.read_list()?
                } else {
                    let mut hash = vec![0; maybe_push_op_code as usize];
                    reader.read_slice(&mut hash)?;
                    hash
                };
                let decimals = reader.read_list()?;
                let maybe_push_op_code: u8 = reader.read()?;
                let mint_baton_vout = if maybe_push_op_code == Opcode::OP_PUSHDATA1 as u8 {
                    let _zero: u8 = reader.read()?;
                    None
                } else {
                    Some(reader.read()?)
                };
                let bytes: Vec<u8> = reader.read_list()?;
                if bytes.len() != 8 {
                    return Err(Error::Custom(format!("Expected 8 bytes, got {}", bytes.len())));
                }
                let initial_token_mint_quantity = u64::from_be_bytes(bytes.try_into().expect("length is 8 bytes"));

                Ok(SlpTransaction::Genesis(SlpGenesisParams {
                    token_ticker,
                    token_name,
                    token_document_url,
                    token_document_hash,
                    decimals,
                    mint_baton_vout,
                    initial_token_mint_quantity,
                }))
            },
            SLP_MINT => {
                let maybe_id: Vec<u8> = reader.read_list()?;
                if maybe_id.len() != 32 {
                    return Err(Error::Custom(format!("Unexpected token id length {}", maybe_id.len())));
                }

                let maybe_push_op_code: u8 = reader.read()?;
                let mint_baton_vout = if maybe_push_op_code == Opcode::OP_PUSHDATA1 as u8 {
                    let _zero: u8 = reader.read()?;
                    None
                } else {
                    Some(reader.read()?)
                };

                let bytes: Vec<u8> = reader.read_list()?;
                if bytes.len() != 8 {
                    return Err(Error::Custom(format!("Expected 8 bytes, got {}", bytes.len())));
                }
                let additional_token_quantity = u64::from_be_bytes(bytes.try_into().expect("length is 8 bytes"));

                Ok(SlpTransaction::Mint {
                    token_id: H256::from(maybe_id.as_slice()),
                    mint_baton_vout,
                    additional_token_quantity,
                })
            },
            SLP_SEND => {
                let maybe_id: Vec<u8> = reader.read_list()?;
                if maybe_id.len() != 32 {
                    return Err(Error::Custom(format!("Unexpected token id length {}", maybe_id.len())));
                }

                let token_id = H256::from(maybe_id.as_slice());
                let mut amounts = Vec::with_capacity(1);
                while !reader.is_finished() {
                    let bytes: Vec<u8> = reader.read_list()?;
                    if bytes.len() != 8 {
                        return Err(Error::Custom(format!("Expected 8 bytes, got {}", bytes.len())));
                    }
                    let amount = u64::from_be_bytes(bytes.try_into().expect("length is 8 bytes"));
                    amounts.push(amount)
                }

                if amounts.len() > 19 {
                    return Err(Error::Custom(format!(
                        "Expected at most 19 token amounts, got {}",
                        amounts.len()
                    )));
                }
                Ok(SlpTransaction::Send { token_id, amounts })
            },
            _ => Err(Error::Custom(format!(
                "Unsupported transaction type {}",
                transaction_type
            ))),
        }
    }
}

#[derive(Debug, Deserializable)]
pub struct SlpTxDetails {
    op_code: u8,
    lokad_id: String,
    token_type: Vec<u8>,
    pub transaction: SlpTransaction,
}

#[derive(Debug, Display, PartialEq)]
pub enum ParseSlpScriptError {
    NotOpReturn,
    UnexpectedLokadId(String),
    #[display(fmt = "UnexpectedTokenType: {:?}", _0)]
    UnexpectedTokenType(Vec<u8>),
    #[display(fmt = "DeserializeFailed: {:?}", _0)]
    DeserializeFailed(Error),
}

impl From<Error> for ParseSlpScriptError {
    fn from(err: Error) -> ParseSlpScriptError { ParseSlpScriptError::DeserializeFailed(err) }
}

pub fn parse_slp_script(script: &[u8]) -> Result<SlpTxDetails, MmError<ParseSlpScriptError>> {
    let details: SlpTxDetails = deserialize(script)?;
    if Opcode::from_u8(details.op_code) != Some(Opcode::OP_RETURN) {
        return MmError::err(ParseSlpScriptError::NotOpReturn);
    }

    if details.lokad_id != SLP_LOKAD_ID {
        return MmError::err(ParseSlpScriptError::UnexpectedLokadId(details.lokad_id));
    }

    if details.token_type.first() != Some(&SLP_FUNGIBLE) {
        return MmError::err(ParseSlpScriptError::UnexpectedTokenType(details.token_type));
    }

    Ok(details)
}

#[derive(Debug, Display)]
enum GenSlpSpendErr {
    RpcError(UtxoRpcError),
    TooManyOutputs,
    #[display(
        fmt = "Not enough {} to generate SLP spend: available {}, required at least {}",
        coin,
        available,
        required
    )]
    InsufficientSlpBalance {
        coin: String,
        available: BigDecimal,
        required: BigDecimal,
    },
    InvalidSlpUtxos(ValidateSlpUtxosErr),
    Internal(String),
}

impl From<UtxoRpcError> for GenSlpSpendErr {
    fn from(err: UtxoRpcError) -> GenSlpSpendErr { GenSlpSpendErr::RpcError(err) }
}

impl From<ValidateSlpUtxosErr> for GenSlpSpendErr {
    fn from(err: ValidateSlpUtxosErr) -> GenSlpSpendErr { GenSlpSpendErr::InvalidSlpUtxos(err) }
}

impl From<UnexpectedDerivationMethod> for GenSlpSpendErr {
    fn from(e: UnexpectedDerivationMethod) -> Self { GenSlpSpendErr::Internal(e.to_string()) }
}

impl From<GenSlpSpendErr> for WithdrawError {
    fn from(err: GenSlpSpendErr) -> WithdrawError {
        match err {
            GenSlpSpendErr::RpcError(e) => e.into(),
            GenSlpSpendErr::TooManyOutputs | GenSlpSpendErr::InvalidSlpUtxos(_) => {
                WithdrawError::InternalError(err.to_string())
            },
            GenSlpSpendErr::InsufficientSlpBalance {
                coin,
                available,
                required,
            } => WithdrawError::NotSufficientBalance {
                coin,
                available,
                required,
            },
            GenSlpSpendErr::Internal(internal) => WithdrawError::InternalError(internal),
        }
    }
}

impl AsRef<UtxoCoinFields> for SlpToken {
    fn as_ref(&self) -> &UtxoCoinFields { self.platform_coin.as_ref() }
}

#[async_trait]
impl UtxoTxBroadcastOps for SlpToken {
    async fn broadcast_tx(&self, tx: &UtxoTx) -> Result<H256Json, MmError<BroadcastTxErr>> {
        let tx_bytes = serialize(tx);
        check_slp_transaction(self.platform_coin.bchd_urls(), tx_bytes.clone().take())
            .await
            .mm_err(|e| BroadcastTxErr::Other(e.to_string()))?;

        let hash = self.rpc().send_raw_transaction(tx_bytes.into()).compat().await?;

        Ok(hash)
    }
}

#[async_trait]
impl UtxoTxGenerationOps for SlpToken {
    async fn get_tx_fee(&self) -> UtxoRpcResult<ActualTxFee> { self.platform_coin.get_tx_fee().await }

    async fn calc_interest_if_required(
        &self,
        unsigned: TransactionInputSigner,
        data: AdditionalTxData,
        my_script_pub: Bytes,
    ) -> UtxoRpcResult<(TransactionInputSigner, AdditionalTxData)> {
        self.platform_coin
            .calc_interest_if_required(unsigned, data, my_script_pub)
            .await
    }
}

impl MarketCoinOps for SlpToken {
    fn ticker(&self) -> &str { &self.conf.ticker }

    fn my_address(&self) -> Result<String, String> {
        let my_address = try_s!(self.as_ref().derivation_method.iguana_or_err());
        let slp_address = try_s!(self.platform_coin.slp_address(my_address));
        slp_address.encode()
    }

    fn get_public_key(&self) -> Result<String, MmError<UnexpectedDerivationMethod>> { unimplemented!() }

    fn sign_message_hash(&self, _message: &str) -> Option<H256> { unimplemented!() }

    fn sign_message(&self, _message: &str) -> SignatureResult<String> { unimplemented!() }

    fn verify_message(&self, _signature: &str, _message: &str, _address: &str) -> VerificationResult<bool> {
        unimplemented!()
    }

    fn my_balance(&self) -> BalanceFut<CoinBalance> {
        let coin = self.clone();
        let fut = async move { Ok(coin.my_coin_balance().await?) };
        Box::new(fut.boxed().compat())
    }

    fn base_coin_balance(&self) -> BalanceFut<BigDecimal> {
        Box::new(self.platform_coin.my_balance().map(|res| res.spendable))
    }

    fn platform_ticker(&self) -> &str { self.platform_coin.ticker() }

    /// Receives raw transaction bytes in hexadecimal format as input and returns tx hash in hexadecimal format
    fn send_raw_tx(&self, tx: &str) -> Box<dyn Future<Item = String, Error = String> + Send> {
        let coin = self.clone();
        let tx = tx.to_owned();
        let fut = async move {
            let bytes = hex::decode(tx).map_to_mm(|e| e).map_err(|e| format!("{:?}", e))?;
            let tx = deserialize(bytes.as_slice())
                .map_to_mm(|e| e)
                .map_err(|e| format!("{:?}", e))?;
            let hash = coin.broadcast_tx(&tx).await.map_err(|e| format!("{:?}", e))?;
            Ok(format!("{:?}", hash))
        };
        Box::new(fut.boxed().compat())
    }

    fn wait_for_confirmations(
        &self,
        tx: &[u8],
        confirmations: u64,
        requires_nota: bool,
        wait_until: u64,
        check_every: u64,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        self.platform_coin
            .wait_for_confirmations(tx, confirmations, requires_nota, wait_until, check_every)
    }

    fn wait_for_tx_spend(
        &self,
        transaction: &[u8],
        wait_until: u64,
        from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        utxo_common::wait_for_output_spend(
            self.platform_coin.as_ref(),
            transaction,
            SLP_SWAP_VOUT,
            from_block,
            wait_until,
        )
    }

    fn tx_enum_from_bytes(&self, bytes: &[u8]) -> Result<TransactionEnum, String> {
        self.platform_coin.tx_enum_from_bytes(bytes)
    }

    fn current_block(&self) -> Box<dyn Future<Item = u64, Error = String> + Send> { self.platform_coin.current_block() }

    fn display_priv_key(&self) -> Result<String, String> { self.platform_coin.display_priv_key() }

    fn min_tx_amount(&self) -> BigDecimal { big_decimal_from_sat_unsigned(1, self.decimals()) }

    fn min_trading_vol(&self) -> MmNumber { big_decimal_from_sat_unsigned(1, self.decimals()).into() }
}

#[async_trait]
impl SwapOps for SlpToken {
    fn send_taker_fee(&self, fee_addr: &[u8], amount: BigDecimal, _uuid: &[u8]) -> TransactionFut {
        let coin = self.clone();
        let fee_pubkey = try_fus!(Public::from_slice(fee_addr));
        let script_pubkey = ScriptBuilder::build_p2pkh(&fee_pubkey.address_hash().into()).into();
        let amount = try_fus!(sat_from_big_decimal(&amount, self.decimals()));

        let fut = async move {
            let slp_out = SlpOutput { amount, script_pubkey };
            let (preimage, recently_spent) = try_s!(coin.generate_slp_tx_preimage(vec![slp_out]).await);
            generate_and_send_tx(
                &coin,
                preimage.available_bch_inputs,
                Some(preimage.slp_inputs.into_iter().map(|slp| slp.bch_unspent).collect()),
                FeePolicy::SendExact,
                recently_spent,
                preimage.outputs,
            )
            .await
        };
        Box::new(fut.boxed().compat().map(|tx| tx.into()))
    }

    fn send_maker_payment(
        &self,
        time_lock: u32,
        maker_pub: &[u8],
        taker_pub: &[u8],
        secret_hash: &[u8],
        amount: BigDecimal,
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        let maker_pub = try_fus!(Public::from_slice(maker_pub));
        let taker_pub = try_fus!(Public::from_slice(taker_pub));
        let amount = try_fus!(sat_from_big_decimal(&amount, self.decimals()));
        let secret_hash = secret_hash.to_owned();

        let coin = self.clone();
        let fut = async move {
            let tx = try_s!(
                coin.send_htlc(&maker_pub, &taker_pub, time_lock, &secret_hash, amount)
                    .await
            );
            Ok(tx.into())
        };
        Box::new(fut.boxed().compat())
    }

    fn send_taker_payment(
        &self,
        time_lock: u32,
        taker_pub: &[u8],
        maker_pub: &[u8],
        secret_hash: &[u8],
        amount: BigDecimal,
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        let taker_pub = try_fus!(Public::from_slice(taker_pub));
        let maker_pub = try_fus!(Public::from_slice(maker_pub));
        let amount = try_fus!(sat_from_big_decimal(&amount, self.decimals()));
        let secret_hash = secret_hash.to_owned();

        let coin = self.clone();
        let fut = async move {
            let tx = try_s!(
                coin.send_htlc(&taker_pub, &maker_pub, time_lock, &secret_hash, amount)
                    .await
            );
            Ok(tx.into())
        };
        Box::new(fut.boxed().compat())
    }

    fn send_maker_spends_taker_payment(
        &self,
        taker_payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &[u8],
        secret: &[u8],
        htlc_privkey: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        let tx = taker_payment_tx.to_owned();
        let taker_pub = try_fus!(Public::from_slice(taker_pub));
        let secret = secret.to_owned();
        let htlc_keypair = try_fus!(key_pair_from_secret(htlc_privkey));
        let coin = self.clone();

        let fut = async move {
            let tx = try_s!(
                coin.spend_htlc(&tx, &taker_pub, time_lock, &secret, &htlc_keypair)
                    .await
            );
            Ok(tx.into())
        };
        Box::new(fut.boxed().compat())
    }

    fn send_taker_spends_maker_payment(
        &self,
        maker_payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &[u8],
        secret: &[u8],
        htlc_privkey: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        let tx = maker_payment_tx.to_owned();
        let maker_pub = try_fus!(Public::from_slice(maker_pub));
        let secret = secret.to_owned();
        let htlc_keypair = try_fus!(key_pair_from_secret(htlc_privkey));
        let coin = self.clone();

        let fut = async move {
            let tx = try_s!(
                coin.spend_htlc(&tx, &maker_pub, time_lock, &secret, &htlc_keypair)
                    .await
            );
            Ok(tx.into())
        };
        Box::new(fut.boxed().compat())
    }

    fn send_taker_refunds_payment(
        &self,
        taker_payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &[u8],
        secret_hash: &[u8],
        htlc_privkey: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        let tx = taker_payment_tx.to_owned();
        let maker_pub = try_fus!(Public::from_slice(maker_pub));
        let secret_hash = secret_hash.to_owned();
        let keypair = try_fus!(key_pair_from_secret(htlc_privkey));
        let coin = self.clone();

        let fut = async move {
            let tx = try_s!(
                coin.refund_htlc(&tx, &maker_pub, time_lock, &secret_hash, &keypair)
                    .await
            );
            Ok(tx.into())
        };
        Box::new(fut.boxed().compat())
    }

    fn send_maker_refunds_payment(
        &self,
        maker_payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &[u8],
        secret_hash: &[u8],
        htlc_privkey: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        let tx = maker_payment_tx.to_owned();
        let taker_pub = try_fus!(Public::from_slice(taker_pub));
        let secret_hash = secret_hash.to_owned();
        let keypair = try_fus!(key_pair_from_secret(htlc_privkey));
        let coin = self.clone();

        let fut = async move {
            let tx = try_s!(
                coin.refund_htlc(&tx, &taker_pub, time_lock, &secret_hash, &keypair)
                    .await
            );
            Ok(tx.into())
        };
        Box::new(fut.boxed().compat())
    }

    fn validate_fee(
        &self,
        fee_tx: &TransactionEnum,
        expected_sender: &[u8],
        fee_addr: &[u8],
        amount: &BigDecimal,
        min_block_number: u64,
        _uuid: &[u8],
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        let tx = match fee_tx {
            TransactionEnum::UtxoTx(tx) => tx.clone(),
            _ => panic!(),
        };
        let coin = self.clone();
        let expected_sender = expected_sender.to_owned();
        let fee_addr = fee_addr.to_owned();
        let amount = amount.to_owned();

        let fut = async move {
            try_s!(
                coin.validate_dex_fee(tx, &expected_sender, &fee_addr, amount, min_block_number)
                    .await
            );
            Ok(())
        };
        Box::new(fut.boxed().compat())
    }

    fn validate_maker_payment(&self, input: ValidatePaymentInput) -> Box<dyn Future<Item = (), Error = String> + Send> {
        let maker_pub = try_fus!(Public::from_slice(&input.maker_pub));
        let taker_pub = try_fus!(Public::from_slice(&input.taker_pub));
        let tx = input.payment_tx.to_owned();
        let secret_hash = input.secret_hash.to_owned();
        let time_lock = input.time_lock;
        let amount = input.amount;
        let confirmations = input.confirmations;

        let coin = self.clone();
        let input = ValidateHtlcInput {
            tx,
            other_pub: maker_pub,
            my_pub: taker_pub,
            time_lock,
            secret_hash,
            amount,
            confirmations,
        };
        let fut = async move {
            try_s!(coin.validate_htlc(input).await);
            Ok(())
        };
        Box::new(fut.boxed().compat())
    }

    fn validate_taker_payment(&self, input: ValidatePaymentInput) -> Box<dyn Future<Item = (), Error = String> + Send> {
        let taker_pub = try_fus!(Public::from_slice(&input.taker_pub));
        let maker_pub = try_fus!(Public::from_slice(&input.maker_pub));
        let confirmations = input.confirmations;

        let coin = self.clone();
        let input = ValidateHtlcInput {
            tx: input.payment_tx,
            other_pub: taker_pub,
            my_pub: maker_pub,
            time_lock: input.time_lock,
            secret_hash: input.secret_hash,
            amount: input.amount,
            confirmations,
        };
        let fut = async move {
            try_s!(coin.validate_htlc(input).await);
            Ok(())
        };
        Box::new(fut.boxed().compat())
    }

    fn check_if_my_payment_sent(
        &self,
        time_lock: u32,
        my_pub: &[u8],
        other_pub: &[u8],
        secret_hash: &[u8],
        _search_from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Box<dyn Future<Item = Option<TransactionEnum>, Error = String> + Send> {
        utxo_common::check_if_my_payment_sent(self.platform_coin.clone(), time_lock, my_pub, other_pub, secret_hash)
    }

    async fn search_for_swap_tx_spend_my(
        &self,
        time_lock: u32,
        other_pub: &[u8],
        secret_hash: &[u8],
        tx: &[u8],
        search_from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        utxo_common::search_for_swap_tx_spend_my(
            self.platform_coin.as_ref(),
            time_lock,
            other_pub,
            secret_hash,
            tx,
            SLP_SWAP_VOUT,
            search_from_block,
        )
        .await
    }

    async fn search_for_swap_tx_spend_other(
        &self,
        time_lock: u32,
        other_pub: &[u8],
        secret_hash: &[u8],
        tx: &[u8],
        search_from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        utxo_common::search_for_swap_tx_spend_other(
            self.platform_coin.as_ref(),
            time_lock,
            other_pub,
            secret_hash,
            tx,
            SLP_SWAP_VOUT,
            search_from_block,
        )
        .await
    }

    fn extract_secret(&self, secret_hash: &[u8], spend_tx: &[u8]) -> Result<Vec<u8>, String> {
        utxo_common::extract_secret(secret_hash, spend_tx)
    }

    fn negotiate_swap_contract_addr(
        &self,
        _other_side_address: Option<&[u8]>,
    ) -> Result<Option<BytesJson>, MmError<NegotiateSwapContractAddrErr>> {
        Ok(None)
    }

    fn get_htlc_key_pair(&self) -> KeyPair { utxo_common::get_htlc_key_pair(&self.platform_coin) }
}

impl From<GenSlpSpendErr> for TradePreimageError {
    fn from(slp: GenSlpSpendErr) -> TradePreimageError {
        match slp {
            GenSlpSpendErr::InsufficientSlpBalance {
                coin,
                available,
                required,
            } => TradePreimageError::NotSufficientBalance {
                coin,
                available,
                required,
            },
            GenSlpSpendErr::RpcError(e) => e.into(),
            GenSlpSpendErr::TooManyOutputs | GenSlpSpendErr::InvalidSlpUtxos(_) => {
                TradePreimageError::InternalError(slp.to_string())
            },
            GenSlpSpendErr::Internal(internal) => TradePreimageError::InternalError(internal),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SlpFeeDetails {
    pub amount: BigDecimal,
    pub coin: String,
}

impl From<SlpFeeDetails> for TxFeeDetails {
    fn from(slp: SlpFeeDetails) -> TxFeeDetails { TxFeeDetails::Slp(slp) }
}

#[async_trait]
impl MmCoin for SlpToken {
    fn is_asset_chain(&self) -> bool { false }

    fn get_raw_transaction(&self, req: RawTransactionRequest) -> RawTransactionFut {
        Box::new(
            utxo_common::get_raw_transaction(self.platform_coin.as_ref(), req)
                .boxed()
                .compat(),
        )
    }

    fn withdraw(&self, req: WithdrawRequest) -> WithdrawFut {
        let coin = self.clone();
        let fut = async move {
            let my_address = coin.platform_coin.as_ref().derivation_method.iguana_or_err()?;
            let key_pair = coin.platform_coin.as_ref().priv_key_policy.key_pair_or_err()?;

            let address = CashAddress::decode(&req.to).map_to_mm(WithdrawError::InvalidAddress)?;
            if address.prefix != *coin.slp_prefix() {
                return MmError::err(WithdrawError::InvalidAddress(format!(
                    "Expected {} address prefix, not {}",
                    coin.slp_prefix(),
                    address.prefix
                )));
            };
            let amount = if req.max {
                coin.my_balance_sat().await?
            } else {
                sat_from_big_decimal(&req.amount, coin.decimals())?
            };

            if address.hash.len() != 20 {
                return MmError::err(WithdrawError::InvalidAddress(format!(
                    "Expected 20 address hash len, not {}",
                    address.hash.len()
                )));
            }

            // TODO clarify with community whether we should support withdrawal to SLP P2SH addresses
            let script_pubkey = match address.address_type {
                CashAddrType::P2PKH => {
                    ScriptBuilder::build_p2pkh(&AddressHashEnum::AddressHash(address.hash.as_slice().into())).to_bytes()
                },
                CashAddrType::P2SH => {
                    return MmError::err(WithdrawError::InvalidAddress(
                        "Withdrawal to P2SH is not supported".into(),
                    ))
                },
            };
            let slp_output = SlpOutput { amount, script_pubkey };
            let (slp_preimage, _) = coin.generate_slp_tx_preimage(vec![slp_output]).await?;
            let mut tx_builder = UtxoTxBuilder::new(&coin.platform_coin)
                .add_required_inputs(slp_preimage.slp_inputs.into_iter().map(|slp| slp.bch_unspent))
                .add_available_inputs(slp_preimage.available_bch_inputs)
                .add_outputs(slp_preimage.outputs);

            let platform_decimals = coin.platform_decimals();
            match req.fee {
                Some(WithdrawFee::UtxoFixed { amount }) => {
                    let fixed = sat_from_big_decimal(&amount, platform_decimals)?;
                    tx_builder = tx_builder.with_fee(ActualTxFee::FixedPerKb(fixed))
                },
                Some(WithdrawFee::UtxoPerKbyte { amount }) => {
                    let dynamic = sat_from_big_decimal(&amount, platform_decimals)?;
                    tx_builder = tx_builder.with_fee(ActualTxFee::Dynamic(dynamic));
                },
                Some(fee_policy) => {
                    let error = format!(
                        "Expected 'UtxoFixed' or 'UtxoPerKbyte' fee types, found {:?}",
                        fee_policy
                    );
                    return MmError::err(WithdrawError::InvalidFeePolicy(error));
                },
                None => (),
            };

            let (unsigned, tx_data) = tx_builder.build().await.mm_err(|gen_tx_error| {
                WithdrawError::from_generate_tx_error(gen_tx_error, coin.platform_ticker().into(), platform_decimals)
            })?;

            let prev_script = ScriptBuilder::build_p2pkh(&my_address.hash);
            let signed = sign_tx(
                unsigned,
                key_pair,
                prev_script,
                coin.platform_conf().signature_version,
                coin.platform_conf().fork_id,
            )?;
            let fee_details = SlpFeeDetails {
                amount: big_decimal_from_sat_unsigned(tx_data.fee_amount, coin.platform_decimals()),
                coin: coin.platform_coin.ticker().into(),
            };
            let my_address_string = coin.my_address().map_to_mm(WithdrawError::InternalError)?;
            let to_address = address.encode().map_to_mm(WithdrawError::InternalError)?;

            let total_amount = big_decimal_from_sat_unsigned(amount, coin.decimals());
            let spent_by_me = total_amount.clone();
            let (received_by_me, my_balance_change) = if my_address_string == to_address {
                (total_amount.clone(), 0.into())
            } else {
                (0.into(), &total_amount * &BigDecimal::from(-1))
            };

            let tx_hash: BytesJson = signed.hash().reversed().take().to_vec().into();
            let details = TransactionDetails {
                tx_hex: serialize(&signed).into(),
                internal_id: tx_hash.clone(),
                tx_hash: tx_hash.to_tx_hash(),
                from: vec![my_address_string],
                to: vec![to_address],
                total_amount,
                spent_by_me,
                received_by_me,
                my_balance_change,
                block_height: 0,
                timestamp: now_ms() / 1000,
                fee_details: Some(fee_details.into()),
                coin: coin.ticker().into(),
                kmd_rewards: None,
                transaction_type: Default::default(),
            };
            Ok(details)
        };
        Box::new(fut.boxed().compat())
    }

    fn decimals(&self) -> u8 { self.decimals() }

    fn convert_to_address(&self, from: &str, to_address_format: Json) -> Result<String, String> {
        utxo_common::convert_to_address(&self.platform_coin, from, to_address_format)
    }

    fn validate_address(&self, address: &str) -> ValidateAddressResult {
        let cash_address = match CashAddress::decode(address) {
            Ok(a) => a,
            Err(e) => {
                return ValidateAddressResult {
                    is_valid: false,
                    reason: Some(format!("Error {} on parsing the {} as cash address", e, address)),
                }
            },
        };

        if cash_address.prefix == *self.slp_prefix() {
            ValidateAddressResult {
                is_valid: true,
                reason: None,
            }
        } else {
            ValidateAddressResult {
                is_valid: false,
                reason: Some(format!(
                    "Address {} has invalid prefix {}, expected {}",
                    address,
                    cash_address.prefix,
                    self.slp_prefix()
                )),
            }
        }
    }

    fn process_history_loop(&self, _ctx: MmArc) -> Box<dyn Future<Item = (), Error = ()> + Send> {
        warn!("process_history_loop is not implemented for SLP yet!");
        Box::new(futures01::future::err(()))
    }

    fn history_sync_status(&self) -> HistorySyncState { self.platform_coin.history_sync_status() }

    /// Get fee to be paid per 1 swap transaction
    fn get_trade_fee(&self) -> Box<dyn Future<Item = TradeFee, Error = String> + Send> {
        utxo_common::get_trade_fee(self.platform_coin.clone())
    }

    async fn get_sender_trade_fee(
        &self,
        value: TradePreimageValue,
        stage: FeeApproxStage,
    ) -> TradePreimageResult<TradeFee> {
        let slp_amount = match value {
            TradePreimageValue::Exact(decimal) | TradePreimageValue::UpperBound(decimal) => {
                sat_from_big_decimal(&decimal, self.decimals())?
            },
        };
        // can use dummy P2SH script_pubkey here
        let script_pubkey = ScriptBuilder::build_p2sh(&H160::default().into()).into();
        let slp_out = SlpOutput {
            amount: slp_amount,
            script_pubkey,
        };
        let (preimage, _) = self.generate_slp_tx_preimage(vec![slp_out]).await?;
        let fee = utxo_common::preimage_trade_fee_required_to_send_outputs(
            &self.platform_coin,
            preimage.outputs,
            FeePolicy::SendExact,
            None,
            &stage,
        )
        .await?;
        Ok(TradeFee {
            coin: self.platform_coin.ticker().into(),
            amount: fee.into(),
            paid_from_trading_vol: false,
        })
    }

    fn get_receiver_trade_fee(&self, _stage: FeeApproxStage) -> TradePreimageFut<TradeFee> {
        let coin = self.clone();

        let fut = async move {
            let htlc_fee = coin.platform_coin.get_htlc_spend_fee(SLP_HTLC_SPEND_SIZE).await?;
            let amount =
                (big_decimal_from_sat_unsigned(htlc_fee, coin.platform_decimals()) + coin.platform_dust_dec()).into();
            Ok(TradeFee {
                coin: coin.platform_coin.ticker().into(),
                amount,
                paid_from_trading_vol: false,
            })
        };

        Box::new(fut.boxed().compat())
    }

    async fn get_fee_to_send_taker_fee(
        &self,
        dex_fee_amount: BigDecimal,
        stage: FeeApproxStage,
    ) -> TradePreimageResult<TradeFee> {
        let slp_amount = sat_from_big_decimal(&dex_fee_amount, self.decimals())?;
        // can use dummy P2PKH script_pubkey here
        let script_pubkey = ScriptBuilder::build_p2pkh(&H160::default().into()).into();
        let slp_out = SlpOutput {
            amount: slp_amount,
            script_pubkey,
        };
        let (preimage, _) = self.generate_slp_tx_preimage(vec![slp_out]).await?;
        let fee = utxo_common::preimage_trade_fee_required_to_send_outputs(
            &self.platform_coin,
            preimage.outputs,
            FeePolicy::SendExact,
            None,
            &stage,
        )
        .await?;
        Ok(TradeFee {
            coin: self.platform_coin.ticker().into(),
            amount: fee.into(),
            paid_from_trading_vol: false,
        })
    }

    fn required_confirmations(&self) -> u64 { self.conf.required_confirmations.load(AtomicOrdering::Relaxed) }

    fn requires_notarization(&self) -> bool { false }

    fn set_required_confirmations(&self, confirmations: u64) {
        self.conf
            .required_confirmations
            .store(confirmations, AtomicOrdering::Relaxed);
    }

    fn set_requires_notarization(&self, _requires_nota: bool) {
        warn!("set_requires_notarization has no effect on SLPTOKEN!")
    }

    fn swap_contract_address(&self) -> Option<BytesJson> { None }

    fn mature_confirmations(&self) -> Option<u32> { self.platform_coin.mature_confirmations() }

    fn coin_protocol_info(&self) -> Vec<u8> { Vec::new() }

    fn is_coin_protocol_supported(&self, _info: &Option<Vec<u8>>) -> bool { true }
}

#[derive(Debug, Display)]
pub enum SlpAddrFromPubkeyErr {
    InvalidHex(hex::FromHexError),
    CashAddrError(String),
    EncodeError(String),
}

impl From<hex::FromHexError> for SlpAddrFromPubkeyErr {
    fn from(err: FromHexError) -> SlpAddrFromPubkeyErr { SlpAddrFromPubkeyErr::InvalidHex(err) }
}

pub fn slp_addr_from_pubkey_str(pubkey: &str, prefix: &str) -> Result<String, MmError<SlpAddrFromPubkeyErr>> {
    let pubkey_bytes = hex::decode(pubkey)?;
    let hash = dhash160(&pubkey_bytes);
    let addr =
        CashAddress::new(prefix, hash.to_vec(), CashAddrType::P2PKH).map_to_mm(SlpAddrFromPubkeyErr::CashAddrError)?;
    addr.encode().map_to_mm(SlpAddrFromPubkeyErr::EncodeError)
}

#[cfg(test)]
mod slp_tests {
    use super::*;
    use crate::utxo::bch::tbch_coin_for_test;
    use common::block_on;

    // https://slp.dev/specs/slp-token-type-1/#examples
    #[test]
    fn test_parse_slp_script() {
        // Send single output
        let script = hex::decode("6a04534c500001010453454e4420e73b2b28c14db8ebbf97749988b539508990e1708021067f206f49d55807dbf4080000000005f5e100").unwrap();
        let slp_data = parse_slp_script(&script).unwrap();
        assert_eq!(slp_data.lokad_id, "SLP\0");
        let expected_amount = 100000000u64;
        let expected_transaction = SlpTransaction::Send {
            token_id: "e73b2b28c14db8ebbf97749988b539508990e1708021067f206f49d55807dbf4".into(),
            amounts: vec![expected_amount],
        };

        assert_eq!(expected_transaction, slp_data.transaction);

        // Genesis
        let script =
            hex::decode("6a04534c500001010747454e45534953044144455804414445584c004c0001084c0008000000174876e800")
                .unwrap();
        let slp_data = parse_slp_script(&script).unwrap();
        assert_eq!(slp_data.lokad_id, "SLP\0");
        let initial_token_mint_quantity = 1000_0000_0000u64;
        let expected_transaction = SlpTransaction::Genesis(SlpGenesisParams {
            token_ticker: "ADEX".to_string(),
            token_name: "ADEX".to_string(),
            token_document_url: "".to_string(),
            token_document_hash: vec![],
            decimals: vec![8],
            mint_baton_vout: None,
            initial_token_mint_quantity,
        });

        assert_eq!(expected_transaction, slp_data.transaction);

        // Genesis from docs example
        let script =
            hex::decode("6a04534c500001010747454e45534953045553445423546574686572204c74642e20555320646f6c6c6172206261636b656420746f6b656e734168747470733a2f2f7465746865722e746f2f77702d636f6e74656e742f75706c6f6164732f323031362f30362f546574686572576869746550617065722e70646620db4451f11eda33950670aaf59e704da90117ff7057283b032cfaec77793139160108010208002386f26fc10000").unwrap();
        let slp_data = parse_slp_script(&script).unwrap();
        assert_eq!(slp_data.lokad_id, "SLP\0");
        let initial_token_mint_quantity = 10000000000000000u64;
        let expected_transaction = SlpTransaction::Genesis(SlpGenesisParams {
            token_ticker: "USDT".to_string(),
            token_name: "Tether Ltd. US dollar backed tokens".to_string(),
            token_document_url: "https://tether.to/wp-content/uploads/2016/06/TetherWhitePaper.pdf".to_string(),
            token_document_hash: hex::decode("db4451f11eda33950670aaf59e704da90117ff7057283b032cfaec7779313916")
                .unwrap(),
            decimals: vec![8],
            mint_baton_vout: Some(2),
            initial_token_mint_quantity,
        });

        assert_eq!(expected_transaction, slp_data.transaction);

        // Mint
        let script =
            hex::decode("6a04534c50000101044d494e5420550d19eb820e616a54b8a73372c4420b5a0567d8dc00f613b71c5234dc884b35010208002386f26fc10000").unwrap();
        let slp_data = parse_slp_script(&script).unwrap();
        assert_eq!(slp_data.lokad_id, "SLP\0");
        let expected_transaction = SlpTransaction::Mint {
            token_id: "550d19eb820e616a54b8a73372c4420b5a0567d8dc00f613b71c5234dc884b35".into(),
            mint_baton_vout: Some(2),
            additional_token_quantity: 10000000000000000,
        };

        assert_eq!(expected_transaction, slp_data.transaction);

        // SEND with 3 outputs
        let script = hex::decode("6a04534c500001010453454e4420550d19eb820e616a54b8a73372c4420b5a0567d8dc00f613b71c5234dc884b350800000000000003e80800000000000003e90800000000000003ea").unwrap();
        let token_id = "550d19eb820e616a54b8a73372c4420b5a0567d8dc00f613b71c5234dc884b35".into();

        let slp_data = parse_slp_script(&script).unwrap();
        assert_eq!(slp_data.lokad_id, "SLP\0");
        let expected_transaction = SlpTransaction::Send {
            token_id,
            amounts: vec![1000, 1001, 1002],
        };
        assert_eq!(expected_transaction, slp_data.transaction);

        // NFT Genesis, unsupported token type
        // https://explorer.bitcoin.com/bch/tx/3dc17770ff832726aace53d305e087601d8b27cf881089d7849173736995f43e
        let script = hex::decode("6a04534c500001410747454e45534953055357454443174573736b65657469742043617264204e6f2e20313136302b68747470733a2f2f636f6c6c65637469626c652e73776565742e696f2f7365726965732f35382f313136302040f8d39b6fc8725d9c766d66643d8ec644363ba32391c1d9a89a3edbdea8866a01004c00080000000000000001").unwrap();

        let actual_err = parse_slp_script(&script).unwrap_err().into_inner();
        let expected_err = ParseSlpScriptError::UnexpectedTokenType(vec![0x41]);
        assert_eq!(expected_err, actual_err);
    }

    #[test]
    fn test_slp_send_output() {
        // Send single output
        let expected_script = hex::decode("6a04534c500001010453454e4420e73b2b28c14db8ebbf97749988b539508990e1708021067f206f49d55807dbf4080000000005f5e100").unwrap();
        let expected_output = TransactionOutput {
            value: 0,
            script_pubkey: expected_script.into(),
        };

        let actual_output = slp_send_output(
            &"e73b2b28c14db8ebbf97749988b539508990e1708021067f206f49d55807dbf4".into(),
            &[100000000],
        );

        assert_eq!(expected_output, actual_output);

        let expected_script = hex::decode("6a04534c500001010453454e4420550d19eb820e616a54b8a73372c4420b5a0567d8dc00f613b71c5234dc884b350800005af3107a40000800232bff5f46c000").unwrap();
        let expected_output = TransactionOutput {
            value: 0,
            script_pubkey: expected_script.into(),
        };

        let actual_output = slp_send_output(
            &"550d19eb820e616a54b8a73372c4420b5a0567d8dc00f613b71c5234dc884b35".into(),
            &[100000000000000, 9900000000000000],
        );

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn test_slp_genesis_output() {
        let expected_script =
            hex::decode("6a04534c500001010747454e45534953044144455804414445584c004c0001084c0008000000174876e800")
                .unwrap();
        let expected_output = TransactionOutput {
            value: 0,
            script_pubkey: expected_script.into(),
        };

        let actual_output = slp_genesis_output("ADEX", "ADEX", None, None, 8, None, 1000_0000_0000);
        assert_eq!(expected_output, actual_output);

        let expected_script =
            hex::decode("6a04534c500001010747454e45534953045553445423546574686572204c74642e20555320646f6c6c6172206261636b656420746f6b656e734168747470733a2f2f7465746865722e746f2f77702d636f6e74656e742f75706c6f6164732f323031362f30362f546574686572576869746550617065722e70646620db4451f11eda33950670aaf59e704da90117ff7057283b032cfaec77793139160108010208002386f26fc10000")
                .unwrap();
        let expected_output = TransactionOutput {
            value: 0,
            script_pubkey: expected_script.into(),
        };

        let actual_output = slp_genesis_output(
            "USDT",
            "Tether Ltd. US dollar backed tokens",
            Some("https://tether.to/wp-content/uploads/2016/06/TetherWhitePaper.pdf"),
            Some("db4451f11eda33950670aaf59e704da90117ff7057283b032cfaec7779313916".into()),
            8,
            Some(2),
            10000000000000000,
        );
        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn test_slp_address() {
        let bch = tbch_coin_for_test();
        let token_id = H256::from("bb309e48930671582bea508f9a1d9b491e49b69be3d6f372dc08da2ac6e90eb7");
        let fusd = SlpToken::new(4, "FUSD".into(), token_id, bch, 0);

        let slp_address = fusd.my_address().unwrap();
        assert_eq!("slptest:qzx0llpyp8gxxsmad25twksqnwd62xm3lsg8lecug8", slp_address);
    }

    #[test]
    fn test_validate_htlc_valid() {
        let bch = tbch_coin_for_test();
        let token_id = H256::from("bb309e48930671582bea508f9a1d9b491e49b69be3d6f372dc08da2ac6e90eb7");
        let fusd = SlpToken::new(4, "FUSD".into(), token_id, bch, 0);

        // https://testnet.simpleledger.info/tx/e935160bfb5b45007a0fc6f8fbe8da618f28df6573731f1ffb54d9560abb49b2
        let tx = hex::decode("0100000002736cf584f877ec7b6b95974bc461a9cfb9f126655b5d335471683154cc6cf4c5020000006a47304402206be99fe56a98e7a8c2ffe6f2d05c5c1f46a6577064b84d27d45fe0e959f6e77402201c512629313b48cd4df873222aa49046ae9a3a6e34e359d10d4308cb40438fba4121036879df230663db4cd083c8eeb0f293f46abc460ad3c299b0089b72e6d472202cffffffff736cf584f877ec7b6b95974bc461a9cfb9f126655b5d335471683154cc6cf4c5030000006a473044022020d774d045bbe3dce5b04af836f6a5629c6c4ce75b0b5ba8a1da0ae9a4ecc0530220522f86d20c9e4142e40f9a9c8d25db16fde91d4a0ad6f6ff2107e201386131b64121036879df230663db4cd083c8eeb0f293f46abc460ad3c299b0089b72e6d472202cffffffff040000000000000000406a04534c500001010453454e4420bb309e48930671582bea508f9a1d9b491e49b69be3d6f372dc08da2ac6e90eb70800000000000003e8080000000000001f3ee80300000000000017a914b0ca1fea17cf522c7e858416093fc6d95e55824087e8030000000000001976a9148cfffc2409d063437d6aa8b75a009b9ba51b71fc88accf614801000000001976a9148cfffc2409d063437d6aa8b75a009b9ba51b71fc88ac8c83d460").unwrap();

        let other_pub = hex::decode("036879df230663db4cd083c8eeb0f293f46abc460ad3c299b0089b72e6d472202c").unwrap();
        let other_pub = Public::from_slice(&other_pub).unwrap();

        let my_pub = hex::decode("03c6a78589e18b482aea046975e6d0acbdea7bf7dbf04d9d5bd67fda917815e3ed").unwrap();
        let my_pub = Public::from_slice(&my_pub).unwrap();

        let lock_time = 1624547837;
        let secret_hash = hex::decode("5d9e149ad9ccb20e9f931a69b605df2ffde60242").unwrap();
        let amount: BigDecimal = "0.1".parse().unwrap();
        let input = ValidateHtlcInput {
            tx,
            other_pub,
            my_pub,
            time_lock: lock_time,
            secret_hash,
            amount,
            confirmations: 1,
        };
        block_on(fusd.validate_htlc(input)).unwrap();
    }

    #[test]
    fn construct_and_send_invalid_slp_htlc_should_fail() {
        let bch = tbch_coin_for_test();
        let token_id = H256::from("bb309e48930671582bea508f9a1d9b491e49b69be3d6f372dc08da2ac6e90eb7");
        let fusd = SlpToken::new(4, "FUSD".into(), token_id, bch.clone(), 0);

        let bch_address = bch.as_ref().derivation_method.unwrap_iguana();
        let (unspents, recently_spent) = block_on(bch.list_unspent_ordered(bch_address)).unwrap();

        let secret_hash = hex::decode("5d9e149ad9ccb20e9f931a69b605df2ffde60242").unwrap();
        let other_pub = hex::decode("036879df230663db4cd083c8eeb0f293f46abc460ad3c299b0089b72e6d472202c").unwrap();
        let other_pub = Public::from_slice(&other_pub).unwrap();

        let my_public_key = bch.my_public_key().unwrap();
        let htlc_script = payment_script(1624547837, &secret_hash, &other_pub, my_public_key);

        let slp_send_op_return_out = slp_send_output(&token_id, &[1000]);

        let invalid_slp_send_out = TransactionOutput {
            value: 1000,
            script_pubkey: ScriptBuilder::build_p2sh(&dhash160(&htlc_script).into()).into(),
        };

        let err = block_on(generate_and_send_tx(
            &fusd,
            unspents,
            None,
            FeePolicy::SendExact,
            recently_spent,
            vec![slp_send_op_return_out, invalid_slp_send_out],
        ))
        .unwrap_err();
        println!("{:?}", err);
        assert!(err.contains("is not valid with reason outputs greater than inputs"));

        // this is invalid tx bytes generated by one of this test runs, ensure that FUSD won't broadcast it using
        // different methods
        let tx_bytes: &[u8] = &[
            1, 0, 0, 0, 1, 105, 91, 221, 196, 250, 138, 113, 118, 165, 149, 181, 70, 15, 224, 124, 67, 133, 237, 31,
            88, 125, 178, 69, 166, 27, 211, 32, 54, 1, 238, 134, 102, 2, 0, 0, 0, 106, 71, 48, 68, 2, 32, 103, 105,
            238, 187, 198, 194, 7, 162, 250, 17, 240, 45, 93, 168, 223, 35, 92, 23, 84, 70, 193, 234, 183, 130, 114,
            49, 198, 118, 69, 22, 128, 118, 2, 32, 127, 44, 73, 98, 217, 254, 44, 181, 87, 175, 114, 138, 223, 173,
            201, 168, 38, 198, 49, 23, 9, 101, 50, 154, 55, 236, 126, 253, 37, 114, 111, 218, 65, 33, 3, 104, 121, 223,
            35, 6, 99, 219, 76, 208, 131, 200, 238, 176, 242, 147, 244, 106, 188, 70, 10, 211, 194, 153, 176, 8, 155,
            114, 230, 212, 114, 32, 44, 255, 255, 255, 255, 3, 0, 0, 0, 0, 0, 0, 0, 0, 55, 106, 4, 83, 76, 80, 0, 1, 1,
            4, 83, 69, 78, 68, 32, 187, 48, 158, 72, 147, 6, 113, 88, 43, 234, 80, 143, 154, 29, 155, 73, 30, 73, 182,
            155, 227, 214, 243, 114, 220, 8, 218, 42, 198, 233, 14, 183, 8, 0, 0, 0, 0, 0, 0, 3, 232, 232, 3, 0, 0, 0,
            0, 0, 0, 23, 169, 20, 149, 59, 57, 9, 255, 106, 162, 105, 248, 93, 163, 76, 19, 42, 146, 66, 68, 64, 225,
            142, 135, 205, 228, 173, 0, 0, 0, 0, 0, 25, 118, 169, 20, 140, 255, 252, 36, 9, 208, 99, 67, 125, 106, 168,
            183, 90, 0, 155, 155, 165, 27, 113, 252, 136, 172, 216, 36, 92, 97,
        ];
        let tx_bytes_str = hex::encode(tx_bytes);

        let err = fusd.send_raw_tx(&tx_bytes_str).wait().unwrap_err();
        println!("{:?}", err);
        assert!(err.contains("is not valid with reason outputs greater than inputs"));

        let utxo_tx: UtxoTx = deserialize(tx_bytes).unwrap();
        let err = block_on(fusd.broadcast_tx(&utxo_tx)).unwrap_err();
        match err.into_inner() {
            BroadcastTxErr::Other(err) => assert!(err.contains("is not valid with reason outputs greater than inputs")),
            e @ _ => panic!("Unexpected err {:?}", e),
        };
    }

    #[test]
    fn test_validate_htlc_invalid_slp_utxo() {
        let bch = tbch_coin_for_test();
        let token_id = H256::from("bb309e48930671582bea508f9a1d9b491e49b69be3d6f372dc08da2ac6e90eb7");
        let fusd = SlpToken::new(4, "FUSD".into(), token_id, bch.clone(), 0);

        // https://www.blockchain.com/ru/bch-testnet/tx/6686ee013620d31ba645b27d581fed85437ce00f46b595a576718afac4dd5b69
        let tx = hex::decode("0100000001ce59a734f33811afcc00c19dcb12202ed00067a50efed80424fabd2b723678c0020000006b483045022100ec1fecff9c60fb7e821b9a412bd8c4ce4a757c68287f9cf9e0f461165492d6530220222f020dd05d65ba35cddd0116c99255612ec90d63019bb1cea45e2cf09a62a94121036879df230663db4cd083c8eeb0f293f46abc460ad3c299b0089b72e6d472202cffffffff030000000000000000376a04534c500001010453454e4420bb309e48930671582bea508f9a1d9b491e49b69be3d6f372dc08da2ac6e90eb70800000000000003e8e80300000000000017a914953b3909ff6aa269f85da34c132a92424440e18e879decad00000000001976a9148cfffc2409d063437d6aa8b75a009b9ba51b71fc88acd1215c61").unwrap();

        let other_pub = hex::decode("036879df230663db4cd083c8eeb0f293f46abc460ad3c299b0089b72e6d472202c").unwrap();
        let other_pub = Public::from_slice(&other_pub).unwrap();

        let lock_time = 1624547837;
        let secret_hash = hex::decode("5d9e149ad9ccb20e9f931a69b605df2ffde60242").unwrap();
        let amount: BigDecimal = "0.1".parse().unwrap();
        let my_pub = bch.my_public_key().unwrap();

        // standard BCH validation should pass as the output itself is correct
        utxo_common::validate_payment(
            bch.clone(),
            deserialize(tx.as_slice()).unwrap(),
            SLP_SWAP_VOUT,
            my_pub,
            &other_pub,
            &secret_hash,
            fusd.platform_dust_dec(),
            lock_time,
            1,
        )
        .wait()
        .unwrap();

        let input = ValidateHtlcInput {
            tx,
            other_pub,
            my_pub: my_pub.clone(),
            time_lock: lock_time,
            secret_hash,
            amount,
            confirmations: 1,
        };
        let validity_err = block_on(fusd.validate_htlc(input)).unwrap_err();
        match validity_err.into_inner() {
            ValidateHtlcError::InvalidSlpUtxo(e) => println!("{:?}", e),
            err @ _ => panic!("Unexpected err {:?}", err),
        };
    }
}
