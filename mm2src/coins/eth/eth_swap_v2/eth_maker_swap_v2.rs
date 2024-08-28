use crate::coin_errors::ValidatePaymentResult;
use crate::eth::eth_swap_v2::{PrepareTxDataError, ZERO_VALUE};
use crate::eth::{wei_from_big_decimal, EthCoin, EthCoinType, SignedEthTx, TAKER_SWAP_V2};
use crate::{RefundMakerPaymentSecretArgs, RefundMakerPaymentTimelockArgs, SendMakerPaymentArgs, SpendMakerPaymentArgs,
            Transaction, TransactionErr, ValidateMakerPaymentArgs};
use ethabi::Token;
use ethcore_transaction::Action;
use ethereum_types::{Address, U256};
use ethkey::public_to_address;
use futures::compat::Future01CompatExt;
use std::convert::TryInto;

const ETH_MAKER_PAYMENT: &str = "ethMakerPayment";
const ERC20_MAKER_PAYMENT: &str = "erc20MakerPayment";

struct MakerPaymentArgs {
    taker_address: Address,
    taker_secret_hash: [u8; 32],
    maker_secret_hash: [u8; 32],
    payment_time_lock: u64,
}

impl EthCoin {
    pub(crate) async fn send_maker_payment_v2_impl(
        &self,
        args: SendMakerPaymentArgs<'_, Self>,
    ) -> Result<SignedEthTx, TransactionErr> {
        let maker_swap_v2_contract = self
            .swap_v2_contracts
            .as_ref()
            .map(|contracts| contracts.maker_swap_v2_contract)
            .ok_or_else(|| TransactionErr::Plain(ERRL!("Expected swap_v2_contracts to be Some, but found None")))?;
        let payment_amount = try_tx_s!(wei_from_big_decimal(&args.amount, self.decimals));
        let payment_args = {
            let taker_address = public_to_address(args.taker_pub);
            MakerPaymentArgs {
                taker_address,
                taker_secret_hash: try_tx_s!(args.taker_secret_hash.try_into()),
                maker_secret_hash: try_tx_s!(args.maker_secret_hash.try_into()),
                payment_time_lock: args.time_lock,
            }
        };
        match &self.coin_type {
            EthCoinType::Eth => {
                let data = try_tx_s!(self.prepare_maker_eth_payment_data(&payment_args).await);
                self.sign_and_send_transaction(
                    payment_amount,
                    Action::Call(maker_swap_v2_contract),
                    data,
                    // TODO need new consts and params for v2 calls. now it uses v1
                    U256::from(self.gas_limit.eth_payment),
                )
                .compat()
                .await
            },
            EthCoinType::Erc20 {
                platform: _,
                token_addr,
            } => {
                let allowed = self
                    .allowance(maker_swap_v2_contract)
                    .compat()
                    .await
                    .map_err(|e| TransactionErr::Plain(ERRL!("{}", e)))?;
                let data = try_tx_s!(
                    self.prepare_maker_erc20_payment_data(&payment_args, payment_amount, *token_addr)
                        .await
                );
                if allowed < payment_amount {
                    let approved_tx = self.approve(maker_swap_v2_contract, U256::max_value()).compat().await?;
                    self.wait_for_required_allowance(maker_swap_v2_contract, payment_amount, args.time_lock)
                        .compat()
                        .await
                        .map_err(|e| {
                            TransactionErr::Plain(ERRL!(
                                "Allowed value was not updated in time after sending approve transaction {:02x}: {}",
                                approved_tx.tx_hash_as_bytes(),
                                e
                            ))
                        })?;
                }
                self.sign_and_send_transaction(
                    U256::from(ZERO_VALUE),
                    Action::Call(maker_swap_v2_contract),
                    data,
                    // TODO need new consts and params for v2 calls. now it uses v1
                    U256::from(self.gas_limit.erc20_payment),
                )
                .compat()
                .await
            },
            EthCoinType::Nft { .. } => Err(TransactionErr::ProtocolNotSupported(ERRL!(
                "NFT protocol is not supported for ETH and ERC20 Swaps"
            ))),
        }
    }

    pub(crate) async fn validate_maker_payment_v2_impl(
        &self,
        _args: ValidateMakerPaymentArgs<'_, Self>,
    ) -> ValidatePaymentResult<()> {
        todo!()
    }

    pub(crate) async fn refund_maker_payment_v2_timelock_impl(
        &self,
        _args: RefundMakerPaymentTimelockArgs<'_>,
    ) -> Result<SignedEthTx, TransactionErr> {
        todo!()
    }

    pub(crate) async fn refund_maker_payment_v2_secret_impl(
        &self,
        _args: RefundMakerPaymentSecretArgs<'_, Self>,
    ) -> Result<SignedEthTx, TransactionErr> {
        todo!()
    }

    pub(crate) async fn spend_maker_payment_v2_impl(
        &self,
        _args: SpendMakerPaymentArgs<'_, Self>,
    ) -> Result<SignedEthTx, TransactionErr> {
        todo!()
    }

    /// Prepares data for EtomicSwapMakerV2 contract [ethMakerPayment](https://github.com/KomodoPlatform/etomic-swap/blob/5e15641cbf41766cd5b37b4d71842c270773f788/contracts/EtomicSwapMakerV2.sol#L30) method
    async fn prepare_maker_eth_payment_data(&self, args: &MakerPaymentArgs) -> Result<Vec<u8>, PrepareTxDataError> {
        let function = TAKER_SWAP_V2.function(ETH_MAKER_PAYMENT)?;
        let id = self.etomic_swap_id_v2(args.payment_time_lock, &args.maker_secret_hash);
        let data = function.encode_input(&[
            Token::FixedBytes(id),
            Token::Address(args.taker_address),
            Token::FixedBytes(args.taker_secret_hash.to_vec()),
            Token::FixedBytes(args.maker_secret_hash.to_vec()),
            Token::Uint(args.payment_time_lock.into()),
        ])?;
        Ok(data)
    }

    /// Prepares data for EtomicSwapMakerV2 contract [erc20MakerPayment](https://github.com/KomodoPlatform/etomic-swap/blob/5e15641cbf41766cd5b37b4d71842c270773f788/contracts/EtomicSwapMakerV2.sol#L64) method
    async fn prepare_maker_erc20_payment_data(
        &self,
        args: &MakerPaymentArgs,
        payment_amount: U256,
        token_address: Address,
    ) -> Result<Vec<u8>, PrepareTxDataError> {
        let function = TAKER_SWAP_V2.function(ERC20_MAKER_PAYMENT)?;
        let id = self.etomic_swap_id_v2(args.payment_time_lock, &args.maker_secret_hash);
        let data = function.encode_input(&[
            Token::FixedBytes(id),
            Token::Uint(payment_amount),
            Token::Address(token_address),
            Token::Address(args.taker_address),
            Token::FixedBytes(args.taker_secret_hash.to_vec()),
            Token::FixedBytes(args.maker_secret_hash.to_vec()),
            Token::Uint(args.payment_time_lock.into()),
        ])?;
        Ok(data)
    }
}
