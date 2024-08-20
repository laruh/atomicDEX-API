use enum_derives::EnumFromStringify;
use ethcore_transaction::SignedTransaction as SignedEthTx;
use ethereum_types::{Address, U256};
use mm2_err_handle::mm_error::MmError;
use web3::types::Transaction as Web3Tx;

pub(crate) mod eth_taker_swap_v2;

/// ZERO_VALUE is used to represent a 0 amount in transactions where the value is encoded in the transaction input data.
/// This is typically used in function calls where the value is not directly transferred with the transaction, such as in
/// `spendTakerPayment` where the [amount](https://github.com/KomodoPlatform/etomic-swap/blob/5e15641cbf41766cd5b37b4d71842c270773f788/contracts/EtomicSwapTakerV2.sol#L166)
/// is provided as part of the input data rather than as an Ether value
pub(crate) const ZERO_VALUE: u32 = 0;

pub(crate) enum EthPaymentType {
    MakerPayments,
    TakerPayments,
}

impl EthPaymentType {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            EthPaymentType::MakerPayments => "makerPayments",
            EthPaymentType::TakerPayments => "takerPayments",
        }
    }
}

#[derive(Debug, Display)]
pub(crate) enum ValidatePaymentV2Err {
    UnexpectedPaymentState(String),
    WrongPaymentTx(String),
}

#[derive(Debug, Display, EnumFromStringify)]
pub(crate) enum PaymentStatusErr {
    #[from_stringify("ethabi::Error")]
    #[display(fmt = "ABI error: {}", _0)]
    ABIError(String),
    #[from_stringify("web3::Error")]
    #[display(fmt = "Transport error: {}", _0)]
    Transport(String),
    #[display(fmt = "Internal error: {}", _0)]
    Internal(String),
    #[display(fmt = "Invalid data error: {}", _0)]
    InvalidData(String),
}

#[derive(Debug, Display, EnumFromStringify)]
pub(crate) enum PrepareTxDataError {
    #[from_stringify("ethabi::Error")]
    #[display(fmt = "ABI error: {}", _0)]
    ABIError(String),
    #[display(fmt = "Internal error: {}", _0)]
    Internal(String),
}

pub(crate) fn validate_payment_state(
    tx: &SignedEthTx,
    state: U256,
    expected_state: u8,
) -> Result<(), PrepareTxDataError> {
    if state != U256::from(expected_state) {
        return Err(PrepareTxDataError::Internal(format!(
            "Payment {:?} state is not `{}`, got `{}`",
            tx, expected_state, state
        )));
    }
    Ok(())
}

pub(crate) fn validate_from_to_and_status(
    tx_from_rpc: &Web3Tx,
    expected_from: Address,
    expected_to: Address,
    status: U256,
    expected_status: u8,
) -> Result<(), MmError<ValidatePaymentV2Err>> {
    if status != U256::from(expected_status) {
        return MmError::err(ValidatePaymentV2Err::UnexpectedPaymentState(format!(
            "Payment state is not `PaymentSent`, got {}",
            status
        )));
    }
    if tx_from_rpc.from != Some(expected_from) {
        return MmError::err(ValidatePaymentV2Err::WrongPaymentTx(format!(
            "Payment tx {:?} was sent from wrong address, expected {:?}",
            tx_from_rpc, expected_from
        )));
    }
    // (in NFT case) as NFT owner calls "safeTransferFrom" directly, then in Transaction 'to' field we expect token_address
    if tx_from_rpc.to != Some(expected_to) {
        return MmError::err(ValidatePaymentV2Err::WrongPaymentTx(format!(
            "Payment tx {:?} was sent to wrong address, expected {:?}",
            tx_from_rpc, expected_to,
        )));
    }
    Ok(())
}
