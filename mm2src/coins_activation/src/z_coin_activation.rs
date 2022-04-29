use crate::context::CoinsActivationContext;
use crate::prelude::*;
use crate::standalone_coin::{InitStandaloneCoinActivationOps, InitStandaloneCoinError,
                             InitStandaloneCoinInitialStatus, InitStandaloneCoinTaskHandle,
                             InitStandaloneCoinTaskManagerShared};
use async_trait::async_trait;
use coins::coin_balance::{EnableCoinBalance, IguanaWalletBalance};
use coins::z_coin::{z_coin_from_conf_and_params, ZCoin, ZCoinBuildError, ZcoinActivationParams};
use coins::{BalanceError, CoinProtocol, MarketCoinOps, PrivKeyBuildPolicy, RegisterCoinError};
use common::executor::Timer;
use common::mm_ctx::MmArc;
use common::mm_error::prelude::*;
use crypto::hw_rpc_task::{HwRpcTaskAwaitingStatus, HwRpcTaskUserAction};
use derive_more::Display;
use futures::compat::Future01CompatExt;
use rpc_task::RpcTaskError;
use ser_error_derive::SerializeErrorType;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value as Json;
use std::time::Duration;

pub type ZcoinTaskManagerShared = InitStandaloneCoinTaskManagerShared<ZCoin>;
pub type ZcoinRpcTaskHandle = InitStandaloneCoinTaskHandle<ZCoin>;
pub type ZcoinAwaitingStatus = HwRpcTaskAwaitingStatus;
pub type ZcoinUserAction = HwRpcTaskUserAction;

#[derive(Clone, Serialize)]
pub struct ZcoinActivationResult {
    pub current_block: u64,
    pub wallet_balance: EnableCoinBalance,
}

#[derive(Clone, Serialize)]
pub enum ZcoinInProgressStatus {
    ActivatingCoin,
    Scanning,
    RequestingWalletBalance,
    Finishing,
    /// This status doesn't require the user to send `UserAction`,
    /// but it tells the user that he should confirm/decline an address on his device.
    WaitingForTrezorToConnect,
    WaitingForUserToConfirmPubkey,
}

impl InitStandaloneCoinInitialStatus for ZcoinInProgressStatus {
    fn initial_status() -> Self { ZcoinInProgressStatus::ActivatingCoin }
}

impl TxHistoryEnabled for ZcoinActivationParams {
    fn tx_history_enabled(&self) -> bool { false }
}

#[derive(Clone, Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum ZcoinInitError {
    #[display(fmt = "Error on coin {} creation: {}", ticker, error)]
    CoinCreationError {
        ticker: String,
        error: String,
    },
    CoinIsAlreadyActivated {
        ticker: String,
    },
    HardwareWalletsAreNotSupportedYet,
    #[display(fmt = "Initialization task has timed out {:?}", duration)]
    TaskTimedOut {
        duration: Duration,
    },
    CouldNotGetBalance(String),
    CouldNotGetBlockCount(String),
    Internal(String),
}

impl ZcoinInitError {
    pub fn from_build_err(build_err: ZCoinBuildError, ticker: String) -> Self {
        ZcoinInitError::CoinCreationError {
            ticker,
            error: build_err.to_string(),
        }
    }
}

impl From<BalanceError> for ZcoinInitError {
    fn from(err: BalanceError) -> Self { ZcoinInitError::CouldNotGetBalance(err.to_string()) }
}

impl From<RegisterCoinError> for ZcoinInitError {
    fn from(reg_err: RegisterCoinError) -> ZcoinInitError {
        match reg_err {
            RegisterCoinError::CoinIsInitializedAlready { coin } => {
                ZcoinInitError::CoinIsAlreadyActivated { ticker: coin }
            },
            RegisterCoinError::Internal(internal) => ZcoinInitError::Internal(internal),
        }
    }
}

impl From<RpcTaskError> for ZcoinInitError {
    fn from(rpc_err: RpcTaskError) -> Self {
        match rpc_err {
            RpcTaskError::Timeout(duration) => ZcoinInitError::TaskTimedOut { duration },
            internal_error => ZcoinInitError::Internal(internal_error.to_string()),
        }
    }
}

impl From<ZcoinInitError> for InitStandaloneCoinError {
    fn from(_: ZcoinInitError) -> Self { todo!() }
}

pub struct ZcoinProtocolInfo;

impl TryFromCoinProtocol for ZcoinProtocolInfo {
    fn try_from_coin_protocol(proto: CoinProtocol) -> Result<Self, MmError<CoinProtocol>>
    where
        Self: Sized,
    {
        match proto {
            CoinProtocol::ZHTLC => Ok(ZcoinProtocolInfo),
            protocol => MmError::err(protocol),
        }
    }
}

#[async_trait]
impl InitStandaloneCoinActivationOps for ZCoin {
    type ActivationRequest = ZcoinActivationParams;
    type StandaloneProtocol = ZcoinProtocolInfo;
    type ActivationResult = ZcoinActivationResult;
    type ActivationError = ZcoinInitError;
    type InProgressStatus = ZcoinInProgressStatus;
    type AwaitingStatus = ZcoinAwaitingStatus;
    type UserAction = ZcoinUserAction;

    fn rpc_task_manager(activation_ctx: &CoinsActivationContext) -> &ZcoinTaskManagerShared {
        &activation_ctx.init_z_coin_task_manager
    }

    async fn init_standalone_coin(
        ctx: MmArc,
        ticker: String,
        coin_conf: Json,
        activation_request: &ZcoinActivationParams,
        _protocol_info: ZcoinProtocolInfo,
        priv_key_policy: PrivKeyBuildPolicy<'_>,
        task_handle: &ZcoinRpcTaskHandle,
    ) -> MmResult<Self, ZcoinInitError> {
        let priv_key = match priv_key_policy {
            PrivKeyBuildPolicy::IguanaPrivKey(key) => key,
            PrivKeyBuildPolicy::HardwareWallet => {
                return MmError::err(ZcoinInitError::HardwareWalletsAreNotSupportedYet)
            },
        };
        let coin = z_coin_from_conf_and_params(&ctx, &ticker, &coin_conf, &activation_request, priv_key)
            .await
            .mm_err(|e| ZcoinInitError::from_build_err(e, ticker))?;

        task_handle.update_in_progress_status(ZcoinInProgressStatus::Scanning)?;
        while !coin.is_sapling_state_synced() {
            Timer::sleep(1.).await;
        }
        Ok(coin)
    }

    async fn get_activation_result(
        &self,
        _ctx: MmArc,
        task_handle: &ZcoinRpcTaskHandle,
        _activation_request: &Self::ActivationRequest,
    ) -> MmResult<Self::ActivationResult, ZcoinInitError> {
        task_handle.update_in_progress_status(ZcoinInProgressStatus::RequestingWalletBalance)?;
        let current_block = self
            .current_block()
            .compat()
            .await
            .map_to_mm(ZcoinInitError::CouldNotGetBlockCount)?;

        let balance = self.my_balance().compat().await?;
        Ok(ZcoinActivationResult {
            current_block,
            wallet_balance: EnableCoinBalance::Iguana(IguanaWalletBalance {
                address: self.my_z_address_encoded(),
                balance,
            }),
        })
    }
}