use zcash_primitives::sapling::keys::OutgoingViewingKey;
use zcash_primitives::zip32::ExtendedSpendingKey;
use zcash_proofs::prover::LocalTxProver;
use common::mm_ctx::MmArc;
use common::mm_error::MmError;
use crate::{AsyncMutex, Json, MarketCoinOps, SwapOps, UtxoActivationParams, ZTransaction};
use crate::utxo::UtxoArc;
use crate::z_coin::ZCoinBuildError;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use db_common::sqlite::rusqlite::{Connection, Error as SqliteError, Row, ToSql, NO_PARAMS};
use std::path::PathBuf;

use crate::z_coin::ZCoin;
use crate::z_coin::ZCoinFields;
use crate::z_coin::ZCoinBuilder;

const DEX_FEE_OVK: OutgoingViewingKey = OutgoingViewingKey([7; 32]);

pub async fn z_coin_from_conf_and_params(
    ctx: &MmArc,
    ticker: &str,
    conf: &Json,
    params: &UtxoActivationParams,
    secp_priv_key: &[u8],
) -> Result<ZCoin, MmError<ZCoinBuildError>> {
    let db_dir_path = ctx.dbdir();
    let z_key = ExtendedSpendingKey::master(secp_priv_key);
    z_coin_from_conf_and_params_with_z_key(ctx, ticker, conf, params, secp_priv_key, db_dir_path, z_key).await
}

fn init_db(sql: &Connection) -> Result<(), SqliteError> {
    const INIT_SAPLING_CACHE_TABLE_STMT: &str = "CREATE TABLE IF NOT EXISTS z_shielded (
        txid INTEGER NOT NULL PRIMARY KEY,
        tx_hash BLOB NOT NULL,
        out_amount FLOAT
    );";

    sql.execute(INIT_SAPLING_CACHE_TABLE_STMT, NO_PARAMS).map(|_| ())
}

fn encrypt_transactions(zcoin: &ZCoin, txbytes: &[u8]) {
    let taker_fee_tx = zcoin.tx_enum_from_bytes(&txbytes).unwrap();
    let a = zcoin.validate_fee();
}

fn main() {
    // just checking what we can do with transactions
    let tx = ZTransaction::read(tx_bytes.as_slice()).unwrap();
    let _ = ZCoin::tx_enum_from_bytes();
}