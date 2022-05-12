use zcash_primitives::sapling::keys::OutgoingViewingKey;
use zcash_primitives::zip32::ExtendedSpendingKey;
use zcash_proofs::prover::LocalTxProver;
use common::mm_ctx::MmArc;
use common::mm_error::MmError;
use crate::{AsyncMutex, Json, MarketCoinOps, UtxoActivationParams, ZTransaction};
use crate::utxo::UtxoArc;
use crate::z_coin::ZCoinBuildError;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use db_common::sqlite::rusqlite::{Connection, Error as SqliteError, Row, ToSql, NO_PARAMS};
use std::path::PathBuf;
use crate::z_coin::ZCoin;

const DEX_FEE_OVK: OutgoingViewingKey = OutgoingViewingKey([7; 32]);

pub struct ZCoinFields {
    z_spending_key: ExtendedSpendingKey,
    z_tx_prover: LocalTxProver,
    /// Mutex preventing concurrent transaction generation/same input usage
    z_unspent_mutex: AsyncMutex<()>,
    /// SQLite connection that is used to cache Sapling data for shielded transactions creation
    sqlite: Mutex<Connection>,
}

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
        tx_hash VARCHAR(255) NOT NULL,
        out_amount FLOAT
    );";

    sql.execute(INIT_SAPLING_CACHE_TABLE_STMT, NO_PARAMS).map(|_| ())
}

pub struct ZCoinBuilder<'a> {
    ctx: &'a MmArc,
    ticker: &'a str,
    conf: &'a Json,
    params: &'a UtxoActivationParams,
    secp_priv_key: &'a [u8],
    db_dir_path: PathBuf,
    z_spending_key: ExtendedSpendingKey,
}

impl<'a> ZCoinBuilder<'a> {
    pub fn new(
        ctx: &'a MmArc,
        ticker: &'a str,
        conf: &'a Json,
        params: &'a UtxoActivationParams,
        secp_priv_key: &'a [u8],
        db_dir_path: PathBuf,
        z_spending_key: ExtendedSpendingKey,
    ) -> ZCoinBuilder<'a> {
        ZCoinBuilder {
            ctx,
            ticker,
            conf,
            params,
            secp_priv_key,
            db_dir_path,
            z_spending_key,
        }
    }
}


fn main() {
    // just checking what we can do with transactions
    let tx = ZTransaction::read(tx_bytes.as_slice()).unwrap();
    let _ = ZCoin::tx_enum_from_bytes();
}