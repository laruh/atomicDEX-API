use common::fs::{read_json, write_json, FsJsonError};
use common::log::LogOnError;
use common::mm_error::prelude::*;
use derive_more::Display;
use futures::lock::Mutex as AsyncMutex;
use futures::FutureExt;
use rpc::v1::types::{Transaction as RpcTransaction, H256 as H256Json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub type TxCacheResult<T> = MmResult<T, TxCacheError>;

lazy_static! {
    static ref TX_CACHE_LOCK: AsyncMutex<()> = AsyncMutex::new(());
}

#[derive(Debug, Display)]
pub enum TxCacheError {
    ErrorLoading(String),
    ErrorSaving(String),
    ErrorDeserializing(String),
    ErrorSerializing(String),
}

impl From<FsJsonError> for TxCacheError {
    fn from(e: FsJsonError) -> Self {
        match e {
            FsJsonError::IoReading(loading) => TxCacheError::ErrorLoading(loading.to_string()),
            FsJsonError::IoWriting(writing) => TxCacheError::ErrorSaving(writing.to_string()),
            FsJsonError::Serializing(ser) => TxCacheError::ErrorSerializing(ser.to_string()),
            FsJsonError::Deserializing(de) => TxCacheError::ErrorDeserializing(de.to_string()),
        }
    }
}

/// Tries to load transactions from cache concurrently.
/// Note 1: tx.confirmations can be out-of-date.
/// Note 2: this function locks the `TX_CACHE_LOCK` mutex to avoid reading and writing the same files at the same time.
pub async fn load_transactions_from_cache_concurrently<I>(
    tx_cache_path: &Path,
    tx_ids: I,
) -> HashMap<H256Json, TxCacheResult<Option<RpcTransaction>>>
where
    I: IntoIterator<Item = H256Json>,
{
    let _ = TX_CACHE_LOCK.lock().await;

    let it = tx_ids
        .into_iter()
        .map(|txid| load_transaction_from_cache(tx_cache_path, txid).map(move |res| (txid, res)));
    futures::future::join_all(it).await.into_iter().collect()
}

/// Uploads transactions to cache concurrently.
/// Note: this function locks the `TX_CACHE_LOCK` mutex and takes `txs` as the Hash map
/// to avoid reading and writing the same files at the same time.
pub async fn cache_transactions_concurrently(tx_cache_path: &Path, txs: &HashMap<H256Json, RpcTransaction>) {
    let _ = TX_CACHE_LOCK.lock().await;

    let it = txs.iter().map(|(_txid, tx)| cache_transaction(tx_cache_path, tx));
    futures::future::join_all(it)
        .await
        .into_iter()
        .for_each(|tx| tx.error_log());
}

/// Tries to load transaction from cache.
/// Note: tx.confirmations can be out-of-date.
async fn load_transaction_from_cache(tx_cache_path: &Path, txid: H256Json) -> TxCacheResult<Option<RpcTransaction>> {
    let path = cached_transaction_path(tx_cache_path, &txid);
    read_json(&path).await.mm_err(TxCacheError::from)
}

/// Uploads transaction to cache.
async fn cache_transaction(tx_cache_path: &Path, tx: &RpcTransaction) -> TxCacheResult<()> {
    const USE_TMP_FILE: bool = true;

    let path = cached_transaction_path(tx_cache_path, &tx.txid);
    write_json(tx, &path, USE_TMP_FILE).await.mm_err(TxCacheError::from)
}

fn cached_transaction_path(tx_cache_path: &Path, txid: &H256Json) -> PathBuf {
    tx_cache_path.join(format!("{:?}", txid))
}
