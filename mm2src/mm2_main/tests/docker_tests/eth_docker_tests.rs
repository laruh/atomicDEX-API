use super::docker_tests_common::{random_secp256k1_secret, ERC1155_TEST_ABI, ERC721_TEST_ABI, GETH_ACCOUNT,
                                 GETH_ERC1155_CONTRACT, GETH_ERC20_CONTRACT, GETH_ERC721_CONTRACT, GETH_MAKER_SWAP_V2,
                                 GETH_NFT_MAKER_SWAP_V2, GETH_NONCE_LOCK, GETH_RPC_URL, GETH_SWAP_CONTRACT,
                                 GETH_TAKER_SWAP_V2, GETH_WATCHERS_SWAP_CONTRACT, GETH_WEB3, MM_CTX, MM_CTX1};
#[cfg(any(feature = "sepolia-maker-swap-v2-tests", feature = "sepolia-taker-swap-v2-tests"))]
use super::docker_tests_common::{SEPOLIA_ERC20_CONTRACT, SEPOLIA_ETOMIC_MAKER_NFT_SWAP_V2, SEPOLIA_MAKER_SWAP_V2,
                                 SEPOLIA_NONCE_LOCK, SEPOLIA_RPC_URL, SEPOLIA_TAKER_SWAP_V2, SEPOLIA_TESTS_LOCK,
                                 SEPOLIA_WEB3};
use crate::common::Future01CompatExt;
use bitcrypto::{dhash160, sha256};
use coins::eth::gas_limit::ETH_MAX_TRADE_GAS;
use coins::eth::v2_activation::{eth_coin_from_conf_and_request_v2, EthActivationV2Request, EthNode};
use coins::eth::{checksum_address, eth_addr_to_hex, eth_coin_from_conf_and_request, EthCoin, EthCoinType,
                 EthPrivKeyBuildPolicy, SignedEthTx, SwapV2Contracts, ERC20_ABI};
use coins::nft::nft_structs::{Chain, ContractType, NftInfo};
use coins::{lp_coinfind, CoinProtocol, CoinWithDerivationMethod, CommonSwapOpsV2, ConfirmPaymentInput,
            DerivationMethod, Eip1559Ops, FoundSwapTxSpend, MakerNftSwapOpsV2, MarketCoinOps, NftSwapInfo,
            ParseCoinAssocTypes, ParseNftAssocTypes, PrivKeyBuildPolicy, RefundNftMakerPaymentArgs, RefundPaymentArgs,
            SearchForSwapTxSpendInput, SendNftMakerPaymentArgs, SendPaymentArgs, SpendNftMakerPaymentArgs,
            SpendPaymentArgs, SwapOps, SwapTxFeePolicy, SwapTxTypeWithSecretHash, ToBytes, Transaction,
            ValidateNftMakerPaymentArgs};
#[cfg(any(feature = "sepolia-maker-swap-v2-tests", feature = "sepolia-taker-swap-v2-tests"))]
use coins::{CoinsContext, DexFee, FundingTxSpend, GenTakerFundingSpendArgs, GenTakerPaymentSpendArgs,
            MakerCoinSwapOpsV2, MmCoinEnum, MmCoinStruct, RefundFundingSecretArgs, RefundMakerPaymentSecretArgs,
            RefundMakerPaymentTimelockArgs, RefundTakerPaymentArgs, SendMakerPaymentArgs, SendTakerFundingArgs,
            SpendMakerPaymentArgs, TakerCoinSwapOpsV2, TxPreimageWithSig, ValidateMakerPaymentArgs,
            ValidateTakerFundingArgs};
use common::{block_on, now_sec};
use crypto::Secp256k1Secret;
use ethereum_types::U256;
use futures01::Future;
#[cfg(any(feature = "sepolia-maker-swap-v2-tests", feature = "sepolia-taker-swap-v2-tests"))]
use mm2_core::mm_ctx::MmArc;
use mm2_number::{BigDecimal, BigUint};
use mm2_test_helpers::for_tests::{erc20_dev_conf, eth_dev_conf, nft_dev_conf};
#[cfg(any(feature = "sepolia-maker-swap-v2-tests", feature = "sepolia-taker-swap-v2-tests"))]
use mm2_test_helpers::for_tests::{eth_sepolia_conf, sepolia_erc20_dev_conf};
use serde_json::Value as Json;
#[cfg(any(feature = "sepolia-maker-swap-v2-tests", feature = "sepolia-taker-swap-v2-tests"))]
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use web3::contract::{Contract, Options};
use web3::ethabi::Token;
#[cfg(any(feature = "sepolia-maker-swap-v2-tests", feature = "sepolia-taker-swap-v2-tests"))]
use web3::types::BlockNumber;
use web3::types::{Address, TransactionRequest, H256};

#[cfg(any(feature = "sepolia-maker-swap-v2-tests", feature = "sepolia-taker-swap-v2-tests"))]
const SEPOLIA_MAKER_PRIV: &str = "6e2f3a6223b928a05a3a3622b0c3f3573d03663b704a61a6eb73326de0487928";
#[cfg(any(feature = "sepolia-maker-swap-v2-tests", feature = "sepolia-taker-swap-v2-tests"))]
const SEPOLIA_TAKER_PRIV: &str = "e0be82dca60ff7e4c6d6db339ac9e1ae249af081dba2110bddd281e711608f16";
const NFT_ETH: &str = "NFT_ETH";
const ETH: &str = "ETH";
const ERC20: &str = "ERC20DEV";

/// # Safety
///
/// GETH_ACCOUNT is set once during initialization before tests start
pub fn geth_account() -> Address { unsafe { GETH_ACCOUNT } }
/// # Safety
///
/// GETH_SWAP_CONTRACT is set once during initialization before tests start
pub fn swap_contract() -> Address { unsafe { GETH_SWAP_CONTRACT } }
/// # Safety
///
/// GETH_MAKER_SWAP_V2 is set once during initialization before tests start
pub fn maker_swap_v2() -> Address { unsafe { GETH_MAKER_SWAP_V2 } }
/// # Safety
///
/// GETH_TAKER_SWAP_V2 is set once during initialization before tests start
pub fn taker_swap_v2() -> Address { unsafe { GETH_TAKER_SWAP_V2 } }
#[cfg(any(feature = "sepolia-maker-swap-v2-tests", feature = "sepolia-taker-swap-v2-tests"))]
pub fn sepolia_taker_swap_v2() -> Address { unsafe { SEPOLIA_TAKER_SWAP_V2 } }
#[cfg(any(feature = "sepolia-maker-swap-v2-tests", feature = "sepolia-taker-swap-v2-tests"))]
pub fn sepolia_maker_swap_v2() -> Address { unsafe { SEPOLIA_MAKER_SWAP_V2 } }
/// # Safety
///
/// GETH_NFT_MAKER_SWAP_V2 is set once during initialization before tests start
pub fn geth_nft_maker_swap_v2() -> Address { unsafe { GETH_NFT_MAKER_SWAP_V2 } }
/// # Safety
///
/// GETH_WATCHERS_SWAP_CONTRACT is set once during initialization before tests start
pub fn watchers_swap_contract() -> Address { unsafe { GETH_WATCHERS_SWAP_CONTRACT } }
/// # Safety
///
/// GETH_ERC20_CONTRACT is set once during initialization before tests start
pub fn erc20_contract() -> Address { unsafe { GETH_ERC20_CONTRACT } }
#[cfg(any(feature = "sepolia-maker-swap-v2-tests", feature = "sepolia-taker-swap-v2-tests"))]
pub fn sepolia_erc20_contract() -> Address { unsafe { SEPOLIA_ERC20_CONTRACT } }
/// Return ERC20 dev token contract address in checksum format
pub fn erc20_contract_checksum() -> String { checksum_address(&format!("{:02x}", erc20_contract())) }
#[cfg(any(feature = "sepolia-maker-swap-v2-tests", feature = "sepolia-taker-swap-v2-tests"))]
pub fn sepolia_erc20_contract_checksum() -> String { checksum_address(&format!("{:02x}", sepolia_erc20_contract())) }
/// # Safety
///
/// GETH_ERC721_CONTRACT is set once during initialization before tests start
pub fn geth_erc721_contract() -> Address { unsafe { GETH_ERC721_CONTRACT } }
/// # Safety
///
/// GETH_ERC1155_CONTRACT is set once during initialization before tests start
pub fn geth_erc1155_contract() -> Address { unsafe { GETH_ERC1155_CONTRACT } }
#[cfg(any(feature = "sepolia-maker-swap-v2-tests", feature = "sepolia-taker-swap-v2-tests"))]
/// # Safety
///
/// SEPOLIA_ETOMIC_MAKER_NFT_SWAP_V2 address is set once during initialization before tests start
pub fn sepolia_etomic_maker_nft() -> Address { unsafe { SEPOLIA_ETOMIC_MAKER_NFT_SWAP_V2 } }

fn wait_for_confirmation(tx_hash: H256) {
    thread::sleep(Duration::from_millis(2000));
    loop {
        match block_on(GETH_WEB3.eth().transaction_receipt(tx_hash)) {
            Ok(Some(r)) => match r.block_hash {
                Some(_) => break,
                None => thread::sleep(Duration::from_millis(100)),
            },
            _ => {
                thread::sleep(Duration::from_millis(100));
            },
        }
    }
}

pub fn fill_eth(to_addr: Address, amount: U256) {
    let _guard = GETH_NONCE_LOCK.lock().unwrap();
    let tx_request = TransactionRequest {
        from: geth_account(),
        to: Some(to_addr),
        gas: None,
        gas_price: None,
        value: Some(amount),
        data: None,
        nonce: None,
        condition: None,
        transaction_type: None,
        access_list: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
    };
    let tx_hash = block_on(GETH_WEB3.eth().send_transaction(tx_request)).unwrap();
    wait_for_confirmation(tx_hash);
}

fn fill_erc20(to_addr: Address, amount: U256) {
    let _guard = GETH_NONCE_LOCK.lock().unwrap();
    let erc20_contract = Contract::from_json(GETH_WEB3.eth(), erc20_contract(), ERC20_ABI.as_bytes()).unwrap();

    let tx_hash = block_on(erc20_contract.call(
        "transfer",
        (Token::Address(to_addr), Token::Uint(amount)),
        geth_account(),
        Options::default(),
    ))
    .unwrap();
    wait_for_confirmation(tx_hash);
}

fn mint_erc721(to_addr: Address, token_id: U256) {
    let _guard = GETH_NONCE_LOCK.lock().unwrap();
    let erc721_contract =
        Contract::from_json(GETH_WEB3.eth(), geth_erc721_contract(), ERC721_TEST_ABI.as_bytes()).unwrap();

    let options = Options {
        gas: Some(U256::from(ETH_MAX_TRADE_GAS)),
        ..Options::default()
    };

    let tx_hash = block_on(erc721_contract.call(
        "mint",
        (Token::Address(to_addr), Token::Uint(token_id)),
        geth_account(),
        options,
    ))
    .unwrap();
    wait_for_confirmation(tx_hash);

    let owner: Address =
        block_on(erc721_contract.query("ownerOf", Token::Uint(token_id), None, Options::default(), None)).unwrap();

    assert_eq!(
        owner, to_addr,
        "The ownership of the tokenID {:?} does not match the expected address {:?}.",
        token_id, to_addr
    );
}

fn geth_erc712_owner(token_id: U256) -> Address {
    let _guard = GETH_NONCE_LOCK.lock().unwrap();
    let erc721_contract =
        Contract::from_json(GETH_WEB3.eth(), geth_erc721_contract(), ERC721_TEST_ABI.as_bytes()).unwrap();
    block_on(erc721_contract.query("ownerOf", Token::Uint(token_id), None, Options::default(), None)).unwrap()
}

fn mint_erc1155(to_addr: Address, token_id: U256, amount: U256) {
    let _guard = GETH_NONCE_LOCK.lock().unwrap();
    let erc1155_contract =
        Contract::from_json(GETH_WEB3.eth(), geth_erc1155_contract(), ERC1155_TEST_ABI.as_bytes()).unwrap();

    let tx_hash = block_on(erc1155_contract.call(
        "mint",
        (
            Token::Address(to_addr),
            Token::Uint(token_id),
            Token::Uint(amount),
            Token::Bytes("".into()),
        ),
        geth_account(),
        Options::default(),
    ))
    .unwrap();
    wait_for_confirmation(tx_hash);

    // Check the balance of the token for the to_addr
    let balance: U256 = block_on(erc1155_contract.query(
        "balanceOf",
        (Token::Address(to_addr), Token::Uint(token_id)),
        None,
        Options::default(),
        None,
    ))
    .unwrap();

    assert_eq!(
        balance, amount,
        "The balance of tokenId {:?} for address {:?} does not match the expected amount {:?}.",
        token_id, to_addr, amount
    );
}

fn geth_erc1155_balance(wallet_addr: Address, token_id: U256) -> U256 {
    let _guard = GETH_NONCE_LOCK.lock().unwrap();
    let erc1155_contract =
        Contract::from_json(GETH_WEB3.eth(), geth_erc1155_contract(), ERC1155_TEST_ABI.as_bytes()).unwrap();
    block_on(erc1155_contract.query(
        "balanceOf",
        (Token::Address(wallet_addr), Token::Uint(token_id)),
        None,
        Options::default(),
        None,
    ))
    .unwrap()
}

pub(crate) async fn fill_erc1155_info(eth_coin: &EthCoin, token_address: Address, token_id: u32, amount: u32) {
    let nft_infos_lock = eth_coin.nfts_infos.clone();
    let mut nft_infos = nft_infos_lock.lock().await;

    let erc1155_nft_info = NftInfo {
        token_address,
        token_id: BigUint::from(token_id),
        chain: Chain::Eth,
        contract_type: ContractType::Erc1155,
        amount: BigDecimal::from(amount),
    };
    let erc1155_address_str = eth_addr_to_hex(&token_address);
    let erc1155_key = format!("{},{}", erc1155_address_str, token_id);
    nft_infos.insert(erc1155_key, erc1155_nft_info);
}

pub(crate) async fn fill_erc721_info(eth_coin: &EthCoin, token_address: Address, token_id: u32) {
    let nft_infos_lock = eth_coin.nfts_infos.clone();
    let mut nft_infos = nft_infos_lock.lock().await;

    let erc721_nft_info = NftInfo {
        token_address,
        token_id: BigUint::from(token_id),
        chain: Chain::Eth,
        contract_type: ContractType::Erc721,
        amount: BigDecimal::from(1),
    };
    let erc721_address_str = eth_addr_to_hex(&token_address);
    let erc721_key = format!("{},{}", erc721_address_str, token_id);
    nft_infos.insert(erc721_key, erc721_nft_info);
}

/// Creates ETH protocol coin supplied with 100 ETH
pub fn eth_coin_with_random_privkey_using_urls(swap_contract_address: Address, urls: &[&str]) -> EthCoin {
    let eth_conf = eth_dev_conf();
    let req = json!({
        "method": "enable",
        "coin": "ETH",
        "swap_contract_address": swap_contract_address,
        "urls": urls,
    });

    let secret = random_secp256k1_secret();
    let eth_coin = block_on(eth_coin_from_conf_and_request(
        &MM_CTX,
        "ETH",
        &eth_conf,
        &req,
        CoinProtocol::ETH,
        PrivKeyBuildPolicy::IguanaPrivKey(secret),
    ))
    .unwrap();

    let my_address = match eth_coin.derivation_method() {
        DerivationMethod::SingleAddress(addr) => *addr,
        _ => panic!("Expected single address"),
    };

    // 100 ETH
    fill_eth(my_address, U256::from(10).pow(U256::from(20)));

    eth_coin
}

/// Creates ETH protocol coin supplied with 100 ETH, using the default GETH_RPC_URL
pub fn eth_coin_with_random_privkey(swap_contract_address: Address) -> EthCoin {
    eth_coin_with_random_privkey_using_urls(swap_contract_address, &[GETH_RPC_URL])
}

/// Creates ERC20 protocol coin supplied with 1 ETH and 100 token
pub fn erc20_coin_with_random_privkey(swap_contract_address: Address) -> EthCoin {
    let erc20_conf = erc20_dev_conf(&erc20_contract_checksum());
    let req = json!({
        "method": "enable",
        "coin": "ERC20DEV",
        "swap_contract_address": swap_contract_address,
        "urls": [GETH_RPC_URL],
    });

    let erc20_coin = block_on(eth_coin_from_conf_and_request(
        &MM_CTX,
        "ERC20DEV",
        &erc20_conf,
        &req,
        CoinProtocol::ERC20 {
            platform: "ETH".to_string(),
            contract_address: checksum_address(&format!("{:02x}", erc20_contract())),
        },
        PrivKeyBuildPolicy::IguanaPrivKey(random_secp256k1_secret()),
    ))
    .unwrap();

    let my_address = match erc20_coin.derivation_method() {
        DerivationMethod::SingleAddress(addr) => *addr,
        _ => panic!("Expected single address"),
    };

    // 1 ETH
    fill_eth(my_address, U256::from(10).pow(U256::from(18)));
    // 100 tokens (it has 8 decimals)
    fill_erc20(my_address, U256::from(10000000000u64));

    erc20_coin
}

#[derive(Clone, Copy, Debug)]
pub enum TestNftType {
    Erc1155 { token_id: u32, amount: u32 },
    Erc721 { token_id: u32 },
}

/// Generates a global NFT coin instance with a random private key and an initial 100 ETH balance.
/// Optionally mints a specified NFT (either ERC721 or ERC1155) to the global NFT address,
/// with details recorded in the `nfts_infos` field based on the provided `nft_type`.
fn global_nft_with_random_privkey(
    swap_v2_contracts: SwapV2Contracts,
    swap_contract_address: Address,
    fallback_swap_contract_address: Address,
    nft_type: Option<TestNftType>,
    nft_ticker: String,
    platform_ticker: String,
) -> EthCoin {
    let build_policy = EthPrivKeyBuildPolicy::IguanaPrivKey(random_secp256k1_secret());
    let node = EthNode {
        url: GETH_RPC_URL.to_string(),
        komodo_proxy: false,
    };
    let platform_request = EthActivationV2Request {
        nodes: vec![node],
        rpc_mode: Default::default(),
        swap_contract_address,
        swap_v2_contracts: Some(swap_v2_contracts),
        fallback_swap_contract: Some(fallback_swap_contract_address),
        contract_supports_watchers: false,
        mm2: None,
        required_confirmations: None,
        priv_key_policy: Default::default(),
        enable_params: Default::default(),
        path_to_address: Default::default(),
        gap_limit: None,
    };
    let coin = block_on(eth_coin_from_conf_and_request_v2(
        &MM_CTX1,
        nft_ticker.as_str(),
        &nft_dev_conf(),
        platform_request,
        build_policy,
    ))
    .unwrap();

    let coin_type = EthCoinType::Nft {
        platform: platform_ticker,
    };
    let global_nft = block_on(coin.set_coin_type(coin_type));
    let my_address = block_on(coin.my_addr());
    fill_eth(my_address, U256::from(10).pow(U256::from(20)));

    if let Some(nft_type) = nft_type {
        match nft_type {
            TestNftType::Erc1155 { token_id, amount } => {
                mint_erc1155(my_address, U256::from(token_id), U256::from(amount));
                block_on(fill_erc1155_info(
                    &global_nft,
                    geth_erc1155_contract(),
                    token_id,
                    amount,
                ));
            },
            TestNftType::Erc721 { token_id } => {
                mint_erc721(my_address, U256::from(token_id));
                block_on(fill_erc721_info(&global_nft, geth_erc721_contract(), token_id));
            },
        }
    }
    global_nft
}

#[cfg(any(feature = "sepolia-maker-swap-v2-tests", feature = "sepolia-taker-swap-v2-tests"))]
/// Can be used to generate coin from Sepolia Maker/Taker priv keys.
fn sepolia_coin_from_privkey(ctx: &MmArc, secret: &'static str, ticker: &str, conf: &Json, erc20: bool) -> EthCoin {
    let swap_addr = SwapAddresses {
        swap_v2_contracts: SwapV2Contracts {
            maker_swap_v2_contract: sepolia_maker_swap_v2(),
            taker_swap_v2_contract: sepolia_taker_swap_v2(),
            nft_maker_swap_v2_contract: sepolia_etomic_maker_nft(),
        },
        swap_contract_address: sepolia_taker_swap_v2(),
        fallback_swap_contract_address: sepolia_taker_swap_v2(),
    };

    let priv_key = Secp256k1Secret::from(secret);
    let build_policy = EthPrivKeyBuildPolicy::IguanaPrivKey(priv_key);

    let node = EthNode {
        url: SEPOLIA_RPC_URL.to_string(),
        komodo_proxy: false,
    };
    let platform_request = EthActivationV2Request {
        nodes: vec![node],
        rpc_mode: Default::default(),
        swap_contract_address: swap_addr.swap_contract_address,
        swap_v2_contracts: Some(swap_addr.swap_v2_contracts),
        fallback_swap_contract: Some(swap_addr.fallback_swap_contract_address),
        contract_supports_watchers: false,
        mm2: None,
        required_confirmations: None,
        priv_key_policy: Default::default(),
        enable_params: Default::default(),
        path_to_address: Default::default(),
        gap_limit: None,
    };
    let coin = block_on(eth_coin_from_conf_and_request_v2(
        ctx,
        ticker,
        conf,
        platform_request,
        build_policy,
    ))
    .unwrap();
    let coin = if erc20 {
        let coin_type = EthCoinType::Erc20 {
            platform: ETH.to_string(),
            token_addr: sepolia_erc20_contract(),
        };
        block_on(coin.set_coin_type(coin_type))
    } else {
        coin
    };

    let coins_ctx = CoinsContext::from_ctx(ctx).unwrap();
    let mut coins = block_on(coins_ctx.lock_coins());
    coins.insert(
        coin.ticker().into(),
        MmCoinStruct::new(MmCoinEnum::EthCoin(coin.clone())),
    );
    coin
}

#[cfg(any(feature = "sepolia-maker-swap-v2-tests", feature = "sepolia-taker-swap-v2-tests"))]
fn get_or_create_sepolia_coin(ctx: &MmArc, priv_key: &'static str, ticker: &str, conf: &Json, erc20: bool) -> EthCoin {
    match block_on(lp_coinfind(ctx, ticker)).unwrap() {
        None => sepolia_coin_from_privkey(ctx, priv_key, ticker, conf, erc20),
        Some(mm_coin) => match mm_coin {
            MmCoinEnum::EthCoin(coin) => coin,
            _ => panic!("Unexpected coin type found. Expected MmCoinEnum::EthCoin"),
        },
    }
}

/// Fills the private key's public address with ETH and ERC20 tokens
pub fn fill_eth_erc20_with_private_key(priv_key: Secp256k1Secret) {
    let eth_conf = eth_dev_conf();
    let req = json!({
        "coin": "ETH",
        "urls": [GETH_RPC_URL],
        "swap_contract_address": swap_contract(),
    });

    let eth_coin = block_on(eth_coin_from_conf_and_request(
        &MM_CTX,
        "ETH",
        &eth_conf,
        &req,
        CoinProtocol::ETH,
        PrivKeyBuildPolicy::IguanaPrivKey(priv_key),
    ))
    .unwrap();
    let my_address = block_on(eth_coin.derivation_method().single_addr_or_err()).unwrap();

    // 100 ETH
    fill_eth(my_address, U256::from(10).pow(U256::from(20)));

    let erc20_conf = erc20_dev_conf(&erc20_contract_checksum());
    let req = json!({
        "method": "enable",
        "coin": "ERC20DEV",
        "urls": [GETH_RPC_URL],
        "swap_contract_address": swap_contract(),
    });

    let _erc20_coin = block_on(eth_coin_from_conf_and_request(
        &MM_CTX,
        "ERC20DEV",
        &erc20_conf,
        &req,
        CoinProtocol::ERC20 {
            platform: "ETH".to_string(),
            contract_address: erc20_contract_checksum(),
        },
        PrivKeyBuildPolicy::IguanaPrivKey(priv_key),
    ))
    .unwrap();

    // 100 tokens (it has 8 decimals)
    fill_erc20(my_address, U256::from(10000000000u64));
}

fn send_and_refund_eth_maker_payment_impl(swap_txfee_policy: SwapTxFeePolicy) {
    thread::sleep(Duration::from_secs(3));
    let eth_coin = eth_coin_with_random_privkey(swap_contract());
    eth_coin.set_swap_transaction_fee_policy(swap_txfee_policy);

    let time_lock = now_sec() - 100;
    let other_pubkey = &[
        0x02, 0xc6, 0x6e, 0x7d, 0x89, 0x66, 0xb5, 0xc5, 0x55, 0xaf, 0x58, 0x05, 0x98, 0x9d, 0xa9, 0xfb, 0xf8, 0xdb,
        0x95, 0xe1, 0x56, 0x31, 0xce, 0x35, 0x8c, 0x3a, 0x17, 0x10, 0xc9, 0x62, 0x67, 0x90, 0x63,
    ];

    let send_payment_args = SendPaymentArgs {
        time_lock_duration: 100,
        time_lock,
        other_pubkey,
        secret_hash: &[0; 20],
        amount: 1.into(),
        swap_contract_address: &Some(swap_contract().as_bytes().into()),
        swap_unique_data: &[],
        payment_instructions: &None,
        watcher_reward: None,
        wait_for_confirmation_until: 0,
    };
    let eth_maker_payment = eth_coin.send_maker_payment(send_payment_args).wait().unwrap();

    let confirm_input = ConfirmPaymentInput {
        payment_tx: eth_maker_payment.tx_hex(),
        confirmations: 1,
        requires_nota: false,
        wait_until: now_sec() + 60,
        check_every: 1,
    };
    eth_coin.wait_for_confirmations(confirm_input).wait().unwrap();

    let refund_args = RefundPaymentArgs {
        payment_tx: &eth_maker_payment.tx_hex(),
        time_lock,
        other_pubkey,
        tx_type_with_secret_hash: SwapTxTypeWithSecretHash::TakerOrMakerPayment {
            maker_secret_hash: &[0; 20],
        },
        swap_contract_address: &Some(swap_contract().as_bytes().into()),
        swap_unique_data: &[],
        watcher_reward: false,
    };
    let payment_refund = block_on(eth_coin.send_maker_refunds_payment(refund_args)).unwrap();
    log!("Payment refund tx hash {:02x}", payment_refund.tx_hash_as_bytes());

    let confirm_input = ConfirmPaymentInput {
        payment_tx: payment_refund.tx_hex(),
        confirmations: 1,
        requires_nota: false,
        wait_until: now_sec() + 60,
        check_every: 1,
    };
    eth_coin.wait_for_confirmations(confirm_input).wait().unwrap();

    let search_input = SearchForSwapTxSpendInput {
        time_lock,
        other_pub: other_pubkey,
        secret_hash: &[0; 20],
        tx: &eth_maker_payment.tx_hex(),
        search_from_block: 0,
        swap_contract_address: &Some(swap_contract().as_bytes().into()),
        swap_unique_data: &[],
        watcher_reward: false,
    };
    let search_tx = block_on(eth_coin.search_for_swap_tx_spend_my(search_input))
        .unwrap()
        .unwrap();

    let expected = FoundSwapTxSpend::Refunded(payment_refund);
    assert_eq!(expected, search_tx);
}

#[test]
fn send_and_refund_eth_maker_payment_internal_gas_policy() {
    send_and_refund_eth_maker_payment_impl(SwapTxFeePolicy::Internal);
}

#[test]
fn send_and_refund_eth_maker_payment_priority_fee() { send_and_refund_eth_maker_payment_impl(SwapTxFeePolicy::Medium); }

fn send_and_spend_eth_maker_payment_impl(swap_txfee_policy: SwapTxFeePolicy) {
    let maker_eth_coin = eth_coin_with_random_privkey(swap_contract());
    let taker_eth_coin = eth_coin_with_random_privkey(swap_contract());

    maker_eth_coin.set_swap_transaction_fee_policy(swap_txfee_policy.clone());
    taker_eth_coin.set_swap_transaction_fee_policy(swap_txfee_policy);

    let time_lock = now_sec() + 1000;
    let maker_pubkey = maker_eth_coin.derive_htlc_pubkey(&[]);
    let taker_pubkey = taker_eth_coin.derive_htlc_pubkey(&[]);
    let secret = &[1; 32];
    let secret_hash_owned = dhash160(secret);
    let secret_hash = secret_hash_owned.as_slice();

    let send_payment_args = SendPaymentArgs {
        time_lock_duration: 1000,
        time_lock,
        other_pubkey: &taker_pubkey,
        secret_hash,
        amount: 1.into(),
        swap_contract_address: &Some(swap_contract().as_bytes().into()),
        swap_unique_data: &[],
        payment_instructions: &None,
        watcher_reward: None,
        wait_for_confirmation_until: 0,
    };
    let eth_maker_payment = maker_eth_coin.send_maker_payment(send_payment_args).wait().unwrap();

    let confirm_input = ConfirmPaymentInput {
        payment_tx: eth_maker_payment.tx_hex(),
        confirmations: 1,
        requires_nota: false,
        wait_until: now_sec() + 60,
        check_every: 1,
    };
    taker_eth_coin.wait_for_confirmations(confirm_input).wait().unwrap();

    let spend_args = SpendPaymentArgs {
        other_payment_tx: &eth_maker_payment.tx_hex(),
        time_lock,
        other_pubkey: &maker_pubkey,
        secret,
        secret_hash,
        swap_contract_address: &Some(swap_contract().as_bytes().into()),
        swap_unique_data: &[],
        watcher_reward: false,
    };
    let payment_spend = block_on(taker_eth_coin.send_taker_spends_maker_payment(spend_args)).unwrap();
    log!("Payment spend tx hash {:02x}", payment_spend.tx_hash_as_bytes());

    let confirm_input = ConfirmPaymentInput {
        payment_tx: payment_spend.tx_hex(),
        confirmations: 1,
        requires_nota: false,
        wait_until: now_sec() + 60,
        check_every: 1,
    };
    taker_eth_coin.wait_for_confirmations(confirm_input).wait().unwrap();

    let search_input = SearchForSwapTxSpendInput {
        time_lock,
        other_pub: &taker_pubkey,
        secret_hash,
        tx: &eth_maker_payment.tx_hex(),
        search_from_block: 0,
        swap_contract_address: &Some(swap_contract().as_bytes().into()),
        swap_unique_data: &[],
        watcher_reward: false,
    };
    let search_tx = block_on(maker_eth_coin.search_for_swap_tx_spend_my(search_input))
        .unwrap()
        .unwrap();

    let expected = FoundSwapTxSpend::Spent(payment_spend);
    assert_eq!(expected, search_tx);
}

#[test]
fn send_and_spend_eth_maker_payment_internal_gas_policy() {
    send_and_spend_eth_maker_payment_impl(SwapTxFeePolicy::Internal);
}

#[test]
fn send_and_spend_eth_maker_payment_priority_fee() { send_and_spend_eth_maker_payment_impl(SwapTxFeePolicy::Medium); }

fn send_and_refund_erc20_maker_payment_impl(swap_txfee_policy: SwapTxFeePolicy) {
    thread::sleep(Duration::from_secs(10));
    let erc20_coin = erc20_coin_with_random_privkey(swap_contract());
    erc20_coin.set_swap_transaction_fee_policy(swap_txfee_policy);

    let time_lock = now_sec() - 100;
    let other_pubkey = &[
        0x02, 0xc6, 0x6e, 0x7d, 0x89, 0x66, 0xb5, 0xc5, 0x55, 0xaf, 0x58, 0x05, 0x98, 0x9d, 0xa9, 0xfb, 0xf8, 0xdb,
        0x95, 0xe1, 0x56, 0x31, 0xce, 0x35, 0x8c, 0x3a, 0x17, 0x10, 0xc9, 0x62, 0x67, 0x90, 0x63,
    ];
    let secret_hash = &[1; 20];

    let send_payment_args = SendPaymentArgs {
        time_lock_duration: 100,
        time_lock,
        other_pubkey,
        secret_hash,
        amount: 1.into(),
        swap_contract_address: &Some(swap_contract().as_bytes().into()),
        swap_unique_data: &[],
        payment_instructions: &None,
        watcher_reward: None,
        wait_for_confirmation_until: now_sec() + 60,
    };
    let eth_maker_payment = erc20_coin.send_maker_payment(send_payment_args).wait().unwrap();

    let confirm_input = ConfirmPaymentInput {
        payment_tx: eth_maker_payment.tx_hex(),
        confirmations: 1,
        requires_nota: false,
        wait_until: now_sec() + 60,
        check_every: 1,
    };
    erc20_coin.wait_for_confirmations(confirm_input).wait().unwrap();

    let refund_args = RefundPaymentArgs {
        payment_tx: &eth_maker_payment.tx_hex(),
        time_lock,
        other_pubkey,
        tx_type_with_secret_hash: SwapTxTypeWithSecretHash::TakerOrMakerPayment {
            maker_secret_hash: secret_hash,
        },
        swap_contract_address: &Some(swap_contract().as_bytes().into()),
        swap_unique_data: &[],
        watcher_reward: false,
    };
    let payment_refund = block_on(erc20_coin.send_maker_refunds_payment(refund_args)).unwrap();
    log!("Payment refund tx hash {:02x}", payment_refund.tx_hash_as_bytes());

    let confirm_input = ConfirmPaymentInput {
        payment_tx: payment_refund.tx_hex(),
        confirmations: 1,
        requires_nota: false,
        wait_until: now_sec() + 60,
        check_every: 1,
    };
    erc20_coin.wait_for_confirmations(confirm_input).wait().unwrap();

    let search_input = SearchForSwapTxSpendInput {
        time_lock,
        other_pub: other_pubkey,
        secret_hash,
        tx: &eth_maker_payment.tx_hex(),
        search_from_block: 0,
        swap_contract_address: &Some(swap_contract().as_bytes().into()),
        swap_unique_data: &[],
        watcher_reward: false,
    };
    let search_tx = block_on(erc20_coin.search_for_swap_tx_spend_my(search_input))
        .unwrap()
        .unwrap();

    let expected = FoundSwapTxSpend::Refunded(payment_refund);
    assert_eq!(expected, search_tx);
}

#[test]
fn send_and_refund_erc20_maker_payment_internal_gas_policy() {
    send_and_refund_erc20_maker_payment_impl(SwapTxFeePolicy::Internal);
}

#[test]
fn send_and_refund_erc20_maker_payment_priority_fee() {
    send_and_refund_erc20_maker_payment_impl(SwapTxFeePolicy::Medium);
}

fn send_and_spend_erc20_maker_payment_impl(swap_txfee_policy: SwapTxFeePolicy) {
    thread::sleep(Duration::from_secs(7));
    let maker_erc20_coin = erc20_coin_with_random_privkey(swap_contract());
    let taker_erc20_coin = erc20_coin_with_random_privkey(swap_contract());

    maker_erc20_coin.set_swap_transaction_fee_policy(swap_txfee_policy.clone());
    taker_erc20_coin.set_swap_transaction_fee_policy(swap_txfee_policy);

    let time_lock = now_sec() + 1000;
    let maker_pubkey = maker_erc20_coin.derive_htlc_pubkey(&[]);
    let taker_pubkey = taker_erc20_coin.derive_htlc_pubkey(&[]);
    let secret = &[2; 32];
    let secret_hash_owned = dhash160(secret);
    let secret_hash = secret_hash_owned.as_slice();

    let send_payment_args = SendPaymentArgs {
        time_lock_duration: 1000,
        time_lock,
        other_pubkey: &taker_pubkey,
        secret_hash,
        amount: 1.into(),
        swap_contract_address: &Some(swap_contract().as_bytes().into()),
        swap_unique_data: &[],
        payment_instructions: &None,
        watcher_reward: None,
        wait_for_confirmation_until: now_sec() + 60,
    };
    let eth_maker_payment = maker_erc20_coin.send_maker_payment(send_payment_args).wait().unwrap();

    let confirm_input = ConfirmPaymentInput {
        payment_tx: eth_maker_payment.tx_hex(),
        confirmations: 1,
        requires_nota: false,
        wait_until: now_sec() + 60,
        check_every: 1,
    };
    taker_erc20_coin.wait_for_confirmations(confirm_input).wait().unwrap();

    let spend_args = SpendPaymentArgs {
        other_payment_tx: &eth_maker_payment.tx_hex(),
        time_lock,
        other_pubkey: &maker_pubkey,
        secret,
        secret_hash,
        swap_contract_address: &Some(swap_contract().as_bytes().into()),
        swap_unique_data: &[],
        watcher_reward: false,
    };
    let payment_spend = block_on(taker_erc20_coin.send_taker_spends_maker_payment(spend_args)).unwrap();
    log!("Payment spend tx hash {:02x}", payment_spend.tx_hash_as_bytes());

    let confirm_input = ConfirmPaymentInput {
        payment_tx: payment_spend.tx_hex(),
        confirmations: 1,
        requires_nota: false,
        wait_until: now_sec() + 60,
        check_every: 1,
    };
    taker_erc20_coin.wait_for_confirmations(confirm_input).wait().unwrap();

    let search_input = SearchForSwapTxSpendInput {
        time_lock,
        other_pub: &taker_pubkey,
        secret_hash,
        tx: &eth_maker_payment.tx_hex(),
        search_from_block: 0,
        swap_contract_address: &Some(swap_contract().as_bytes().into()),
        swap_unique_data: &[],
        watcher_reward: false,
    };
    let search_tx = block_on(maker_erc20_coin.search_for_swap_tx_spend_my(search_input))
        .unwrap()
        .unwrap();

    let expected = FoundSwapTxSpend::Spent(payment_spend);
    assert_eq!(expected, search_tx);
}

#[test]
fn send_and_spend_erc20_maker_payment_internal_gas_policy() {
    send_and_spend_erc20_maker_payment_impl(SwapTxFeePolicy::Internal);
}

#[test]
fn send_and_spend_erc20_maker_payment_priority_fee() {
    send_and_spend_erc20_maker_payment_impl(SwapTxFeePolicy::Medium);
}

#[cfg(any(feature = "sepolia-maker-swap-v2-tests", feature = "sepolia-taker-swap-v2-tests"))]
/// Wait for all pending transactions for the given address to be confirmed
fn wait_pending_transactions(wallet_address: Address) {
    let _guard = SEPOLIA_NONCE_LOCK.lock().unwrap();
    let web3 = SEPOLIA_WEB3.clone();

    loop {
        let latest_nonce = block_on(web3.eth().transaction_count(wallet_address, Some(BlockNumber::Latest))).unwrap();
        let pending_nonce = block_on(web3.eth().transaction_count(wallet_address, Some(BlockNumber::Pending))).unwrap();

        if latest_nonce == pending_nonce {
            log!(
                "All pending transactions have been confirmed. Latest nonce: {}",
                latest_nonce
            );
            break;
        } else {
            log!(
                "Waiting for pending transactions to confirm... Current nonce: {}, Pending nonce: {}",
                latest_nonce,
                pending_nonce
            );
            thread::sleep(Duration::from_secs(1));
        }
    }
}

#[test]
fn send_and_spend_erc721_maker_payment() {
    let token_id = 1u32;
    let time_lock = now_sec() + 1000;
    let activation = NftActivationV2Args::init();
    let setup = setup_test(
        token_id,
        None,
        ContractType::Erc721,
        geth_erc721_contract(),
        time_lock,
        activation,
    );

    let maker_payment = send_nft_maker_payment(&setup, 1.into());
    log!(
        "Maker sent ERC721 NFT payment, tx hash: {:02x}",
        maker_payment.tx_hash()
    );

    wait_for_confirmations(&setup.maker_global_nft, &maker_payment, 200);
    validate_nft_maker_payment(&setup, &maker_payment, 1.into());

    let spend_tx = spend_nft_maker_payment(&setup, &maker_payment, &ContractType::Erc721);
    log!(
        "Taker spent ERC721 NFT Maker payment, tx hash: {:02x}",
        spend_tx.tx_hash()
    );

    wait_for_confirmations(&setup.taker_global_nft, &spend_tx, 200);
    let new_owner = geth_erc712_owner(U256::from(token_id));
    let taker_address = block_on(setup.taker_global_nft.my_addr());
    assert_eq!(new_owner, taker_address);
}

#[test]
fn send_and_spend_erc1155_maker_payment() {
    let token_id = 1u32;
    let amount = 3u32;
    let time_lock = now_sec() + 1000;
    let activation = NftActivationV2Args::init();
    let setup = setup_test(
        token_id,
        Some(amount),
        ContractType::Erc1155,
        geth_erc1155_contract(),
        time_lock,
        activation,
    );

    let maker_address = block_on(setup.maker_global_nft.my_addr());
    let maker_balance = geth_erc1155_balance(maker_address, U256::from(token_id));
    assert_eq!(U256::from(amount), maker_balance);

    let swap_amount = 2u32;
    let maker_payment = send_nft_maker_payment(&setup, swap_amount.into());
    log!(
        "Maker sent ERC1155 NFT payment, tx hash: {:02x}",
        maker_payment.tx_hash()
    );

    wait_for_confirmations(&setup.maker_global_nft, &maker_payment, 100);

    validate_nft_maker_payment(&setup, &maker_payment, swap_amount.into());

    let spend_tx = spend_nft_maker_payment(&setup, &maker_payment, &ContractType::Erc1155);
    log!(
        "Taker spent ERC1155 NFT Maker payment, tx hash: {:02x}",
        spend_tx.tx_hash()
    );

    wait_for_confirmations(&setup.taker_global_nft, &spend_tx, 100);

    let taker_address = block_on(setup.taker_global_nft.my_addr());
    let taker_balance = geth_erc1155_balance(taker_address, U256::from(token_id));
    assert_eq!(U256::from(swap_amount), taker_balance);

    let maker_new_balance = geth_erc1155_balance(maker_address, U256::from(token_id));
    assert_eq!(U256::from(1u32), maker_new_balance);
}

#[test]
fn test_nonce_several_urls() {
    // Use one working and one failing URL.
    let coin = eth_coin_with_random_privkey_using_urls(swap_contract(), &[GETH_RPC_URL, "http://127.0.0.1:0"]);
    let my_address = block_on(coin.derivation_method().single_addr_or_err()).unwrap();
    let (old_nonce, _) = coin.clone().get_addr_nonce(my_address).wait().unwrap();

    // Send a payment to increase the nonce.
    coin.send_to_address(my_address, 200000000.into()).wait().unwrap();

    let (new_nonce, _) = coin.get_addr_nonce(my_address).wait().unwrap();
    assert_eq!(old_nonce + 1, new_nonce);
}

#[test]
fn test_nonce_lock() {
    use futures::future::join_all;

    let coin = eth_coin_with_random_privkey(swap_contract());
    let my_address = block_on(coin.derivation_method().single_addr_or_err()).unwrap();
    let futures = (0..5).map(|_| coin.send_to_address(my_address, 200000000.into()).compat());
    let results = block_on(join_all(futures));

    // make sure all transactions are successful
    for result in results {
        result.unwrap();
    }
}

#[test]
fn send_and_refund_erc721_maker_payment_timelock() {
    let token_id = 2u32;
    let time_lock_to_refund = now_sec() - 1000;
    let activation = NftActivationV2Args::init();
    let setup = setup_test(
        token_id,
        None,
        ContractType::Erc721,
        geth_erc721_contract(),
        time_lock_to_refund,
        activation,
    );

    let maker_payment_to_refund = send_nft_maker_payment(&setup, 1.into());
    log!(
        "Maker sent ERC721 NFT payment, tx hash: {:02x}",
        maker_payment_to_refund.tx_hash()
    );

    wait_for_confirmations(&setup.maker_global_nft, &maker_payment_to_refund, 150);
    let current_owner = geth_erc712_owner(U256::from(token_id));
    assert_eq!(current_owner, geth_nft_maker_swap_v2());

    let refund_timelock_tx = refund_nft_maker_payment(
        &setup,
        &maker_payment_to_refund,
        &ContractType::Erc721,
        RefundType::Timelock,
    );
    log!(
        "Maker refunded ERC721 NFT payment after timelock, tx hash: {:02x}",
        refund_timelock_tx.tx_hash()
    );

    wait_for_confirmations(&setup.maker_global_nft, &refund_timelock_tx, 150);
    let current_owner = geth_erc712_owner(U256::from(token_id));
    let maker_address = block_on(setup.maker_global_nft.my_addr());
    assert_eq!(current_owner, maker_address);
}

#[test]
fn send_and_refund_erc1155_maker_payment_timelock() {
    let token_id = 2u32;
    let amount = 3u32;
    let time_lock_to_refund = now_sec() - 1000;
    let activation = NftActivationV2Args::init();
    let setup = setup_test(
        token_id,
        Some(amount),
        ContractType::Erc1155,
        geth_erc1155_contract(),
        time_lock_to_refund,
        activation,
    );

    let maker_address = block_on(setup.maker_global_nft.my_addr());
    let balance = geth_erc1155_balance(maker_address, U256::from(token_id));
    assert_eq!(U256::from(amount), balance);

    let swap_amount = 2u32;
    let maker_payment_to_refund = send_nft_maker_payment(&setup, swap_amount.into());
    log!(
        "Maker sent ERC1155 NFT payment, tx hash: {:02x}",
        maker_payment_to_refund.tx_hash()
    );

    wait_for_confirmations(&setup.maker_global_nft, &maker_payment_to_refund, 150);

    let swap_contract_balance = geth_erc1155_balance(geth_nft_maker_swap_v2(), U256::from(token_id));
    assert_eq!(U256::from(swap_amount), swap_contract_balance);
    let balance = geth_erc1155_balance(maker_address, U256::from(token_id));
    assert_eq!(U256::from(1u32), balance);

    let refund_timelock_tx = refund_nft_maker_payment(
        &setup,
        &maker_payment_to_refund,
        &ContractType::Erc1155,
        RefundType::Timelock,
    );
    log!(
        "Maker refunded ERC1155 NFT payment after timelock, tx hash: {:02x}",
        refund_timelock_tx.tx_hash()
    );

    wait_for_confirmations(&setup.maker_global_nft, &refund_timelock_tx, 150);

    let balance = geth_erc1155_balance(maker_address, U256::from(token_id));
    assert_eq!(U256::from(amount), balance);
}

#[test]
fn send_and_refund_erc721_maker_payment_secret() {
    let token_id = 3u32;
    let time_lock_to_refund = now_sec() + 1000;
    let activation = NftActivationV2Args::init();
    let setup = setup_test(
        token_id,
        None,
        ContractType::Erc721,
        geth_erc721_contract(),
        time_lock_to_refund,
        activation,
    );

    let maker_payment_to_refund = send_nft_maker_payment(&setup, 1.into());
    log!(
        "Maker sent ERC721 NFT payment, tx hash: {:02x}",
        maker_payment_to_refund.tx_hash()
    );

    wait_for_confirmations(&setup.maker_global_nft, &maker_payment_to_refund, 150);
    let current_owner = geth_erc712_owner(U256::from(token_id));
    assert_eq!(current_owner, geth_nft_maker_swap_v2());

    let refund_secret_tx = refund_nft_maker_payment(
        &setup,
        &maker_payment_to_refund,
        &ContractType::Erc721,
        RefundType::Secret,
    );
    log!(
        "Maker refunded ERC721 NFT payment using Taker secret, tx hash: {:02x}",
        refund_secret_tx.tx_hash()
    );

    wait_for_confirmations(&setup.maker_global_nft, &refund_secret_tx, 150);
    let current_owner = geth_erc712_owner(U256::from(token_id));
    let maker_address = block_on(setup.maker_global_nft.my_addr());
    assert_eq!(current_owner, maker_address);
}

#[test]
fn send_and_refund_erc1155_maker_payment_secret() {
    let token_id = 3u32;
    let amount = 3u32;
    let time_lock_to_refund = now_sec() + 1000;
    let activation = NftActivationV2Args::init();
    let setup = setup_test(
        token_id,
        Some(amount),
        ContractType::Erc1155,
        geth_erc1155_contract(),
        time_lock_to_refund,
        activation,
    );

    let maker_address = block_on(setup.maker_global_nft.my_addr());
    let balance = geth_erc1155_balance(maker_address, U256::from(token_id));
    assert_eq!(U256::from(amount), balance);

    let swap_amount = 2u32;
    let maker_payment_to_refund = send_nft_maker_payment(&setup, swap_amount.into());
    log!(
        "Maker sent ERC1155 NFT payment, tx hash: {:02x}",
        maker_payment_to_refund.tx_hash()
    );

    wait_for_confirmations(&setup.maker_global_nft, &maker_payment_to_refund, 100);

    let swap_contract_balance = geth_erc1155_balance(geth_nft_maker_swap_v2(), U256::from(token_id));
    assert_eq!(U256::from(swap_amount), swap_contract_balance);
    let balance = geth_erc1155_balance(maker_address, U256::from(token_id));
    assert_eq!(U256::from(1u32), balance);

    let refund_secret_tx = refund_nft_maker_payment(
        &setup,
        &maker_payment_to_refund,
        &ContractType::Erc1155,
        RefundType::Secret,
    );
    log!(
        "Maker refunded ERC1155 NFT payment using Taker secret, tx hash: {:02x}",
        refund_secret_tx.tx_hash()
    );

    wait_for_confirmations(&setup.maker_global_nft, &refund_secret_tx, 100);

    let balance = geth_erc1155_balance(maker_address, U256::from(token_id));
    assert_eq!(U256::from(amount), balance);
}

struct NftTestSetup {
    maker_global_nft: EthCoin,
    taker_global_nft: EthCoin,
    nft_swap_info: TestNftSwapInfo<EthCoin>,
    maker_secret: Vec<u8>,
    maker_secret_hash: Vec<u8>,
    taker_secret: Vec<u8>,
    taker_secret_hash: Vec<u8>,
    time_lock: u64,
}

/// Structure representing necessary NFT info for Swap
pub struct TestNftSwapInfo<Coin: ParseNftAssocTypes + ?Sized> {
    /// The address of the NFT token
    pub token_address: Coin::ContractAddress,
    /// The ID of the NFT token.
    pub token_id: Vec<u8>,
    /// The type of smart contract that governs this NFT
    pub contract_type: Coin::ContractType,
}

struct NftActivationV2Args {
    swap_contract_address: Address,
    fallback_swap_contract_address: Address,
    swap_v2_contracts: SwapV2Contracts,
    nft_ticker: String,
    platform_ticker: String,
}

impl NftActivationV2Args {
    fn init() -> Self {
        Self {
            swap_contract_address: swap_contract(),
            fallback_swap_contract_address: swap_contract(),
            swap_v2_contracts: SwapV2Contracts {
                maker_swap_v2_contract: maker_swap_v2(),
                taker_swap_v2_contract: taker_swap_v2(),
                nft_maker_swap_v2_contract: geth_nft_maker_swap_v2(),
            },
            nft_ticker: NFT_ETH.to_string(),
            platform_ticker: "ETH".to_string(),
        }
    }
}

fn setup_test(
    token_id: u32,
    amount: Option<u32>,
    contract_type: ContractType,
    token_contract: Address,
    time_lock: u64,
    activation: NftActivationV2Args,
) -> NftTestSetup {
    let nft_type = match contract_type {
        ContractType::Erc721 => TestNftType::Erc721 { token_id },
        ContractType::Erc1155 => TestNftType::Erc1155 {
            token_id,
            amount: amount.unwrap(),
        },
    };

    let maker_global_nft = global_nft_with_random_privkey(
        activation.swap_v2_contracts,
        activation.swap_contract_address,
        activation.fallback_swap_contract_address,
        Some(nft_type),
        activation.nft_ticker.clone(),
        activation.platform_ticker.clone(),
    );
    let taker_global_nft = global_nft_with_random_privkey(
        activation.swap_v2_contracts,
        activation.swap_contract_address,
        activation.fallback_swap_contract_address,
        None,
        activation.nft_ticker,
        activation.platform_ticker,
    );
    let maker_secret = vec![1; 32];
    let maker_secret_hash = sha256(&maker_secret).to_vec();
    let taker_secret = vec![0; 32];
    let taker_secret_hash = sha256(&taker_secret).to_vec();

    let token_id = BigUint::from(token_id).to_bytes();

    let nft_swap_info = TestNftSwapInfo {
        token_address: token_contract,
        token_id,
        contract_type,
    };

    NftTestSetup {
        maker_global_nft,
        taker_global_nft,
        nft_swap_info,
        maker_secret,
        maker_secret_hash,
        taker_secret,
        taker_secret_hash,
        time_lock,
    }
}

fn send_nft_maker_payment(setup: &NftTestSetup, amount: BigDecimal) -> SignedEthTx {
    let nft_swap_info = NftSwapInfo {
        token_address: &setup.nft_swap_info.token_address,
        token_id: &setup.nft_swap_info.token_id,
        contract_type: &setup.nft_swap_info.contract_type,
    };
    let send_payment_args = SendNftMakerPaymentArgs::<EthCoin> {
        time_lock: setup.time_lock,
        taker_secret_hash: &setup.taker_secret_hash,
        maker_secret_hash: &setup.maker_secret_hash,
        amount,
        taker_pub: &setup.taker_global_nft.derive_htlc_pubkey_v2(&[]),
        swap_unique_data: &[],
        nft_swap_info: &nft_swap_info,
    };
    block_on(setup.maker_global_nft.send_nft_maker_payment_v2(send_payment_args)).unwrap()
}

fn wait_for_confirmations(coin: &EthCoin, tx: &SignedEthTx, wait_seconds: u64) {
    let confirm_input = ConfirmPaymentInput {
        payment_tx: tx.tx_hex(),
        confirmations: 1,
        requires_nota: false,
        wait_until: now_sec() + wait_seconds,
        check_every: 1,
    };
    coin.wait_for_confirmations(confirm_input).wait().unwrap();
}

fn validate_nft_maker_payment(setup: &NftTestSetup, maker_payment: &SignedEthTx, amount: BigDecimal) {
    let nft_swap_info = NftSwapInfo {
        token_address: &setup.nft_swap_info.token_address,
        token_id: &setup.nft_swap_info.token_id,
        contract_type: &setup.nft_swap_info.contract_type,
    };
    let validate_args = ValidateNftMakerPaymentArgs {
        maker_payment_tx: maker_payment,
        time_lock: setup.time_lock,
        taker_secret_hash: &setup.taker_secret_hash,
        maker_secret_hash: &setup.maker_secret_hash,
        amount,
        taker_pub: &setup.taker_global_nft.derive_htlc_pubkey_v2(&[]),
        maker_pub: &setup.maker_global_nft.derive_htlc_pubkey_v2(&[]),
        swap_unique_data: &[],
        nft_swap_info: &nft_swap_info,
    };
    block_on(setup.maker_global_nft.validate_nft_maker_payment_v2(validate_args)).unwrap()
}

fn spend_nft_maker_payment(
    setup: &NftTestSetup,
    maker_payment: &SignedEthTx,
    contract_type: &ContractType,
) -> SignedEthTx {
    let spend_payment_args = SpendNftMakerPaymentArgs {
        maker_payment_tx: maker_payment,
        taker_secret_hash: &setup.taker_secret_hash,
        maker_secret_hash: &setup.maker_secret_hash,
        maker_secret: &setup.maker_secret,
        maker_pub: &setup.maker_global_nft.derive_htlc_pubkey_v2(&[]),
        swap_unique_data: &[],
        contract_type,
    };
    block_on(setup.taker_global_nft.spend_nft_maker_payment_v2(spend_payment_args)).unwrap()
}

fn refund_nft_maker_payment(
    setup: &NftTestSetup,
    maker_payment: &SignedEthTx,
    contract_type: &ContractType,
    refund_type: RefundType,
) -> SignedEthTx {
    let refund_args = RefundNftMakerPaymentArgs {
        maker_payment_tx: maker_payment,
        taker_secret_hash: &setup.taker_secret_hash,
        maker_secret_hash: &setup.maker_secret_hash,
        taker_secret: &setup.taker_secret,
        swap_unique_data: &[],
        contract_type,
    };
    match refund_type {
        RefundType::Timelock => {
            block_on(setup.maker_global_nft.refund_nft_maker_payment_v2_timelock(refund_args)).unwrap()
        },
        RefundType::Secret => block_on(setup.maker_global_nft.refund_nft_maker_payment_v2_secret(refund_args)).unwrap(),
    }
}

enum RefundType {
    Timelock,
    Secret,
}

#[derive(Copy, Clone)]
struct SwapAddresses {
    swap_v2_contracts: SwapV2Contracts,
    swap_contract_address: Address,
    fallback_swap_contract_address: Address,
}

#[allow(dead_code)]
/// Needed for Geth taker or maker swap v2 tests
impl SwapAddresses {
    fn init() -> Self {
        Self {
            swap_contract_address: swap_contract(),
            fallback_swap_contract_address: swap_contract(),
            swap_v2_contracts: SwapV2Contracts {
                maker_swap_v2_contract: maker_swap_v2(),
                taker_swap_v2_contract: taker_swap_v2(),
                nft_maker_swap_v2_contract: geth_nft_maker_swap_v2(),
            },
        }
    }
}

#[allow(dead_code)]
/// Needed for eth or erc20 v2 activation in Geth tests
fn eth_coin_v2_activation_with_random_privkey(
    ticker: &str,
    conf: &Json,
    swap_addr: SwapAddresses,
    erc20: bool,
) -> EthCoin {
    let build_policy = EthPrivKeyBuildPolicy::IguanaPrivKey(random_secp256k1_secret());
    let node = EthNode {
        url: GETH_RPC_URL.to_string(),
        komodo_proxy: false,
    };
    let platform_request = EthActivationV2Request {
        nodes: vec![node],
        rpc_mode: Default::default(),
        swap_contract_address: swap_addr.swap_contract_address,
        swap_v2_contracts: Some(swap_addr.swap_v2_contracts),
        fallback_swap_contract: Some(swap_addr.fallback_swap_contract_address),
        contract_supports_watchers: false,
        mm2: None,
        required_confirmations: None,
        priv_key_policy: Default::default(),
        enable_params: Default::default(),
        path_to_address: Default::default(),
        gap_limit: None,
    };
    let coin = block_on(eth_coin_from_conf_and_request_v2(
        &MM_CTX1,
        ticker,
        conf,
        platform_request,
        build_policy,
    ))
    .unwrap();
    let my_address = block_on(coin.my_addr());
    fill_eth(my_address, U256::from(10).pow(U256::from(20)));
    fill_erc20(my_address, U256::from(10000000000u64));
    if erc20 {
        let coin_type = EthCoinType::Erc20 {
            platform: ETH.to_string(),
            token_addr: erc20_contract(),
        };
        let coin = block_on(coin.set_coin_type(coin_type));
        return coin;
    }
    coin
}

#[cfg(feature = "sepolia-taker-swap-v2-tests")]
#[test]
fn send_and_refund_taker_funding_by_secret_eth() {
    let _guard = SEPOLIA_TESTS_LOCK.lock().unwrap();

    let taker_coin = get_or_create_sepolia_coin(&MM_CTX1, SEPOLIA_TAKER_PRIV, ETH, &eth_sepolia_conf(), false);
    let maker_coin = get_or_create_sepolia_coin(&MM_CTX, SEPOLIA_MAKER_PRIV, ETH, &eth_sepolia_conf(), false);

    let taker_secret = vec![0; 32];
    let taker_secret_hash = sha256(&taker_secret).to_vec();
    let maker_secret = vec![1; 32];
    let maker_secret_hash = sha256(&maker_secret).to_vec();
    let funding_time_lock = now_sec() + 3000;
    let payment_time_lock = now_sec() + 1000;

    let taker_address = block_on(taker_coin.my_addr());

    let dex_fee = &DexFee::Standard("0.00001".into());
    let trading_amount = BigDecimal::from_str("0.0001").unwrap();

    let maker_pub = &maker_coin.derive_htlc_pubkey_v2(&[]);
    let payment_args = SendTakerFundingArgs {
        funding_time_lock,
        payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        maker_pub: maker_pub.as_bytes(),
        dex_fee,
        premium_amount: BigDecimal::default(),
        trading_amount: trading_amount.clone(),
        swap_unique_data: &[],
    };

    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    thread::sleep(Duration::from_secs(2));
    let funding_tx = block_on(taker_coin.send_taker_funding(payment_args)).unwrap();
    log!("Taker sent ETH funding, tx hash: {:02x}", funding_tx.tx_hash());

    let refund_args = RefundFundingSecretArgs {
        funding_tx: &funding_tx,
        funding_time_lock,
        payment_time_lock,
        maker_pubkey: maker_pub,
        taker_secret: &taker_secret,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        dex_fee,
        premium_amount: Default::default(),
        trading_amount,
        swap_unique_data: &[],
        watcher_reward: false,
    };
    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    let funding_tx_refund = block_on(taker_coin.refund_taker_funding_secret(refund_args)).unwrap();
    log!(
        "Taker refunded ETH funding by secret, tx hash: {:02x}",
        funding_tx_refund.tx_hash()
    );

    wait_for_confirmations(&taker_coin, &funding_tx_refund, 100);
}

#[cfg(feature = "sepolia-taker-swap-v2-tests")]
#[test]
fn send_and_refund_taker_funding_by_secret_erc20() {
    let _guard = SEPOLIA_TESTS_LOCK.lock().unwrap();

    let erc20_conf = &sepolia_erc20_dev_conf(&sepolia_erc20_contract_checksum());
    let taker_coin = get_or_create_sepolia_coin(&MM_CTX1, SEPOLIA_TAKER_PRIV, ERC20, erc20_conf, true);
    let maker_coin = get_or_create_sepolia_coin(&MM_CTX1, SEPOLIA_MAKER_PRIV, ERC20, erc20_conf, true);

    let taker_secret = vec![0; 32];
    let taker_secret_hash = sha256(&taker_secret).to_vec();
    let maker_secret = vec![1; 32];
    let maker_secret_hash = sha256(&maker_secret).to_vec();

    let taker_address = block_on(taker_coin.my_addr());

    let funding_time_lock = now_sec() + 3000;
    let payment_time_lock = now_sec() + 1000;

    let dex_fee = &DexFee::Standard("0.00001".into());
    let trading_amount = BigDecimal::from_str("0.0001").unwrap();

    let maker_pub = &maker_coin.derive_htlc_pubkey_v2(&[]);
    let payment_args = SendTakerFundingArgs {
        funding_time_lock,
        payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        maker_pub: maker_pub.as_bytes(),
        dex_fee,
        premium_amount: BigDecimal::default(),
        trading_amount: trading_amount.clone(),
        swap_unique_data: &[],
    };

    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    let funding_tx = block_on(taker_coin.send_taker_funding(payment_args)).unwrap();
    log!("Taker sent ERC20 funding, tx hash: {:02x}", funding_tx.tx_hash());
    wait_for_confirmations(&taker_coin, &funding_tx, 200);

    let refund_args = RefundFundingSecretArgs {
        funding_tx: &funding_tx,
        funding_time_lock,
        payment_time_lock,
        maker_pubkey: &taker_coin.derive_htlc_pubkey_v2(&[]),
        taker_secret: &taker_secret,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        dex_fee,
        premium_amount: Default::default(),
        trading_amount,
        swap_unique_data: &[],
        watcher_reward: false,
    };
    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    let funding_tx_refund = block_on(taker_coin.refund_taker_funding_secret(refund_args)).unwrap();
    log!(
        "Taker refunded ERC20 funding by secret, tx hash: {:02x}",
        funding_tx_refund.tx_hash()
    );
    wait_for_confirmations(&taker_coin, &funding_tx_refund, 200);
}

#[cfg(feature = "sepolia-taker-swap-v2-tests")]
#[test]
fn send_and_refund_taker_funding_exceed_pre_approve_timelock_eth() {
    let _guard = SEPOLIA_TESTS_LOCK.lock().unwrap();

    let taker_coin = get_or_create_sepolia_coin(&MM_CTX1, SEPOLIA_TAKER_PRIV, ETH, &eth_sepolia_conf(), false);
    let maker_coin = get_or_create_sepolia_coin(&MM_CTX, SEPOLIA_MAKER_PRIV, ETH, &eth_sepolia_conf(), false);

    let taker_secret = vec![0; 32];
    let taker_secret_hash = sha256(&taker_secret).to_vec();
    let maker_secret = vec![1; 32];
    let maker_secret_hash = sha256(&maker_secret).to_vec();

    let taker_address = block_on(taker_coin.my_addr());

    // if TakerPaymentState is `PaymentSent` then timestamp should exceed payment pre-approve lock time (funding_time_lock)
    let funding_time_lock = now_sec() - 3000;
    let payment_time_lock = now_sec() + 1000;

    let dex_fee = &DexFee::Standard("0.00001".into());
    let trading_amount = BigDecimal::from_str("0.0001").unwrap();

    let maker_pub = &maker_coin.derive_htlc_pubkey_v2(&[]);
    let payment_args = SendTakerFundingArgs {
        funding_time_lock,
        payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        maker_pub: maker_pub.as_bytes(),
        dex_fee,
        premium_amount: BigDecimal::default(),
        trading_amount: trading_amount.clone(),
        swap_unique_data: &[],
    };
    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    let funding_tx = block_on(taker_coin.send_taker_funding(payment_args)).unwrap();
    log!("Taker sent ETH funding, tx hash: {:02x}", funding_tx.tx_hash());
    wait_for_confirmations(&taker_coin, &funding_tx, 100);

    let tx_type_with_secret_hash = SwapTxTypeWithSecretHash::TakerPaymentV2 {
        maker_secret_hash: &maker_secret_hash,
        taker_secret_hash: &taker_secret_hash,
    };

    let refund_args = RefundTakerPaymentArgs {
        payment_tx: &funding_tx.to_bytes(),
        time_lock: payment_time_lock,
        maker_pub: maker_pub.as_bytes(),
        tx_type_with_secret_hash,
        swap_unique_data: &[],
        watcher_reward: false,
        dex_fee,
        premium_amount: BigDecimal::default(),
        trading_amount,
    };
    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    let funding_tx_refund = block_on(taker_coin.refund_taker_funding_timelock(refund_args)).unwrap();
    log!(
        "Taker refunded ETH funding after pre-approval lock time was exceeded, tx hash: {:02x}",
        funding_tx_refund.tx_hash()
    );

    wait_for_confirmations(&taker_coin, &funding_tx_refund, 100);
}

#[cfg(feature = "sepolia-taker-swap-v2-tests")]
#[test]
fn taker_send_approve_and_spend_eth() {
    let _guard = SEPOLIA_TESTS_LOCK.lock().unwrap();

    let taker_coin = get_or_create_sepolia_coin(&MM_CTX1, SEPOLIA_TAKER_PRIV, ETH, &eth_sepolia_conf(), false);
    let maker_coin = get_or_create_sepolia_coin(&MM_CTX, SEPOLIA_MAKER_PRIV, ETH, &eth_sepolia_conf(), false);

    let taker_secret = vec![0; 32];
    let taker_secret_hash = sha256(&taker_secret).to_vec();
    let maker_secret = vec![1; 32];
    let maker_secret_hash = sha256(&maker_secret).to_vec();
    let funding_time_lock = now_sec() + 3000;
    let payment_time_lock = now_sec() + 600;

    let taker_address = block_on(taker_coin.my_addr());
    let maker_address = block_on(maker_coin.my_addr());

    let dex_fee = &DexFee::Standard("0.00001".into());
    let trading_amount = BigDecimal::from_str("0.0001").unwrap();

    let maker_pub = &maker_coin.derive_htlc_pubkey_v2(&[]);
    let payment_args = SendTakerFundingArgs {
        funding_time_lock,
        payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        maker_pub: maker_pub.as_bytes(),
        dex_fee,
        premium_amount: BigDecimal::default(),
        trading_amount: trading_amount.clone(),
        swap_unique_data: &[],
    };
    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    let funding_tx = block_on(taker_coin.send_taker_funding(payment_args)).unwrap();
    log!("Taker sent ETH funding, tx hash: {:02x}", funding_tx.tx_hash());
    wait_for_confirmations(&taker_coin, &funding_tx, 100);

    let taker_pub = &taker_coin.derive_htlc_pubkey_v2(&[]);
    let validate = ValidateTakerFundingArgs {
        funding_tx: &funding_tx,
        funding_time_lock,
        payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        taker_pub,
        dex_fee,
        premium_amount: Default::default(),
        trading_amount: trading_amount.clone(),
        swap_unique_data: &[],
    };
    block_on(maker_coin.validate_taker_funding(validate)).unwrap();

    let approve_args = GenTakerFundingSpendArgs {
        funding_tx: &funding_tx,
        maker_pub,
        taker_pub,
        funding_time_lock,
        taker_secret_hash: &taker_secret_hash,
        taker_payment_time_lock: funding_time_lock,
        maker_secret_hash: &maker_secret_hash,
    };
    let preimage = TxPreimageWithSig {
        preimage: funding_tx.clone(),
        signature: taker_coin.parse_signature(&[0u8; 65]).unwrap(),
    };
    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    let taker_approve_tx =
        block_on(taker_coin.sign_and_send_taker_funding_spend(&preimage, &approve_args, &[])).unwrap();
    log!(
        "Taker approved ETH payment, tx hash: {:02x}",
        taker_approve_tx.tx_hash()
    );
    wait_for_confirmations(&taker_coin, &taker_approve_tx, 100);

    wait_pending_transactions(Address::from_slice(maker_address.as_bytes()));
    let check_taker_approved_tx = block_on(maker_coin.search_for_taker_funding_spend(&taker_approve_tx, 0u64, &[]))
        .unwrap()
        .unwrap();
    match check_taker_approved_tx {
        FundingTxSpend::TransferredToTakerPayment(tx) => {
            assert_eq!(tx, taker_approve_tx);
        },
        FundingTxSpend::RefundedTimelock(_) | FundingTxSpend::RefundedSecret { .. } => {
            panic!("Wrong FundingTxSpend variant, expected TransferredToTakerPayment")
        },
    };

    let dex_fee_pub = sepolia_taker_swap_v2();
    let spend_args = GenTakerPaymentSpendArgs {
        taker_tx: &taker_approve_tx,
        time_lock: payment_time_lock,
        maker_secret_hash: &maker_secret_hash,
        maker_pub,
        maker_address: &maker_address,
        taker_pub,
        dex_fee_pub: dex_fee_pub.as_bytes(),
        dex_fee,
        premium_amount: Default::default(),
        trading_amount,
    };
    wait_pending_transactions(Address::from_slice(maker_address.as_bytes()));
    let spend_tx =
        block_on(maker_coin.sign_and_broadcast_taker_payment_spend(&preimage, &spend_args, &maker_secret, &[]))
            .unwrap();
    log!("Maker spent ETH payment, tx hash: {:02x}", spend_tx.tx_hash());
    wait_for_confirmations(&maker_coin, &spend_tx, 100);
    block_on(taker_coin.wait_for_taker_payment_spend(&spend_tx, 0u64, payment_time_lock)).unwrap();
}

#[cfg(feature = "sepolia-taker-swap-v2-tests")]
#[test]
fn taker_send_approve_and_spend_erc20() {
    let _guard = SEPOLIA_TESTS_LOCK.lock().unwrap();

    let erc20_conf = &sepolia_erc20_dev_conf(&sepolia_erc20_contract_checksum());
    let taker_coin = get_or_create_sepolia_coin(&MM_CTX1, SEPOLIA_TAKER_PRIV, ERC20, erc20_conf, true);
    let maker_coin = get_or_create_sepolia_coin(&MM_CTX, SEPOLIA_MAKER_PRIV, ERC20, erc20_conf, true);

    let taker_secret = vec![0; 32];
    let taker_secret_hash = sha256(&taker_secret).to_vec();
    let maker_secret = vec![1; 32];
    let maker_secret_hash = sha256(&maker_secret).to_vec();
    let funding_time_lock = now_sec() + 3000;
    let payment_time_lock = now_sec() + 600;

    let taker_address = block_on(taker_coin.my_addr());
    let maker_address = block_on(maker_coin.my_addr());

    let dex_fee = &DexFee::Standard("0.00001".into());
    let trading_amount = BigDecimal::from_str("0.0001").unwrap();

    let maker_pub = &maker_coin.derive_htlc_pubkey_v2(&[]);
    let payment_args = SendTakerFundingArgs {
        funding_time_lock,
        payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        maker_pub: maker_pub.as_bytes(),
        dex_fee,
        premium_amount: BigDecimal::default(),
        trading_amount: trading_amount.clone(),
        swap_unique_data: &[],
    };
    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    let funding_tx = block_on(taker_coin.send_taker_funding(payment_args)).unwrap();
    log!("Taker sent ERC20 funding, tx hash: {:02x}", funding_tx.tx_hash());
    wait_for_confirmations(&taker_coin, &funding_tx, 100);

    let taker_pub = &taker_coin.derive_htlc_pubkey_v2(&[]);
    let validate = ValidateTakerFundingArgs {
        funding_tx: &funding_tx,
        funding_time_lock,
        payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        taker_pub,
        dex_fee,
        premium_amount: Default::default(),
        trading_amount: trading_amount.clone(),
        swap_unique_data: &[],
    };
    block_on(maker_coin.validate_taker_funding(validate)).unwrap();

    let approve_args = GenTakerFundingSpendArgs {
        funding_tx: &funding_tx,
        maker_pub,
        taker_pub,
        funding_time_lock,
        taker_secret_hash: &taker_secret_hash,
        taker_payment_time_lock: funding_time_lock,
        maker_secret_hash: &maker_secret_hash,
    };
    let preimage = TxPreimageWithSig {
        preimage: funding_tx.clone(),
        signature: taker_coin.parse_signature(&[0u8; 65]).unwrap(),
    };
    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    let taker_approve_tx =
        block_on(taker_coin.sign_and_send_taker_funding_spend(&preimage, &approve_args, &[])).unwrap();
    log!(
        "Taker approved ERC20 payment, tx hash: {:02x}",
        taker_approve_tx.tx_hash()
    );
    wait_for_confirmations(&taker_coin, &taker_approve_tx, 100);

    wait_pending_transactions(Address::from_slice(maker_address.as_bytes()));
    let check_taker_approved_tx = block_on(maker_coin.search_for_taker_funding_spend(&taker_approve_tx, 0u64, &[]))
        .unwrap()
        .unwrap();
    match check_taker_approved_tx {
        FundingTxSpend::TransferredToTakerPayment(tx) => {
            assert_eq!(tx, taker_approve_tx);
        },
        FundingTxSpend::RefundedTimelock(_) | FundingTxSpend::RefundedSecret { .. } => {
            panic!("Wrong FundingTxSpend variant, expected TransferredToTakerPayment")
        },
    };

    let dex_fee_pub = sepolia_taker_swap_v2();
    let spend_args = GenTakerPaymentSpendArgs {
        taker_tx: &taker_approve_tx,
        time_lock: payment_time_lock,
        maker_secret_hash: &maker_secret_hash,
        maker_pub,
        maker_address: &maker_address,
        taker_pub,
        dex_fee_pub: dex_fee_pub.as_bytes(),
        dex_fee,
        premium_amount: Default::default(),
        trading_amount,
    };
    wait_pending_transactions(Address::from_slice(maker_address.as_bytes()));
    let spend_tx =
        block_on(maker_coin.sign_and_broadcast_taker_payment_spend(&preimage, &spend_args, &maker_secret, &[]))
            .unwrap();
    log!("Maker spent ERC20 payment, tx hash: {:02x}", spend_tx.tx_hash());
    block_on(taker_coin.wait_for_taker_payment_spend(&spend_tx, 0u64, payment_time_lock)).unwrap();
}

#[cfg(feature = "sepolia-taker-swap-v2-tests")]
#[test]
fn send_and_refund_taker_funding_exceed_payment_timelock_eth() {
    let _guard = SEPOLIA_TESTS_LOCK.lock().unwrap();

    let taker_coin = get_or_create_sepolia_coin(&MM_CTX1, SEPOLIA_TAKER_PRIV, ETH, &eth_sepolia_conf(), false);
    let maker_coin = get_or_create_sepolia_coin(&MM_CTX, SEPOLIA_MAKER_PRIV, ETH, &eth_sepolia_conf(), false);

    let taker_secret = vec![0; 32];
    let taker_secret_hash = sha256(&taker_secret).to_vec();
    let maker_secret = vec![1; 32];
    let maker_secret_hash = sha256(&maker_secret).to_vec();
    let funding_time_lock = now_sec() + 3000;
    let payment_time_lock = now_sec() - 1000;

    let taker_address = block_on(taker_coin.my_addr());

    let dex_fee = &DexFee::Standard("0.00001".into());
    let trading_amount = BigDecimal::from_str("0.0001").unwrap();

    let maker_pub = &maker_coin.derive_htlc_pubkey_v2(&[]);
    let payment_args = SendTakerFundingArgs {
        funding_time_lock,
        payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        maker_pub: maker_pub.as_bytes(),
        dex_fee,
        premium_amount: BigDecimal::default(),
        trading_amount: trading_amount.clone(),
        swap_unique_data: &[],
    };
    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    let funding_tx = block_on(taker_coin.send_taker_funding(payment_args)).unwrap();
    log!("Taker sent ETH funding, tx hash: {:02x}", funding_tx.tx_hash());
    wait_for_confirmations(&taker_coin, &funding_tx, 100);

    let taker_pub = &taker_coin.derive_htlc_pubkey_v2(&[]);
    let approve_args = GenTakerFundingSpendArgs {
        funding_tx: &funding_tx,
        maker_pub,
        taker_pub,
        funding_time_lock,
        taker_secret_hash: &taker_secret_hash,
        taker_payment_time_lock: funding_time_lock,
        maker_secret_hash: &maker_secret_hash,
    };
    let preimage = TxPreimageWithSig {
        preimage: funding_tx.clone(),
        signature: taker_coin.parse_signature(&[0u8; 65]).unwrap(),
    };
    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    let taker_approve_tx =
        block_on(taker_coin.sign_and_send_taker_funding_spend(&preimage, &approve_args, &[])).unwrap();
    log!(
        "Taker approved ETH payment, tx hash: {:02x}",
        taker_approve_tx.tx_hash()
    );
    wait_for_confirmations(&taker_coin, &taker_approve_tx, 100);

    let tx_type_with_secret_hash = SwapTxTypeWithSecretHash::TakerPaymentV2 {
        maker_secret_hash: &maker_secret_hash,
        taker_secret_hash: &taker_secret_hash,
    };
    let refund_args = RefundTakerPaymentArgs {
        payment_tx: &funding_tx.to_bytes(),
        time_lock: payment_time_lock,
        maker_pub: maker_pub.as_bytes(),
        tx_type_with_secret_hash,
        swap_unique_data: &[],
        watcher_reward: false,
        dex_fee,
        premium_amount: BigDecimal::default(),
        trading_amount,
    };
    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    let funding_tx_refund = block_on(taker_coin.refund_taker_funding_timelock(refund_args)).unwrap();
    log!(
        "Taker refunded ETH funding after payment lock time was exceeded, tx hash: {:02x}",
        funding_tx_refund.tx_hash()
    );
    wait_for_confirmations(&taker_coin, &funding_tx_refund, 100);
}

#[cfg(feature = "sepolia-taker-swap-v2-tests")]
#[test]
fn send_and_refund_taker_funding_exceed_payment_timelock_erc20() {
    let _guard = SEPOLIA_TESTS_LOCK.lock().unwrap();

    let erc20_conf = &sepolia_erc20_dev_conf(&sepolia_erc20_contract_checksum());
    let taker_coin = get_or_create_sepolia_coin(&MM_CTX1, SEPOLIA_TAKER_PRIV, ERC20, erc20_conf, true);
    let maker_coin = get_or_create_sepolia_coin(&MM_CTX, SEPOLIA_MAKER_PRIV, ERC20, erc20_conf, true);

    let taker_secret = vec![0; 32];
    let taker_secret_hash = sha256(&taker_secret).to_vec();
    let maker_secret = vec![1; 32];
    let maker_secret_hash = sha256(&maker_secret).to_vec();
    let funding_time_lock = now_sec() + 29;
    let payment_time_lock = now_sec() + 15;

    let taker_address = block_on(taker_coin.my_addr());

    let dex_fee = &DexFee::Standard("0.00001".into());
    let trading_amount = BigDecimal::from_str("0.0001").unwrap();

    let maker_pub = &maker_coin.derive_htlc_pubkey_v2(&[]);
    let payment_args = SendTakerFundingArgs {
        funding_time_lock,
        payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        maker_pub: maker_pub.as_bytes(),
        dex_fee,
        premium_amount: BigDecimal::default(),
        trading_amount: trading_amount.clone(),
        swap_unique_data: &[],
    };
    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    let funding_tx = block_on(taker_coin.send_taker_funding(payment_args)).unwrap();
    log!("Taker sent ERC20 funding, tx hash: {:02x}", funding_tx.tx_hash());
    wait_for_confirmations(&taker_coin, &funding_tx, 100);
    thread::sleep(Duration::from_secs(16));

    let taker_pub = &taker_coin.derive_htlc_pubkey_v2(&[]);
    let approve_args = GenTakerFundingSpendArgs {
        funding_tx: &funding_tx,
        maker_pub,
        taker_pub,
        funding_time_lock,
        taker_secret_hash: &taker_secret_hash,
        taker_payment_time_lock: funding_time_lock,
        maker_secret_hash: &maker_secret_hash,
    };
    let preimage = TxPreimageWithSig {
        preimage: funding_tx.clone(),
        signature: taker_coin.parse_signature(&[0u8; 65]).unwrap(),
    };
    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    let taker_approve_tx =
        block_on(taker_coin.sign_and_send_taker_funding_spend(&preimage, &approve_args, &[])).unwrap();
    log!(
        "Taker approved ERC20 payment, tx hash: {:02x}",
        taker_approve_tx.tx_hash()
    );
    wait_for_confirmations(&taker_coin, &taker_approve_tx, 100);

    let tx_type_with_secret_hash = SwapTxTypeWithSecretHash::TakerPaymentV2 {
        maker_secret_hash: &maker_secret_hash,
        taker_secret_hash: &taker_secret_hash,
    };
    let refund_args = RefundTakerPaymentArgs {
        payment_tx: &funding_tx.to_bytes(),
        time_lock: payment_time_lock,
        maker_pub: maker_pub.as_bytes(),
        tx_type_with_secret_hash,
        swap_unique_data: &[],
        watcher_reward: false,
        dex_fee,
        premium_amount: BigDecimal::default(),
        trading_amount,
    };
    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    let funding_tx_refund = block_on(taker_coin.refund_taker_funding_timelock(refund_args)).unwrap();
    log!(
        "Taker refunded ERC20 funding after payment lock time was exceeded, tx hash: {:02x}",
        funding_tx_refund.tx_hash()
    );
    wait_for_confirmations(&taker_coin, &funding_tx_refund, 100);
}

#[cfg(feature = "sepolia-taker-swap-v2-tests")]
#[test]
fn send_and_refund_taker_funding_exceed_pre_approve_timelock_erc20() {
    let _guard = SEPOLIA_TESTS_LOCK.lock().unwrap();

    let erc20_conf = &sepolia_erc20_dev_conf(&sepolia_erc20_contract_checksum());
    let taker_coin = get_or_create_sepolia_coin(&MM_CTX1, SEPOLIA_TAKER_PRIV, ERC20, erc20_conf, true);
    let maker_coin = get_or_create_sepolia_coin(&MM_CTX1, SEPOLIA_MAKER_PRIV, ERC20, erc20_conf, true);

    let taker_secret = vec![0; 32];
    let taker_secret_hash = sha256(&taker_secret).to_vec();
    let maker_secret = vec![1; 32];
    let maker_secret_hash = sha256(&maker_secret).to_vec();

    let taker_address = block_on(taker_coin.my_addr());

    // if TakerPaymentState is `PaymentSent` then timestamp should exceed payment pre-approve lock time (funding_time_lock)
    let funding_time_lock = now_sec() + 29;
    let payment_time_lock = now_sec() + 1000;

    let dex_fee = &DexFee::Standard("0.00001".into());
    let trading_amount = BigDecimal::from_str("0.0001").unwrap();

    let maker_pub = &maker_coin.derive_htlc_pubkey_v2(&[]);
    let payment_args = SendTakerFundingArgs {
        funding_time_lock,
        payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        maker_pub: maker_pub.as_bytes(),
        dex_fee,
        premium_amount: BigDecimal::default(),
        trading_amount: trading_amount.clone(),
        swap_unique_data: &[],
    };
    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    let funding_tx = block_on(taker_coin.send_taker_funding(payment_args)).unwrap();
    log!("Taker sent ERC20 funding, tx hash: {:02x}", funding_tx.tx_hash());
    wait_for_confirmations(&taker_coin, &funding_tx, 150);
    thread::sleep(Duration::from_secs(29));

    let tx_type_with_secret_hash = SwapTxTypeWithSecretHash::TakerPaymentV2 {
        maker_secret_hash: &maker_secret_hash,
        taker_secret_hash: &taker_secret_hash,
    };

    let refund_args = RefundTakerPaymentArgs {
        payment_tx: &funding_tx.to_bytes(),
        time_lock: payment_time_lock,
        maker_pub: maker_pub.as_bytes(),
        tx_type_with_secret_hash,
        swap_unique_data: &[],
        watcher_reward: false,
        dex_fee,
        premium_amount: BigDecimal::default(),
        trading_amount,
    };
    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    thread::sleep(Duration::from_secs(3));
    let funding_tx_refund = block_on(taker_coin.refund_taker_funding_timelock(refund_args)).unwrap();
    log!(
        "Taker refunded ERC20 funding after pre-approval lock time was exceeded, tx hash: {:02x}",
        funding_tx_refund.tx_hash()
    );
    wait_for_confirmations(&taker_coin, &funding_tx_refund, 150);
}

#[cfg(feature = "sepolia-maker-swap-v2-tests")]
#[test]
fn send_maker_payment_and_refund_timelock_eth() {
    let _guard = SEPOLIA_TESTS_LOCK.lock().unwrap();

    let taker_coin = get_or_create_sepolia_coin(&MM_CTX1, SEPOLIA_TAKER_PRIV, ETH, &eth_sepolia_conf(), false);
    let maker_coin = get_or_create_sepolia_coin(&MM_CTX, SEPOLIA_MAKER_PRIV, ETH, &eth_sepolia_conf(), false);

    let taker_secret = vec![0; 32];
    let taker_secret_hash = sha256(&taker_secret).to_vec();
    let maker_secret = vec![1; 32];
    let maker_secret_hash = sha256(&maker_secret).to_vec();
    let payment_time_lock = now_sec() - 1000;

    let maker_address = block_on(maker_coin.my_addr());
    let taker_pub = &taker_coin.derive_htlc_pubkey_v2(&[]);

    let trading_amount = BigDecimal::from_str("0.0001").unwrap();

    let payment_args = SendMakerPaymentArgs {
        time_lock: payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        amount: trading_amount.clone(),
        taker_pub,
        swap_unique_data: &[],
    };
    wait_pending_transactions(Address::from_slice(maker_address.as_bytes()));
    let payment_tx = block_on(maker_coin.send_maker_payment_v2(payment_args)).unwrap();
    log!("Maker sent ETH payment, tx hash: {:02x}", payment_tx.tx_hash());
    wait_for_confirmations(&maker_coin, &payment_tx, 100);

    let tx_type_with_secret_hash = SwapTxTypeWithSecretHash::MakerPaymentV2 {
        maker_secret_hash: &maker_secret_hash,
        taker_secret_hash: &taker_secret_hash,
    };
    let refund_args = RefundMakerPaymentTimelockArgs {
        payment_tx: &payment_tx.to_bytes(),
        time_lock: payment_time_lock,
        taker_pub: &taker_pub.to_bytes(),
        tx_type_with_secret_hash,
        swap_unique_data: &[],
        watcher_reward: false,
        amount: trading_amount,
    };
    wait_pending_transactions(Address::from_slice(maker_address.as_bytes()));
    let payment_tx_refund = block_on(maker_coin.refund_maker_payment_v2_timelock(refund_args)).unwrap();
    log!(
        "Maker refunded ETH payment after timelock, tx hash: {:02x}",
        payment_tx_refund.tx_hash()
    );
    wait_for_confirmations(&maker_coin, &payment_tx_refund, 100);
}

#[cfg(feature = "sepolia-maker-swap-v2-tests")]
#[test]
fn send_maker_payment_and_refund_timelock_erc20() {
    let _guard = SEPOLIA_TESTS_LOCK.lock().unwrap();

    let erc20_conf = &sepolia_erc20_dev_conf(&sepolia_erc20_contract_checksum());
    let taker_coin = get_or_create_sepolia_coin(&MM_CTX1, SEPOLIA_TAKER_PRIV, ERC20, erc20_conf, true);
    let maker_coin = get_or_create_sepolia_coin(&MM_CTX, SEPOLIA_MAKER_PRIV, ERC20, erc20_conf, true);

    let taker_secret = vec![0; 32];
    let taker_secret_hash = sha256(&taker_secret).to_vec();
    let maker_secret = vec![1; 32];
    let maker_secret_hash = sha256(&maker_secret).to_vec();
    let payment_time_lock = now_sec() - 1000;

    let maker_address = block_on(maker_coin.my_addr());
    let taker_pub = &taker_coin.derive_htlc_pubkey_v2(&[]);

    let trading_amount = BigDecimal::from_str("0.0001").unwrap();

    let payment_args = SendMakerPaymentArgs {
        time_lock: payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        amount: trading_amount.clone(),
        taker_pub,
        swap_unique_data: &[],
    };
    wait_pending_transactions(Address::from_slice(maker_address.as_bytes()));
    let payment_tx = block_on(maker_coin.send_maker_payment_v2(payment_args)).unwrap();
    log!("Maker sent ERC20 payment, tx hash: {:02x}", payment_tx.tx_hash());
    wait_for_confirmations(&maker_coin, &payment_tx, 100);

    let tx_type_with_secret_hash = SwapTxTypeWithSecretHash::MakerPaymentV2 {
        maker_secret_hash: &maker_secret_hash,
        taker_secret_hash: &taker_secret_hash,
    };
    let refund_args = RefundMakerPaymentTimelockArgs {
        payment_tx: &payment_tx.to_bytes(),
        time_lock: payment_time_lock,
        taker_pub: &taker_pub.to_bytes(),
        tx_type_with_secret_hash,
        swap_unique_data: &[],
        watcher_reward: false,
        amount: trading_amount,
    };
    wait_pending_transactions(Address::from_slice(maker_address.as_bytes()));
    let payment_tx_refund = block_on(maker_coin.refund_maker_payment_v2_timelock(refund_args)).unwrap();
    log!(
        "Maker refunded ERC20 payment after timelock, tx hash: {:02x}",
        payment_tx_refund.tx_hash()
    );
    wait_for_confirmations(&maker_coin, &payment_tx_refund, 100);
}

#[cfg(feature = "sepolia-maker-swap-v2-tests")]
#[test]
fn send_maker_payment_and_refund_secret_eth() {
    let _guard = SEPOLIA_TESTS_LOCK.lock().unwrap();

    let taker_coin = get_or_create_sepolia_coin(&MM_CTX1, SEPOLIA_TAKER_PRIV, ETH, &eth_sepolia_conf(), false);
    let maker_coin = get_or_create_sepolia_coin(&MM_CTX, SEPOLIA_MAKER_PRIV, ETH, &eth_sepolia_conf(), false);

    let taker_secret = vec![0; 32];
    let taker_secret_hash = sha256(&taker_secret).to_vec();
    let maker_secret = vec![1; 32];
    let maker_secret_hash = sha256(&maker_secret).to_vec();
    let payment_time_lock = now_sec() + 1000;

    let maker_address = block_on(maker_coin.my_addr());
    let taker_pub = &taker_coin.derive_htlc_pubkey_v2(&[]);

    let trading_amount = BigDecimal::from_str("0.0001").unwrap();

    let payment_args = SendMakerPaymentArgs {
        time_lock: payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        amount: trading_amount.clone(),
        taker_pub,
        swap_unique_data: &[],
    };
    wait_pending_transactions(Address::from_slice(maker_address.as_bytes()));
    let payment_tx = block_on(maker_coin.send_maker_payment_v2(payment_args)).unwrap();
    log!("Maker sent ETH payment, tx hash: {:02x}", payment_tx.tx_hash());
    wait_for_confirmations(&maker_coin, &payment_tx, 100);

    let refund_args = RefundMakerPaymentSecretArgs {
        maker_payment_tx: &payment_tx,
        time_lock: payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        taker_secret: &taker_secret,
        taker_pub,
        swap_unique_data: &[],
        amount: trading_amount,
    };
    wait_pending_transactions(Address::from_slice(maker_address.as_bytes()));
    let payment_tx_refund = block_on(maker_coin.refund_maker_payment_v2_secret(refund_args)).unwrap();
    log!(
        "Maker refunded ETH payment using taker secret, tx hash: {:02x}",
        payment_tx_refund.tx_hash()
    );
    wait_for_confirmations(&maker_coin, &payment_tx_refund, 100);
}

#[cfg(feature = "sepolia-maker-swap-v2-tests")]
#[test]
fn send_maker_payment_and_refund_secret_erc20() {
    let _guard = SEPOLIA_TESTS_LOCK.lock().unwrap();

    let erc20_conf = &sepolia_erc20_dev_conf(&sepolia_erc20_contract_checksum());
    let taker_coin = get_or_create_sepolia_coin(&MM_CTX1, SEPOLIA_TAKER_PRIV, ERC20, erc20_conf, true);
    let maker_coin = get_or_create_sepolia_coin(&MM_CTX, SEPOLIA_MAKER_PRIV, ERC20, erc20_conf, true);

    let taker_secret = vec![0; 32];
    let taker_secret_hash = sha256(&taker_secret).to_vec();
    let maker_secret = vec![1; 32];
    let maker_secret_hash = sha256(&maker_secret).to_vec();
    let payment_time_lock = now_sec() + 1000;

    let maker_address = block_on(maker_coin.my_addr());
    let taker_pub = &taker_coin.derive_htlc_pubkey_v2(&[]);

    let trading_amount = BigDecimal::from_str("0.0001").unwrap();

    let payment_args = SendMakerPaymentArgs {
        time_lock: payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        amount: trading_amount.clone(),
        taker_pub,
        swap_unique_data: &[],
    };
    wait_pending_transactions(Address::from_slice(maker_address.as_bytes()));
    let payment_tx = block_on(maker_coin.send_maker_payment_v2(payment_args)).unwrap();
    log!("Maker sent ERC20 payment, tx hash: {:02x}", payment_tx.tx_hash());
    wait_for_confirmations(&maker_coin, &payment_tx, 100);

    let refund_args = RefundMakerPaymentSecretArgs {
        maker_payment_tx: &payment_tx,
        time_lock: payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        taker_secret: &taker_secret,
        taker_pub,
        swap_unique_data: &[],
        amount: trading_amount,
    };
    wait_pending_transactions(Address::from_slice(maker_address.as_bytes()));
    let payment_tx_refund = block_on(maker_coin.refund_maker_payment_v2_secret(refund_args)).unwrap();
    log!(
        "Maker refunded ERC20 payment using taker secret, tx hash: {:02x}",
        payment_tx_refund.tx_hash()
    );
    wait_for_confirmations(&maker_coin, &payment_tx_refund, 100);
}

#[cfg(feature = "sepolia-maker-swap-v2-tests")]
#[test]
fn send_and_spend_maker_payment_eth() {
    let _guard = SEPOLIA_TESTS_LOCK.lock().unwrap();

    let taker_coin = get_or_create_sepolia_coin(&MM_CTX1, SEPOLIA_TAKER_PRIV, ETH, &eth_sepolia_conf(), false);
    let maker_coin = get_or_create_sepolia_coin(&MM_CTX, SEPOLIA_MAKER_PRIV, ETH, &eth_sepolia_conf(), false);

    let taker_secret = vec![0; 32];
    let taker_secret_hash = sha256(&taker_secret).to_vec();
    let maker_secret = vec![1; 32];
    let maker_secret_hash = sha256(&maker_secret).to_vec();
    let payment_time_lock = now_sec() + 1000;

    let maker_address = block_on(maker_coin.my_addr());
    let taker_address = block_on(taker_coin.my_addr());
    let maker_pub = &maker_coin.derive_htlc_pubkey_v2(&[]);
    let taker_pub = &taker_coin.derive_htlc_pubkey_v2(&[]);

    let trading_amount = BigDecimal::from_str("0.0001").unwrap();

    let payment_args = SendMakerPaymentArgs {
        time_lock: payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        amount: trading_amount.clone(),
        taker_pub,
        swap_unique_data: &[],
    };
    wait_pending_transactions(Address::from_slice(maker_address.as_bytes()));
    let payment_tx = block_on(maker_coin.send_maker_payment_v2(payment_args)).unwrap();
    log!("Maker sent ETH payment, tx hash: {:02x}", payment_tx.tx_hash());
    wait_for_confirmations(&maker_coin, &payment_tx, 100);

    let validation_args = ValidateMakerPaymentArgs {
        maker_payment_tx: &payment_tx,
        time_lock: payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        amount: trading_amount.clone(),
        maker_pub,
        swap_unique_data: &[],
    };
    block_on(taker_coin.validate_maker_payment_v2(validation_args)).unwrap();
    log!("Taker validated maker ETH payment");

    let spend_args = SpendMakerPaymentArgs {
        maker_payment_tx: &payment_tx,
        time_lock: payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        maker_secret: &maker_secret,
        maker_pub,
        swap_unique_data: &[],
        amount: trading_amount,
    };
    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    let spend_tx = block_on(taker_coin.spend_maker_payment_v2(spend_args)).unwrap();
    log!("Taker spent maker ETH payment, tx hash: {:02x}", spend_tx.tx_hash());
    wait_for_confirmations(&taker_coin, &spend_tx, 100);

    block_on(maker_coin.wait_for_maker_payment_spend(&spend_tx, 0u64, payment_time_lock)).unwrap();
}

#[cfg(feature = "sepolia-maker-swap-v2-tests")]
#[test]
fn send_and_spend_maker_payment_erc20() {
    let _guard = SEPOLIA_TESTS_LOCK.lock().unwrap();

    let erc20_conf = &sepolia_erc20_dev_conf(&sepolia_erc20_contract_checksum());
    let taker_coin = get_or_create_sepolia_coin(&MM_CTX1, SEPOLIA_TAKER_PRIV, ERC20, erc20_conf, true);
    let maker_coin = get_or_create_sepolia_coin(&MM_CTX, SEPOLIA_MAKER_PRIV, ERC20, erc20_conf, true);

    let taker_secret = vec![0; 32];
    let taker_secret_hash = sha256(&taker_secret).to_vec();
    let maker_secret = vec![1; 32];
    let maker_secret_hash = sha256(&maker_secret).to_vec();
    let payment_time_lock = now_sec() + 1000;

    let maker_address = block_on(maker_coin.my_addr());
    let taker_address = block_on(taker_coin.my_addr());
    let maker_pub = &maker_coin.derive_htlc_pubkey_v2(&[]);
    let taker_pub = &taker_coin.derive_htlc_pubkey_v2(&[]);

    let trading_amount = BigDecimal::from_str("0.0001").unwrap();

    let payment_args = SendMakerPaymentArgs {
        time_lock: payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        amount: trading_amount.clone(),
        taker_pub,
        swap_unique_data: &[],
    };
    wait_pending_transactions(Address::from_slice(maker_address.as_bytes()));
    let payment_tx = block_on(maker_coin.send_maker_payment_v2(payment_args)).unwrap();
    log!("Maker sent ERC20 payment, tx hash: {:02x}", payment_tx.tx_hash());
    wait_for_confirmations(&maker_coin, &payment_tx, 100);

    let validation_args = ValidateMakerPaymentArgs {
        maker_payment_tx: &payment_tx,
        time_lock: payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        amount: trading_amount.clone(),
        maker_pub,
        swap_unique_data: &[],
    };
    block_on(taker_coin.validate_maker_payment_v2(validation_args)).unwrap();
    log!("Taker validated maker ERC20 payment");

    let spend_args = SpendMakerPaymentArgs {
        maker_payment_tx: &payment_tx,
        time_lock: payment_time_lock,
        taker_secret_hash: &taker_secret_hash,
        maker_secret_hash: &maker_secret_hash,
        maker_secret: &maker_secret,
        maker_pub,
        swap_unique_data: &[],
        amount: trading_amount,
    };
    wait_pending_transactions(Address::from_slice(taker_address.as_bytes()));
    let spend_tx = block_on(taker_coin.spend_maker_payment_v2(spend_args)).unwrap();
    log!("Taker spent maker ERC20 payment, tx hash: {:02x}", spend_tx.tx_hash());
    wait_for_confirmations(&taker_coin, &spend_tx, 100);

    block_on(maker_coin.wait_for_maker_payment_spend(&spend_tx, 0u64, payment_time_lock)).unwrap();
}
