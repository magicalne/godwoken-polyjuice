use std::{collections::HashMap, convert::TryInto};

use gw_common::{h256_ext::H256Ext, H256};
use gw_types::{offchain::RunResult, U256};

use crate::{
    ctx::MockChain,
    rpc::{EnvType, RPC},
};

pub struct SandBox {
    contracts: Vec<[u8; 20]>,
    // key: contract eth addr
    // value: (contract binary, storage values)
    cached_contract_bin: HashMap<[u8; 20], (Vec<u8>, Vec<H256>)>,
    rpc: RPC,
    eoa_accounts: Vec<[u8; 20]>,
    contract_accounts: Vec<[u8; 20]>,
}

const ZERO_ADDRESS: [u8; 20] = [0u8; 20];

impl SandBox {
    pub fn new(
        env_type: EnvType,
        eoa_accounts: Vec<[u8; 20]>,
        contract_accounts: Vec<[u8; 20]>,
    ) -> anyhow::Result<Self> {
        let rpc = RPC::new(env_type)?;
        Ok(Self {
            contracts: vec![],
            cached_contract_bin: HashMap::new(),
            rpc,
            eoa_accounts,
            contract_accounts,
        })
    }

    pub async fn execute(
        &mut self,
        from_eth_addr: &[u8; 20],
        to_eth_addr: &[u8; 20],
        mint_ckb: U256,
        gas_price: u128,
        gas_limit: u64,
        input_data: &str,
        value: u128,
    ) -> anyhow::Result<RunResult> {
        self.contracts.clear();
        // create preset contract accounts
        for contract in &self.contract_accounts {
            self.contracts.push(contract.clone());
        }
        let input = hex::decode(input_data).expect("input data");

        self.try_deploy(
            from_eth_addr,
            mint_ckb,
            to_eth_addr,
            gas_limit,
            gas_price,
            value,
        )
        .await?;
        loop {
            let mut chain = MockChain::setup("..")?;

            // create preset eoa accounts
            for eoa in &self.eoa_accounts {
                chain.create_eoa_account(eoa, mint_ckb)?;
            }
            println!("Presset EOA accoutns");

            self.deploy_contracts(&mut chain, mint_ckb).await?;
            let from_id = chain.create_eoa_account(from_eth_addr, mint_ckb)?;
            // get original to contract binary by eth address
            let to_id = chain
                .get_account_id_by_eth_address(to_eth_addr)?
                .expect("get account id by eth addr");
            let run_result = chain.execute(from_id, to_id, &input, gas_limit, gas_price, value)?;
            // If a contract address used in the call which is not cached, we nned to execute
            // again.
            for addr in run_result.trace.contract_addrs.iter() {
                let addr: [u8; 20] = addr.to_vec().try_into().expect("parse to [u8; 20]");
                if !self.cached_contract_bin.contains_key(&addr) {
                    continue;
                }
            }
            return Ok(run_result);
        }
    }

    // Get contract binary. Check local cache first. If it's not cached, then read from rpc.
    async fn get_contract_bin(
        &mut self,
        eth_addr: &[u8; 20],
    ) -> anyhow::Result<(Vec<u8>, Vec<H256>)> {
        match self.cached_contract_bin.get(eth_addr) {
            Some((bin, storage_values)) => Ok((bin.to_vec(), storage_values.clone())),
            None => {
                let eth_addr_str = hex::encode(eth_addr);
                let code = self.rpc.get_code(&eth_addr_str).await?;
                let code = code.trim_start_matches("0x");
                println!(
                    "get code form addr: {}, code size: {}",
                    eth_addr_str,
                    code.len()
                );
                let code = hex::decode(code)?;
                let mut storage_values: Vec<H256> = Vec::with_capacity(20);
                for i in 0..20 {
                    let index = i as u32;
                    let value = self.rpc.get_storage_at(&eth_addr_str, index).await?;
                    println!("read storage at: {}", &value);
                    let value = value.trim_start_matches("0x");
                    let value = hex::decode(&value).expect("parse storage value");
                    let value: [u8; 32] = value.try_into().expect("parse value to h256");
                    storage_values.push(value.into());
                }
                self.cached_contract_bin
                    .insert(eth_addr.clone(), (code.clone(), storage_values.clone()));
                Ok((code, storage_values))
            }
        }
    }

    //FIXME: cannot trace contract address if we don't deploy the contract!
    async fn deploy_contracts(
        &mut self,
        chain: &mut MockChain,
        mint_ckb: U256,
    ) -> anyhow::Result<()> {
        // Deploy new contract first.
        let contracts = self.contracts.clone();
        for addr in contracts.iter().rev() {
            if addr.eq(&ZERO_ADDRESS) {
                continue;
            }
            println!("deploy contract: {}", &hex::encode(addr));
            let (code, storages) = self.get_contract_bin(addr).await?;
            let storages = storages
                .iter()
                .enumerate()
                .map(|(idx, v)| {
                    let index = H256::from_u32(idx as u32);
                    (index, v.clone())
                })
                .collect();
            let _ = chain.create_contract_account(addr, mint_ckb, &code, storages)?;
        }
        Ok(())
    }

    // Collecting contracts used by `to addr`.
    async fn try_deploy(
        &mut self,
        from_eth_addr: &[u8; 20],
        mint_ckb: U256,
        to_addr: &[u8; 20],
        gas_limit: u64,
        gas_price: u128,
        value: u128,
    ) -> anyhow::Result<()> {
        self.contracts.push(to_addr.clone());
        loop {
            let mut chain = MockChain::setup("..")?;
            let from_id = chain.create_eoa_account(from_eth_addr, mint_ckb)?;
            let contracts = self.contracts.clone();
            if contracts.is_empty() {
                return Ok(());
            }
            for eth_addr in contracts {
                let (code, _) = self.get_contract_bin(&eth_addr).await?;
                let run_result = chain.deploy(from_id, &code, gas_limit, gas_price, value)?;
                // no more contract referenced
                if run_result.trace.contract_addrs.is_empty() {
                    return Ok(());
                }
                for call_addr in run_result.trace.contract_addrs {
                    let call_addr = call_addr.try_into().expect("parse to [u8; 20]");
                    self.contracts.push(call_addr);
                }
            }
        }
    }
}
