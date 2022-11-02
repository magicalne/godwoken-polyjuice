use std::convert::TryInto;

use lib::{
    helper::{parse_log, string_to_eth_addr},
    rpc::EnvType,
    sand_box::SandBox,
};

#[tokio::test]
async fn ibamm_test() -> anyhow::Result<()> {
    let eoa_accounts = vec!["c207a5dc49771a71367bd3a97fe58aaf9c5dfdae"];
    let contract_accounts = vec!["ec2bf7ec6afcec1594baf4f33736573d0a12c25e"];
    let eoa_accounts: Vec<[u8; 20]> = eoa_accounts.iter().map(|s| string_to_eth_addr(s)).collect();
    let contract_accounts: Vec<[u8; 20]> = contract_accounts
        .iter()
        .map(|s| string_to_eth_addr(s))
        .collect();
    let mut sand_box = SandBox::new(EnvType::MainNet, eoa_accounts, contract_accounts)?;

    let from_eth_addr = "c7035d9319654fae4a0abe9a88121b9d9c36900f";
    let to_eth_addr = "d839f4468a47ac17321c28669029d069ab73f535";
    let mint_ckb = 1000_000_000;
    let gas_price = 1;
    let gas_limit = 10_000_000;
    let value = 0;
    let input_data = "f5e3c462000000000000000000000000c207a5dc49771a71367bd3a97fe58aaf9c5dfdae0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000ec2bf7ec6afcec1594baf4f33736573d0a12c25e";
    let from_eth_addr: [u8; 20] = hex::decode(from_eth_addr)?
        .try_into()
        .expect("from eth addr");
    let to_eth_addr: [u8; 20] = hex::decode(to_eth_addr)?.try_into().expect("to eth addr");
    let run_result = sand_box
        .execute(
            &from_eth_addr,
            &to_eth_addr,
            mint_ckb.into(),
            gas_price,
            gas_limit,
            input_data,
            value,
        )
        .await?;
    run_result.write.logs.iter().for_each(|log| {
        let log = parse_log(log);
        println!("log: {:?}", &log);
    });
    println!("return data: {}", &hex::encode(run_result.return_data));
    Ok(())
}
