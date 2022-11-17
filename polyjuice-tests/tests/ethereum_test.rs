use gw_common::H256;
use gw_types::{offchain::RunResult, U256};
use lib::{
    ctx::MockChain,
    helper::{parse_log, Log},
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap},
    convert::TryInto,
    fs, io,
    path::{Path, PathBuf},
    u128,
};

const TEST_CASE_DIR: &str = "../integration-test/ethereum-tests/GeneralStateTests/";
const HARD_FORKS: &[&str] = &["Berlin", "Istanbul"];
const EXCLUDE_TEST_FILES: &[&str] = &[
    "ByZero.json",
    "createContractViaTransactionCost53000.json",
    "HighGasPrice.json",
];

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct Info {
    comment: String,
    #[serde(rename = "filling-rpc-server")]
    filling_rpc_server: String,
    #[serde(rename = "filling-tool-version")]
    filling_tool_version: String,
    #[serde(rename = "generatedTestHash")]
    generated_test_hash: String,
    labels: Option<HashMap<String, String>>,
    lllcversion: String,
    solidity: String,
    source: String,
    #[serde(rename = "sourceHash")]
    source_hash: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Env {
    current_base_fee: String,
    current_coinbase: String,
    current_difficulty: String,
    current_gas_limit: String,
    current_number: String,
    current_timestamp: String,
    previous_hash: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct Pre {
    balance: String,
    code: String,
    nonce: String,
    storage: HashMap<String, String>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct Post {
    hash: String,
    indexes: Indexes,
    logs: String,
    #[serde(rename = "txbytes")]
    tx_bytes: String,
}

#[derive(Deserialize, Debug)]
struct Indexes {
    data: usize,
    gas: usize,
    value: usize,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct Transaction {
    data: Vec<String>,
    #[serde(rename = "gasLimit")]
    gas_limit: Vec<String>,
    #[serde(rename = "gasPrice")]
    gas_price: Option<String>,
    nonce: String,
    sender: String,
    to: String,
    value: Vec<String>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct TestCase {
    #[serde(rename = "_info")]
    info: Info,
    env: Env,
    pre: BTreeMap<String, Pre>,
    post: BTreeMap<String, Vec<Post>>,
    transaction: Transaction,
}

struct VMTestRunner {
    testcase: TestCase,
}

impl VMTestRunner {
    fn new(testcase: TestCase) -> anyhow::Result<Self> {
        Ok(Self { testcase })
    }

    // handle pre
    // reset chain
    // create accounts and fill with balance, code, storage
    fn init(&self) -> anyhow::Result<MockChain> {
        //reset chain for each test
        let mut chain = MockChain::setup("..")?;

        for (eth_addr, account) in self.testcase.pre.iter() {
            println!("init account for: {}", &eth_addr);
            let balance = U256::from_str_radix(&account.balance, 16)?;

            let eth_addr = hex::decode(eth_addr.trim_start_matches("0x"))?;
            let eth_addr: [u8; 20] = eth_addr.try_into().unwrap();

            if account.code != "0x" {
                let code = hex::decode(&account.code.trim_start_matches("0x"))?;
                let mut storage = HashMap::with_capacity(account.storage.len());
                for (k, v) in &account.storage {
                    let k = hex_to_h256(k)?;
                    let v = hex_to_h256(v)?;
                    storage.insert(k, v);
                }
                let account_id =
                    chain.create_contract_account(&eth_addr, balance, &code, storage)?;
                println!("Contract account id {} created", account_id);
            } else {
                let account_id = chain.create_eoa_account(&eth_addr, balance)?;
                println!("EOA account id {} created", account_id);
            }
        }
        Ok(chain)
    }

    fn run(&self) -> anyhow::Result<()> {
        // prepare tx form `post`
        for hardfork in HARD_FORKS {
            // init ctx for each `post`
            let mut chain = self.init()?;
            if let Some(posts) = self.testcase.post.get(&hardfork.to_string()) {
                println!("Prepare tx, hardfork: {}", hardfork);
                for post in posts {
                    self.run_tx(post, &mut chain)?;
                }
            }
        }
        Ok(())
    }

    fn run_tx(&self, post: &Post, chain: &mut MockChain) -> anyhow::Result<()> {
        let transaction = &self.testcase.transaction;
        let gas = transaction
            .gas_limit
            .get(post.indexes.gas)
            .expect("gas limit");
        let gas_limit = U256::from_str_radix(gas, 16)?;
        let data = transaction.data.get(post.indexes.data).expect("data");
        let data = hex::decode(data.trim_start_matches("0x"))?;
        let value = transaction.value.get(post.indexes.value).expect("value");
        let value = U256::from_str_radix(value, 16)?;

        let gas_price = match &transaction.gas_price {
            Some(gas_price) => U256::from_str_radix(gas_price, 16)?,
            None => U256::zero(),
        };
        let from_eth_addr = hex_to_eth_address(&transaction.sender)?;
        let to_eth_addr = hex_to_eth_address(&transaction.to)?;
        let from_id = chain
            .get_account_id_by_eth_address(&from_eth_addr)?
            .ok_or(anyhow::anyhow!("Cannot find from id."))?;
        let to_id = chain
            .get_account_id_by_eth_address(&to_eth_addr)?
            .ok_or(anyhow::anyhow!("Cannot find to id."))?;
        let tx = Tx {
            from_id,
            to_id,
            code: &data,
            gas_limit: gas_limit.as_u64(),
            gas_price: gas_price.as_u128(),
            value: value.as_u128(),
        };
        let sub_test_case = SubTestCase { chain, tx };
        let run_result = sub_test_case.run()?;
        let logs_hash = rlp_log_hash(&run_result);
        let expect_logs_hash = hex::decode(post.logs.trim_start_matches("0x"))?;
        //assert_eq!(logs_hash.as_slice(), &expect_logs_hash, "compare log hash");
        if logs_hash.as_slice() != &expect_logs_hash {
            return Err(anyhow::anyhow!(
                "Compare logs hash failed: expect: {}, actual: {}",
                hex::encode(&expect_logs_hash),
                hex::encode(logs_hash.as_slice())
            ));
        }
        Ok(())
    }
}

struct Tx<'a> {
    from_id: u32,
    to_id: u32,
    code: &'a [u8],
    gas_limit: u64,
    gas_price: u128,
    value: u128,
}

struct SubTestCase<'a, 'b> {
    chain: &'a mut MockChain,
    tx: Tx<'b>,
}

impl<'a, 'b> SubTestCase<'a, 'b> {
    fn run(self) -> anyhow::Result<RunResult> {
        let Tx {
            from_id,
            to_id,
            code,
            gas_limit,
            gas_price,
            value,
        } = self.tx;
        let run_result = self
            .chain
            .execute(from_id, to_id, code, gas_limit, gas_price, value)?;
        if run_result.exit_code != 0 {
            return Err(anyhow::anyhow!("Test case failed."));
        }
        Ok(run_result)
    }
}

fn rlp_log_hash(run_result: &RunResult) -> H256 {
    let mut stream = rlp::RlpStream::new();
    stream.begin_unbounded_list();
    run_result.logs.iter().for_each(|l| {
        let log = parse_log(l);
        if let Log::PolyjuiceUser {
            address,
            data,
            topics,
        } = log
        {
            stream.begin_list(3);
            stream.append(&address.to_vec());
            stream.begin_list(topics.len());
            topics.iter().for_each(|t| {
                stream.append(&t.as_slice());
            });
            if data.is_empty() {
                stream.append_empty_data();
            } else {
                stream.append(&data);
            }
        }
    });
    stream.finalize_unbounded_list();
    let log_hash = tiny_keccak::keccak256(&stream.out().freeze());
    log_hash.into()
}

fn hex_to_h256(hex_str: &str) -> anyhow::Result<H256> {
    const PREFIX: &str = "0x";
    let hex_str = if hex_str.starts_with(PREFIX) {
        hex_str.trim_start_matches("0x")
    } else {
        hex_str
    };
    let buf = hex::decode(hex_str)?;
    assert!(buf.len() <= 32);
    let mut key = [0u8; 32];
    if buf.len() < 32 {
        let idx = 32 - buf.len();
        key[idx..].copy_from_slice(&buf);
    } else {
        key.copy_from_slice(&buf);
    };
    let key = H256::from(key);

    Ok(key)
}

fn hex_to_eth_address(hex_str: &str) -> anyhow::Result<[u8; 20]> {
    const PREFIX: &str = "0x";
    let hex_str = if hex_str.starts_with(PREFIX) {
        hex_str.trim_start_matches("0x")
    } else {
        hex_str
    };
    let buf = hex::decode(hex_str)?;
    //assert_eq!(buf.len(), 20, "eth address");
    if buf.len() != 20 {
        return Err(anyhow::anyhow!("Invalid eth address."));
    }
    let eth_address = buf.try_into().unwrap();
    Ok(eth_address)
}

fn read_all_files(path: &Path, paths: &mut Vec<PathBuf>) -> io::Result<()> {
    for file in fs::read_dir(path)? {
        let p = file?.path();
        if p.is_dir() {
            read_all_files(p.as_path(), paths)?;
        } else {
            paths.push(p);
        }
    }

    Ok(())
}
#[test]
fn ethereum_test() -> anyhow::Result<()> {
    let mut paths = Vec::new();
    read_all_files(Path::new(TEST_CASE_DIR), &mut paths)?;
    let mut err_cases = Vec::new();
    for path in paths {
        // Skip testcases in `EXCLUDE_TEST_FILES`.
        if let Some(filename) = path.file_name() {
            if let Some(filename) = filename.to_str() {
                if EXCLUDE_TEST_FILES.contains(&filename) {
                    continue;
                }
                // Skip non-JSON files.
                if !filename.ends_with("json") {
                    continue;
                }
            }
        }

        println!("Starting test with: {:?}", &path);
        let content = fs::read_to_string(&path)?;
        let test_cases: HashMap<String, TestCase> = serde_json::from_str(&content)?;
        for (testname, testcase) in test_cases {
            println!("test name: {}", testname);
            let runner = VMTestRunner::new(testcase)?;
            if runner.run().is_err() {
                err_cases.push(path.clone());
            }
        }
    }
    if !err_cases.is_empty() {
        println!("============================================================================");
        println!("============================Error test case paths===========================");
        for path in err_cases {
            println!("{:?}", &path);
        }
        println!("============================================================================");
        println!("============================================================================");
        return Err(anyhow::anyhow!("Some tests are failed."));
    }
    Ok(())
}

#[test]
fn ethereum_failure_test() -> anyhow::Result<()> {
    let mut paths = Vec::new();
    read_all_files(Path::new(TEST_CASE_DIR), &mut paths)?;
    let mut err_cases = Vec::new();
    for path in paths {
        if let Some(filename) = path.file_name() {
            if let Some(filename) = filename.to_str() {
                if EXCLUDE_TEST_FILES.contains(&filename) {
                    println!("Starting test with: {:?}", &path);
                    let content = fs::read_to_string(&path)?;
                    let test_cases: HashMap<String, TestCase> = serde_json::from_str(&content)?;
                    for (testname, testcase) in test_cases {
                        println!("test name: {}", testname);
                        let runner = VMTestRunner::new(testcase)?;
                        if runner.run().is_err() {
                            err_cases.push(path.clone());
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn ethereum_single_test() -> anyhow::Result<()> {
    let path =
        "../integration-test/ethereum-tests/GeneralStateTests/stCreate2/RevertOpcodeCreate.json";
    /*
     * exit code: 3
     */
    let content = fs::read_to_string(&path)?;
    let test_cases: HashMap<String, TestCase> = serde_json::from_str(&content)?;
    for (testname, testcase) in test_cases {
        println!("test name: {}", testname);
        let runner = VMTestRunner::new(testcase)?;
        let res = runner.run()?;
        println!("res: {:?}", res);
    }

    Ok(())
}
/* ALL FAILED TESTS
"../integration-test/ethereum-tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_ABCB_RECURSIVE.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_ABCB_RECURSIVE.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_ABCB_RECURSIVE.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_ABCB_RECURSIVE.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_ABCB_RECURSIVE.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_ABCB_RECURSIVE.json"
"../integration-test/ethereum-tests/GeneralStateTests/stMemExpandingEIP150Calls/CallGoesOOGOnSecondLevel2WithMemExpandingCalls.json"
"../integration-test/ethereum-tests/GeneralStateTests/stMemExpandingEIP150Calls/CallGoesOOGOnSecondLevelWithMemExpandingCalls.json"
"../integration-test/ethereum-tests/GeneralStateTests/stPreCompiledContracts/precompsEIP2929.json"
"../integration-test/ethereum-tests/GeneralStateTests/stPreCompiledContracts/idPrecomps.json"
"../integration-test/ethereum-tests/GeneralStateTests/stPreCompiledContracts/modexp.json"
"../integration-test/ethereum-tests/GeneralStateTests/stEIP150singleCodeGasPrices/RawCreateGas.json"
"../integration-test/ethereum-tests/GeneralStateTests/stEIP150singleCodeGasPrices/eip2929-ff.json"
"../integration-test/ethereum-tests/GeneralStateTests/stEIP150singleCodeGasPrices/RawCreateGasValueTransfer.json"
"../integration-test/ethereum-tests/GeneralStateTests/stStaticFlagEnabled/CallWithZeroValueToPrecompileFromTransaction.json"
"../integration-test/ethereum-tests/GeneralStateTests/stStaticFlagEnabled/DelegatecallToPrecompileFromTransaction.json"
"../integration-test/ethereum-tests/GeneralStateTests/stStaticFlagEnabled/CallcodeToPrecompileFromTransaction.json"
"../integration-test/ethereum-tests/GeneralStateTests/stExample/invalidTr.json"
"../integration-test/ethereum-tests/GeneralStateTests/stExample/eip1559.json"
"../integration-test/ethereum-tests/GeneralStateTests/stMemoryTest/stackLimitPush32_1025.json"
"../integration-test/ethereum-tests/GeneralStateTests/stMemoryTest/mstore_dejavu.json"
"../integration-test/ethereum-tests/GeneralStateTests/stMemoryTest/log4_dejavu.json"
"../integration-test/ethereum-tests/GeneralStateTests/stMemoryTest/log2_dejavu.json"
"../integration-test/ethereum-tests/GeneralStateTests/stMemoryTest/mload_dejavu.json"
"../integration-test/ethereum-tests/GeneralStateTests/stMemoryTest/sha3_dejavu.json"
"../integration-test/ethereum-tests/GeneralStateTests/stMemoryTest/calldatacopy_dejavu.json"
"../integration-test/ethereum-tests/GeneralStateTests/stMemoryTest/buffer.json"
"../integration-test/ethereum-tests/GeneralStateTests/stMemoryTest/bufferSrcOffset.json"
"../integration-test/ethereum-tests/GeneralStateTests/stMemoryTest/log3_dejavu.json"
"../integration-test/ethereum-tests/GeneralStateTests/stMemoryTest/log1_dejavu.json"
"../integration-test/ethereum-tests/GeneralStateTests/stMemoryTest/extcodecopy_dejavu.json"
"../integration-test/ethereum-tests/GeneralStateTests/stMemoryTest/codecopy_dejavu.json"
"../integration-test/ethereum-tests/GeneralStateTests/stMemoryTest/mstroe8_dejavu.json"
"../integration-test/ethereum-tests/GeneralStateTests/stMemoryTest/stackLimitGas_1025.json"
"../integration-test/ethereum-tests/GeneralStateTests/stMemoryTest/stackLimitPush31_1025.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSolidityTest/CallRecursiveMethods.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSolidityTest/TestContractSuicide.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSolidityTest/CallInfiniteLoop.json"
"../integration-test/ethereum-tests/GeneralStateTests/stQuadraticComplexityTest/Call20KbytesContract50_2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stQuadraticComplexityTest/Call20KbytesContract50_3.json"
"../integration-test/ethereum-tests/GeneralStateTests/stQuadraticComplexityTest/Call50000_ecrec.json"
"../integration-test/ethereum-tests/GeneralStateTests/stQuadraticComplexityTest/Call50000_sha256.json"
"../integration-test/ethereum-tests/GeneralStateTests/stQuadraticComplexityTest/Create1000Byzantium.json"
"../integration-test/ethereum-tests/GeneralStateTests/stQuadraticComplexityTest/Call20KbytesContract50_1.json"
"../integration-test/ethereum-tests/GeneralStateTests/stQuadraticComplexityTest/Call50000.json"
"../integration-test/ethereum-tests/GeneralStateTests/stQuadraticComplexityTest/Return50000.json"
"../integration-test/ethereum-tests/GeneralStateTests/stQuadraticComplexityTest/Call50000_rip160.json"
"../integration-test/ethereum-tests/GeneralStateTests/stQuadraticComplexityTest/Call1MB1024Calldepth.json"
"../integration-test/ethereum-tests/GeneralStateTests/stQuadraticComplexityTest/QuadraticComplexitySolidity_CallDataCopy.json"
"../integration-test/ethereum-tests/GeneralStateTests/stQuadraticComplexityTest/Return50000_2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stQuadraticComplexityTest/Callcode50000.json"
"../integration-test/ethereum-tests/GeneralStateTests/stQuadraticComplexityTest/Create1000.json"
"../integration-test/ethereum-tests/GeneralStateTests/stQuadraticComplexityTest/Call50000_identity.json"
"../integration-test/ethereum-tests/GeneralStateTests/stQuadraticComplexityTest/Call50000_identity2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stHomesteadSpecific/createContractViaContract.json"
"../integration-test/ethereum-tests/GeneralStateTests/stHomesteadSpecific/contractCreationOOGdontLeaveEmptyContractViaTransaction.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSpecialTest/block504980.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSpecialTest/failed_tx_xcf416c53.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSpecialTest/StackDepthLimitSEC.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSpecialTest/JUMPDEST_Attack.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSpecialTest/selfdestructEIP2929.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSpecialTest/deploymentError.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSpecialTest/FailedCreateRevertsDeletion.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSpecialTest/OverflowGasMakeMoney.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSpecialTest/JUMPDEST_AttackwithJump.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTimeConsuming/CALLBlake2f_MaxRounds.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTimeConsuming/sstore_combinations_initial01_2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTimeConsuming/sstore_combinations_initial10_2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTimeConsuming/static_Call50000_sha256.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTimeConsuming/sstore_combinations_initial11.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTimeConsuming/sstore_combinations_initial20_2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTimeConsuming/sstore_combinations_initial11_2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTimeConsuming/sstore_combinations_initial00.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTimeConsuming/sstore_combinations_initial01.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTimeConsuming/sstore_combinations_initial00_2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTimeConsuming/sstore_combinations_initial10.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTimeConsuming/sstore_combinations_initial21.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTimeConsuming/sstore_combinations_initial21_2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTimeConsuming/sstore_combinations_initial20.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/RevertDepthCreate2OOGBerlin.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/CREATE2_Bounds2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/create2InitCodes.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/create2callPrecompiles.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/create2collisionSelfdestructedOOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/Create2OOGafterInitCodeReturndata.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/CREATE2_Suicide.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/RevertDepthCreate2OOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/Create2OOGafterInitCodeReturndata3.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/RevertOpcodeCreate.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/RevertDepthCreateAddressCollision.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/create2collisionSelfdestructed.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/create2noCash.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/Create2Recursive.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/create2collisionCode2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/create2collisionBalance.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/create2SmartInitCode.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/create2collisionNonce.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/create2collisionSelfdestructedRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/CREATE2_FirstByte_loop.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/create2collisionStorage.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/RevertDepthCreateAddressCollisionBerlin.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/CREATE2_Bounds3.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/create2collisionCode.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/CREATE2_Bounds.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/Create2OnDepth1023.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/returndatacopy_following_successful_create.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/CreateMessageRevertedOOGInInit.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/create2collisionSelfdestructed2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/Create2OnDepth1024.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/Create2OOGafterInitCodeReturndata2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreate2/RevertInCreateInInitCreate2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_failing_callcode.json"
"../integration-test/ethereum-tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_failing_staticcall.json"
"../integration-test/ethereum-tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial.json"
"../integration-test/ethereum-tests/GeneralStateTests/stReturnDataTest/returndatacopy_after_failing_delegatecall.json"
"../integration-test/ethereum-tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_big_sum.json"
"../integration-test/ethereum-tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_create.json"
"../integration-test/ethereum-tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_successful_create.json"
"../integration-test/ethereum-tests/GeneralStateTests/stReturnDataTest/returndatacopy_initial_256.json"
"../integration-test/ethereum-tests/GeneralStateTests/stReturnDataTest/revertRetDataSize.json"
"../integration-test/ethereum-tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_too_big_transfer.json"
"../integration-test/ethereum-tests/GeneralStateTests/stReturnDataTest/returndatacopy_overrun.json"
"../integration-test/ethereum-tests/GeneralStateTests/stReturnDataTest/returndatacopy_following_failing_call.json"
"../integration-test/ethereum-tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToNonZeroBalance_OOGRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToOneStorageKey_OOGRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_OOGRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToOneStorageKey_OOGRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToEmpty_OOGRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_OOGRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToEmpty_OOGRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToEmpty_OOGRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToOneStorageKey_OOGRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_OOGRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToNonZeroBalance_OOGRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToNonZeroBalance_OOGRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToOneStorageKey_OOGRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_OOGRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToEmpty_OOGRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToNonZeroBalance_OOGRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertOpcodeReturn.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/PythonRevertTestTue201814-1430.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertOpcodeInInit.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertSubCallStorageOOG2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertOpcodeWithBigOutputInInit.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertDepthCreateOOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/LoopDelegateCallsDepthThenRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertOpcodeCreate.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertDepthCreateAddressCollision.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertPrefoundEmptyOOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertOpcodeCalls.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertPrefoundCallOOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertInCreateInInit.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertPrefoundEmptyCallOOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertOpcode.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/LoopCallsDepthThenRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/LoopCallsDepthThenRevert3.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/LoopCallsDepthThenRevert2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertPrefoundOOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertDepth2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/TouchToEmptyAccountRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/LoopCallsThenRevert.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertOnEmptyStack.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertOpcodeInCallsOnNonEmptyReturnData.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertOpcodeDirectCall.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertSubCallStorageOOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRevertTest/RevertRemoteSubCallStorageOOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
"../integration-test/ethereum-tests/GeneralStateTests/stBugs/evmBytecode.json"
"../integration-test/ethereum-tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL.json"
"../integration-test/ethereum-tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL_ToEmpty.json"
"../integration-test/ethereum-tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL_ToNonNonZeroBalance.json"
"../integration-test/ethereum-tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData_ToOneStorageKey.json"
"../integration-test/ethereum-tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL_ToOneStorageKey.json"
"../integration-test/ethereum-tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData_ToNonNonZeroBalance.json"
"../integration-test/ethereum-tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData_ToEmpty.json"
"../integration-test/ethereum-tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/CREATE_FirstByte_loop.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/CREATE_EContractCreateEContractInInit_Tr.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/CREATE_EContractCreateNEContractInInitOOG_Tr.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/CREATE_ContractSuicideDuringInit_WithValue.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/TransactionCollisionToEmptyButCode.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/CREATE_ContractSuicideDuringInit_WithValueToItself.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/CreateOOGafterInitCodeReturndata.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/CREATE_EContractCreateNEContractInInit_Tr.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/CREATE_AcreateB_BSuicide_BStore.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/CREATE_empty000CreateinInitCode_Transaction.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/CreateResults.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/CREATE_ContractSSTOREDuringInit.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/CREATE_ContractSuicideDuringInit_ThenStoreThenReturn.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/CREATE_ContractSuicideDuringInit.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/CREATE_ContractRETURNBigOffset.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/CreateOOGafterInitCodeReturndata2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/TransactionCollisionToEmptyButNonce.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/TransactionCollisionToEmpty.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCreateTest/CreateOOGafterInitCodeReturndata3.json"
"../integration-test/ethereum-tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRefundTest/refund600.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRefundTest/refund_OOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRefundTest/refund_CallToSuicideTwice.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRefundTest/refund_TxToSuicideOOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRefundTest/refund_NoOOG_1.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRefundTest/refund50percentCap.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRefundTest/refund50_2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRefundTest/refund_multimpleSuicide.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRefundTest/refund50_1.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRefundTest/refund_CallA_OOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
"../integration-test/ethereum-tests/GeneralStateTests/stArgsZeroOneBalance/createNonConst.json"
"../integration-test/ethereum-tests/GeneralStateTests/stArgsZeroOneBalance/jumpiNonConst.json"
"../integration-test/ethereum-tests/GeneralStateTests/stArgsZeroOneBalance/jumpNonConst.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024BalanceTooLow.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024PreCalls.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCreateCallCodeTest/CallcodeLoseGasOOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCreateCallCodeTest/Callcode1024BalanceTooLow.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCreateCallCodeTest/Callcode1024OOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCreateCallCodeTest/createJS_ExampleContract.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPerTxsNotEnoughGas.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPerTxs.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCreateCallCodeTest/contractCreationMakeCallThatAskMoreGasThenTransactionProvided.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCreateCallCodeTest/CallRecursiveBombPreCall.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCreateCallCodeTest/createJS_NoCollision.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCodes/callcallcall_ABCB_RECURSIVE.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCodes/callcallcallcode_ABCB_RECURSIVE.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_ABCB_RECURSIVE.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCodes/callcodecallcall_ABCB_RECURSIVE.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCodes/callcodecallcallcode_ABCB_RECURSIVE.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCodes/call_OOG_additionalGasCosts2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCodes/callcallcodecall_ABCB_RECURSIVE.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCodes/callcodecallcodecall_ABCB_RECURSIVE.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCallCodes/callcallcodecallcode_ABCB_RECURSIVE.json"
"../integration-test/ethereum-tests/GeneralStateTests/stPreCompiledContracts2/CALLCODEIdentity_5.json"
"../integration-test/ethereum-tests/GeneralStateTests/stPreCompiledContracts2/CallRipemd160_5.json"
"../integration-test/ethereum-tests/GeneralStateTests/stPreCompiledContracts2/CALLCODEBlake2f.json"
"../integration-test/ethereum-tests/GeneralStateTests/stPreCompiledContracts2/CallIdentity_5.json"
"../integration-test/ethereum-tests/GeneralStateTests/stPreCompiledContracts2/CALLCODERipemd160_5.json"
"../integration-test/ethereum-tests/GeneralStateTests/stPreCompiledContracts2/modexpRandomInput.json"
"../integration-test/ethereum-tests/GeneralStateTests/stPreCompiledContracts2/modexp_0_0_0_20500.json"
"../integration-test/ethereum-tests/GeneralStateTests/stPreCompiledContracts2/CallSha256_5.json"
"../integration-test/ethereum-tests/GeneralStateTests/stPreCompiledContracts2/CALLCODESha256_5.json"
"../integration-test/ethereum-tests/GeneralStateTests/stPreCompiledContracts2/CALLBlake2f.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRecursiveCreate/recursiveCreateReturnValue.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCodeSizeLimit/codesizeInit.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCodeSizeLimit/codesizeValid.json"
"../integration-test/ethereum-tests/GeneralStateTests/stCodeSizeLimit/codesizeOOGInvalidSize.json"
"../integration-test/ethereum-tests/GeneralStateTests/stEIP150Specific/CallGoesOOGOnSecondLevel2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stEIP158Specific/vitalikTransactionTest.json"
"../integration-test/ethereum-tests/GeneralStateTests/stInitCodeTest/TransactionCreateStopInInitcode.json"
"../integration-test/ethereum-tests/GeneralStateTests/stInitCodeTest/TransactionCreateAutoSuicideContract.json"
"../integration-test/ethereum-tests/GeneralStateTests/stInitCodeTest/TransactionCreateRandomInitCode.json"
"../integration-test/ethereum-tests/GeneralStateTests/stInitCodeTest/StackUnderFlowContractCreation.json"
"../integration-test/ethereum-tests/GeneralStateTests/stInitCodeTest/OutOfGasPrefundedContractCreation.json"
"../integration-test/ethereum-tests/GeneralStateTests/stInitCodeTest/TransactionCreateSuicideInInitcode.json"
"../integration-test/ethereum-tests/GeneralStateTests/stInitCodeTest/OutOfGasContractCreation.json"
"../integration-test/ethereum-tests/GeneralStateTests/stAttackTest/CrashingTransaction.json"
"../integration-test/ethereum-tests/GeneralStateTests/stAttackTest/ContractCreationSpam.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsAt.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsBefore.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransitionTest/createNameRegistratorPerTxsAfter.json"
"../integration-test/ethereum-tests/GeneralStateTests/stExtCodeHash/callToSuicideThenExtcodehash.json"
"../integration-test/ethereum-tests/GeneralStateTests/stExtCodeHash/createEmptyThenExtcodehash.json"
"../integration-test/ethereum-tests/GeneralStateTests/stExtCodeHash/extCodeHashChangedAccount.json"
"../integration-test/ethereum-tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallSuicide.json"
"../integration-test/ethereum-tests/GeneralStateTests/stExtCodeHash/extCodeHashInInitCode.json"
"../integration-test/ethereum-tests/GeneralStateTests/stDelegatecallTestHomestead/Delegatecall1024OOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024BalanceTooLow.json"
"../integration-test/ethereum-tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024PreCalls.json"
"../integration-test/ethereum-tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stDelegatecallTestHomestead/Call1024OOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stDelegatecallTestHomestead/CallRecursiveBombPreCall.json"
"../integration-test/ethereum-tests/GeneralStateTests/stDelegatecallTestHomestead/Delegatecall1024.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest563.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest604.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest494.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest449.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest456.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest583.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest645.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest640.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest423.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest611.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest576.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest632.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest506.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest626.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest523.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest547.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest454.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest575.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest448.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest642.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest393.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest639.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest524.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest418.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest650.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest589.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest573.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest566.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest643.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest542.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest499.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest527.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest496.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest467.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest625.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest458.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest601.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest636.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest646.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest485.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest569.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest498.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest481.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest647.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest468.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest528.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest513.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest476.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest618.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest554.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest484.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest627.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest644.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest415.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest445.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest461.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest443.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest597.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest422.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest562.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest504.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom2/randomStatetest538.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest347.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest294.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest336.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest13.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest368.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest257.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest189.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest146.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest53.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest370.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest352.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest303.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest7.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest153.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest134.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest36.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest307.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest178.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest353.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest250.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest101.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest320.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest359.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest50.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest302.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest313.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest263.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest150.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest108.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest97.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest151.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest154.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest135.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest24.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest143.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest133.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest185.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest261.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest292.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest365.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest103.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest296.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest306.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest54.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest84.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest48.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest326.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest20.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest205.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest304.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest295.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest10.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest274.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest327.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest248.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest55.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest355.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest163.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest16.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest233.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest159.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest32.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest18.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest125.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest266.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest51.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest341.json"
"../integration-test/ethereum-tests/GeneralStateTests/stRandom/randomStatetest177.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransactionTest/TransactionToAddressh160minusOne.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransactionTest/TransactionToItself.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransactionTest/ValueOverflow.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransactionTest/InternalCallHittingGasLimit.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransactionTest/OverflowGasRequire2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransactionTest/CreateTransactionSuccess.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransactionTest/CreateMessageReverted.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransactionTest/ContractStoreClearsSuccess.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransactionTest/ContractStoreClearsOOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransactionTest/TransactionSendingToEmpty.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransactionTest/TransactionSendingToZero.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransactionTest/SuicidesAndInternlCallSuicidesSuccess.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransactionTest/Opcodes_TransactionInit.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransactionTest/HighGasLimit.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransactionTest/EmptyTransaction3.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransactionTest/CreateTransactionEOF1.json"
"../integration-test/ethereum-tests/GeneralStateTests/stTransactionTest/TransactionDataCosts652.json"
"../integration-test/ethereum-tests/GeneralStateTests/VMTests/vmPerformance/loopMul.json"
"../integration-test/ethereum-tests/GeneralStateTests/VMTests/vmPerformance/loopExp.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump1.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds1.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOOG_MemExpansionOOV.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorMemOOGAndInsufficientBalance.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump0.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb1.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0_OOG_atMaxCallDepth.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb3.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/testRandomTest.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory1.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/ABAcalls2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds0.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMemExpansion.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/ABAcalls1.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory0.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/createWithInvalidOpcode.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/ABAcalls3.json"
"../integration-test/ethereum-tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwnerNoArgument.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/dayLimitResetSpentToday.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/walletConstructionOOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitOnlyOneOwnerNew.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner_mySelf.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/multiOwnedConstructionNotEnoughGas.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner_toIsOwner.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/multiOwnedAddOwnerAddMyself.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/dayLimitConstructionOOG.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/walletRemoveOwnerRemovePendingTransaction.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/walletAddOwnerRemovePendingTransaction.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/dayLimitConstructionPartial.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/multiOwnedConstructionCorrect.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/dayLimitConstruction.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/walletKillToWallet.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/walletChangeOwnerRemovePendingTransaction.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/walletConstruction.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo1.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner_ownerIsNotOwner.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo0.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitMultiOwner.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/multiOwnedConstructionNotEnoughGasPartial.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitOnlyOneOwner.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/dayLimitSetDailyLimit.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/walletKill.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/dayLimitSetDailyLimitNoData.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/walletChangeRequirementRemovePendingTransaction.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/multiOwnedAddOwner.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo2.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/walletConstructionPartial.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner_fromNotOwner.json"
"../integration-test/ethereum-tests/GeneralStateTests/stWalletTest/walletExecuteUnderDailyLimit.json"
"../integration-test/ethereum-tests/GeneralStateTests/stEIP2930/manualCreate.json"
"../integration-test/ethereum-tests/GeneralStateTests/stEIP2930/variedContext.json"
 */
