#![cfg(feature = "circuits")]

use bus_mapping::circuit_input_builder::{keccak_inputs, BuilderClient, CircuitsParams};

use halo2_proofs::circuit::Value;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use integration_tests::{get_client, log_init, GenDataOutput};
use integration_tests::{END_BLOCK, START_BLOCK, TX_ID};
use lazy_static::lazy_static;
use paste::paste;
use zkevm_circuits::bytecode_circuit::dev::test_bytecode_circuit;
use zkevm_circuits::copy_circuit::dev::test_copy_circuit;
use zkevm_circuits::evm_circuit::EvmCircuit;
use zkevm_circuits::evm_circuit::{test::run_test_circuit, witness::block_convert};
use zkevm_circuits::keccak_circuit::keccak_packed_multi::multi_keccak;
use zkevm_circuits::state_circuit::StateCircuit;
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::tx_circuit::TxCircuit;
use zkevm_circuits::util::{Challenges, SubCircuit};

lazy_static! {
    pub static ref GEN_DATA: GenDataOutput = GenDataOutput::load();
}

const CIRCUITS_PARAMS: CircuitsParams = CircuitsParams {
    max_rws: 0,
    max_txs: 10,
    max_calldata: 4000,
    max_bytecode: 4000,
    keccak_padding: None,
};

#[tokio::test]
async fn test_mock_prove_tx() {
    log_init();
    let tx_id: &str = &TX_ID;
    log::info!("test evm circuit, tx: {}", tx_id);
    if tx_id.is_empty() {
        return;
    }
    let cli = get_client();
    let cli = BuilderClient::new(cli, CIRCUITS_PARAMS).await.unwrap();
    let builder = cli.gen_inputs_tx(tx_id).await.unwrap();

    if builder.block.txs.is_empty() {
        log::info!("skip empty block");
        return;
    }

    let block = block_convert(&builder.block, &builder.code_db).unwrap();
    run_test_circuit(block).unwrap();
    log::info!("prove done");
}

#[tokio::test]
async fn test_evm_circuit_all_block() {
    log_init();
    let start: usize = *START_BLOCK;
    let end: usize = *END_BLOCK;
    for blk in start..=end {
        test_evm_circuit_block(blk as u64).await;
    }
}

#[tokio::test]
async fn test_print_circuits_size() {
    log_init();
    let start: usize = *START_BLOCK;
    let end: usize = *END_BLOCK;
    for block_num in start..=end {
        log::info!("test circuits size, block number: {}", block_num);
        let cli = get_client();
        let cli = BuilderClient::new(cli, CIRCUITS_PARAMS).await.unwrap();
        let (builder, _) = cli.gen_inputs(block_num as u64).await.unwrap();

        if builder.block.txs.is_empty() {
            log::info!("skip empty block");
            return;
        }

        let block = block_convert(&builder.block, &builder.code_db).unwrap();
        let evm_rows = EvmCircuit::get_num_rows_required(&block);
        let keccak_inputs = keccak_inputs(&builder.block, &builder.code_db).unwrap();

        let challenges = Challenges::mock(
            Value::known(block.randomness),
            Value::known(block.randomness),
        );
        let keccak_rows = multi_keccak(&keccak_inputs, challenges, None)
            .unwrap()
            .len();
        log::info!(
            "block number: {}, evm row {}, keccak row {}",
            block_num,
            evm_rows,
            keccak_rows
        );
    }
}

#[tokio::test]
async fn test_evm_circuit_batch() {
    log_init();
    let start: usize = 1;
    let end: usize = 8;
    let cli = get_client();
    let cli = BuilderClient::new(cli, CIRCUITS_PARAMS).await.unwrap();
    let builder = cli
        .gen_inputs_multi_blocks(start as u64, end as u64 + 1)
        .await
        .unwrap();

    if builder.block.txs.is_empty() {
        log::info!("skip empty block");
        return;
    }

    let block = block_convert(&builder.block, &builder.code_db).unwrap();
    log::info!("tx num: {}", builder.block.txs.len());
    run_test_circuit(block).unwrap();
    log::info!("prove done");
}

async fn test_evm_circuit_block(block_num: u64) {
    log::info!("test evm circuit, block number: {}", block_num);
    let cli = get_client();
    let cli = BuilderClient::new(cli, CIRCUITS_PARAMS).await.unwrap();
    let (builder, _) = cli.gen_inputs(block_num).await.unwrap();

    let block = block_convert(&builder.block, &builder.code_db).unwrap();
    if builder.block.txs.is_empty() {
        log::info!("skip empty block");
        return;
    }

    let result = run_test_circuit(block);
    log::info!(
        "test evm circuit, block number: {} result {:?}",
        block_num,
        result
    );
}

async fn test_state_circuit_block(block_num: u64) {
    const DEGREE: usize = 17;
    log::info!("test state circuit, block number: {}", block_num);
    let cli = get_client();
    let cli = BuilderClient::new(cli, CIRCUITS_PARAMS).await.unwrap();
    let (builder, _) = cli.gen_inputs(block_num).await.unwrap();
    let block = block_convert(&builder.block, &builder.code_db).unwrap();

    let circuit = StateCircuit::<Fr>::new_from_block(&block);
    let prover = MockProver::<Fr>::run(DEGREE as u32, &circuit, circuit.instance()).unwrap();
    prover
        .verify_par()
        .expect("state_circuit verification failed");
}

async fn test_tx_circuit_block(block_num: u64) {
    const DEGREE: u32 = 20;

    log::info!("test tx circuit, block number: {}", block_num);
    let cli = get_client();
    let cli = BuilderClient::new(cli, CIRCUITS_PARAMS).await.unwrap();

    let (builder, _) = cli.gen_inputs(block_num).await.unwrap();
    let block = block_convert(&builder.block, &builder.code_db).unwrap();
    let circuit = TxCircuit::<Fr>::new_from_block(&block);

    let prover = MockProver::run(DEGREE, &circuit, vec![vec![]]).unwrap();

    prover.verify_par().expect("tx_circuit verification failed");
}

pub async fn test_bytecode_circuit_block(block_num: u64) {
    const DEGREE: u32 = 16;

    log::info!("test bytecode circuit, block number: {}", block_num);
    let cli = get_client();
    let cli = BuilderClient::new(cli, CIRCUITS_PARAMS).await.unwrap();
    let (builder, _) = cli.gen_inputs(block_num).await.unwrap();
    let bytecodes: Vec<Vec<u8>> = builder.code_db.0.values().cloned().collect();

    test_bytecode_circuit::<Fr>(DEGREE, bytecodes);
}

pub async fn test_copy_circuit_block(block_num: u64) {
    const DEGREE: u32 = 16;

    log::info!("test copy circuit, block number: {}", block_num);
    let cli = get_client();
    let cli = BuilderClient::new(cli, CIRCUITS_PARAMS).await.unwrap();
    let (builder, _) = cli.gen_inputs(block_num).await.unwrap();
    let block = block_convert(&builder.block, &builder.code_db).unwrap();

    assert!(test_copy_circuit(DEGREE, block).is_ok());
}

pub async fn test_super_circuit_block(block_num: u64) {
    const MAX_TXS: usize = 4;
    const MAX_CALLDATA: usize = 512;
    const MAX_RWS: usize = 5888;
    const MAX_BYTECODE: usize = 5000;

    log::info!("test super circuit, block number: {}", block_num);
    let cli = get_client();
    let cli = BuilderClient::new(
        cli,
        CircuitsParams {
            max_rws: MAX_RWS,
            max_txs: MAX_TXS,
            max_calldata: MAX_CALLDATA,
            max_bytecode: MAX_BYTECODE,
            keccak_padding: None,
        },
    )
    .await
    .unwrap();
    let (builder, _) = cli.gen_inputs(block_num).await.unwrap();
    let (k, circuit, instance) =
        SuperCircuit::<_, MAX_TXS, MAX_CALLDATA, MAX_RWS>::build_from_circuit_input_builder(
            &builder,
        )
        .unwrap();
    let prover = MockProver::run(k, &circuit, instance).unwrap();
    let res = prover.verify_par();
    if let Err(err) = res {
        eprintln!("Verification failures:");
        eprintln!("{:#?}", err);
        panic!("Failed verification");
    }
}

macro_rules! declare_tests {
    ($name:ident, $block_tag:expr) => {
        paste! {
            #[tokio::test]
            async fn [<serial_test_evm_ $name>]() {
                log_init();
                let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
                test_evm_circuit_block(*block_num).await;
            }

            #[tokio::test]
            async fn [<serial_test_state_ $name>]() {
                log_init();
                let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
                test_state_circuit_block(*block_num).await;
            }

            #[tokio::test]
            async fn [<serial_test_tx_ $name>]() {
                log_init();
                let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
                test_tx_circuit_block(*block_num).await;
            }

            #[tokio::test]
            async fn [<serial_test_bytecode_ $name>]() {
                log_init();
                let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
                test_bytecode_circuit_block(*block_num).await;
            }

            #[tokio::test]
            async fn [<serial_test_copy_ $name>]() {
                log_init();
                let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
                test_copy_circuit_block(*block_num).await;
            }

            #[tokio::test]
            async fn [<serial_test_super_ $name>]() {
                log_init();
                let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
                test_super_circuit_block(*block_num).await;
            }
        }
    };
}

declare_tests!(circuit_block_transfer_0, "Transfer 0");
/*
declare_tests!(
    circuit_deploy_greeter,
    "Deploy Greeter"
);
*/
declare_tests!(circuit_multiple_transfers_0, "Multiple transfers 0");
declare_tests!(
    circuit_erc20_openzeppelin_transfer_fail,
    "ERC20 OpenZeppelin transfer failed"
);
declare_tests!(
    circuit_erc20_openzeppelin_transfer_succeed,
    "ERC20 OpenZeppelin transfer successful"
);
declare_tests!(
    circuit_multiple_erc20_openzeppelin_transfers,
    "Multiple ERC20 OpenZeppelin transfers"
);
