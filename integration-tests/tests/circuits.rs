#![cfg(feature = "circuits")]

use bus_mapping::circuit_input_builder::{keccak_inputs, BuilderClient, CircuitsParams};

use halo2_proofs::circuit::Value;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use integration_tests::{get_client, log_init, GenDataOutput};
use integration_tests::{END_BLOCK, START_BLOCK, TX_ID};
use lazy_static::lazy_static;
use paste::paste;
use zkevm_circuits::copy_circuit::dev::test_copy_circuit;
use zkevm_circuits::evm_circuit::EvmCircuit;
use zkevm_circuits::evm_circuit::{test::run_test_circuit, witness::block_convert};
use zkevm_circuits::keccak_circuit::keccak_packed_multi::multi_keccak;
use zkevm_circuits::state_circuit::StateCircuit;
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::tx_circuit::TxCircuit;
use zkevm_circuits::util::{Challenges, SubCircuit};

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
