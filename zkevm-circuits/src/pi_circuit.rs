//! Public Input Circuit implementation

use std::iter;
use std::marker::PhantomData;

use crate::table::TxFieldTag;
use crate::table::TxTable;
use crate::table::{BlockTable, KeccakTable};
use crate::util::{random_linear_combine_word as rlc, Challenges};
use bus_mapping::circuit_input_builder::get_dummy_tx;
use eth_types::geth_types::BlockConstants;
use eth_types::sign_types::SignData;
use eth_types::H256;
use eth_types::{geth_types::Transaction, Address, Field, ToBigEndian, ToScalar, Word};
use ethers_core::types::Block;
use ethers_core::utils::keccak256;
use gadgets::util::Expr;
use halo2_proofs::plonk::{Fixed, Instance, SecondPhase};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

/// Fixed by the spec
const BLOCK_LEN: usize = 7 + 256;
const EXTRA_LEN: usize = 2;
const BYTE_POW_BASE: u64 = 1 << 8;
const BLOCK_HEADER_BYTES_NUM: usize = 116;
const KECCAK_DIGEST_SIZE: usize = 32;
const RPI_CELL_IDX: usize = 0;
const RPI_RLC_ACC_CELL_IDX: usize = 1;

/// Values of the block table (as in the spec)
#[derive(Clone, Default, Debug)]
pub struct BlockValues {
    coinbase: Address,
    gas_limit: u64,
    number: u64,
    timestamp: u64,
    difficulty: Word,
    base_fee: Word, // NOTE: BaseFee was added by EIP-1559 and is ignored in legacy headers.
    chain_id: u64,
    history_hashes: Vec<H256>,
}

/// Values of the tx table (as in the spec)
#[derive(Default, Debug, Clone)]
pub struct TxValues {
    nonce: u64,
    gas: u64, //gas limit
    gas_price: Word,
    from_addr: Address,
    to_addr: Address,
    is_create: u64,
    value: Word,
    call_data_len: u64,
    call_data_gas_cost: u64,
    v: u64,
    r: Word,
    s: Word,
    tx_sign_hash: [u8; 32],

    /// Transaction hash.
    pub tx_hash: H256,
}

/// Extra values (not contained in block or tx tables)
#[derive(Default, Debug, Clone)]
pub struct ExtraValues {
    // block_hash: H256,
    state_root: H256,
    prev_state_root: H256,
}

/// PublicData contains all the values that the PiCircuit recieves as input
#[derive(Debug, Clone, Default)]
pub struct PublicData {
    /// chain id
    pub chain_id: Word,
    /// History hashes contains the most recent 256 block hashes in history,
    /// where the latest one is at history_hashes[history_hashes.len() - 1].
    pub history_hashes: Vec<Word>,
    /// Block from geth
    pub eth_block: Block<eth_types::Transaction>,
    /// Constants related to Ethereum block
    pub block_constants: BlockConstants,
    /// Previous block root
    pub prev_state_root: H256,
}

impl PublicData {
    /// Returns struct with values for the block table
    pub fn get_block_table_values(&self) -> BlockValues {
        let history_hashes = [
            vec![H256::zero(); 256 - self.history_hashes.len()],
            self.history_hashes
                .iter()
                .map(|&hash| H256::from(hash.to_be_bytes()))
                .collect(),
        ]
        .concat();
        BlockValues {
            coinbase: self.block_constants.coinbase,
            gas_limit: self.block_constants.gas_limit.as_u64(),
            number: self.block_constants.number.as_u64(),
            timestamp: self.block_constants.timestamp.as_u64(),
            difficulty: self.block_constants.difficulty,
            base_fee: self.block_constants.base_fee,
            chain_id: self.chain_id.as_u64(),
            history_hashes,
        }
    }

    /// Returns struct with values for the tx table
    pub fn get_tx_table_values(&self) -> Vec<TxValues> {
        let chain_id: u64 = self
            .chain_id
            .try_into()
            .expect("Error converting chain_id to u64");
        let mut tx_vals = vec![];
        for tx in &self.txs() {
            let sign_data: SignData = tx
                .sign_data(chain_id)
                .expect("Error computing tx_sign_hash");
            let mut msg_hash_le = [0u8; 32];
            msg_hash_le.copy_from_slice(sign_data.msg_hash.to_bytes().as_slice());
            tx_vals.push(TxValues {
                nonce: tx.nonce.as_u64(),
                gas_price: tx.gas_price,
                gas: tx.gas_limit.as_u64(),
                from_addr: tx.from,
                to_addr: tx.to.unwrap_or_else(Address::zero),
                is_create: (tx.to.is_none() as u64),
                value: tx.value,
                call_data_len: tx.call_data.0.len() as u64,
                call_data_gas_cost: tx.call_data.iter().fold(0, |acc, b| {
                    if *b == 0 {
                        acc + 4
                    } else {
                        acc + 16
                    }
                }),
                v: tx.v,
                r: tx.r,
                s: tx.s,
                tx_sign_hash: msg_hash_le,
                tx_hash: tx.hash,
            });
        }
        tx_vals
    }

    /// Returns struct with the extra values
    pub fn get_extra_values(&self) -> ExtraValues {
        ExtraValues {
            // block_hash: self.eth_block.hash.unwrap_or_else(H256::zero),
            state_root: self.eth_block.state_root,
            prev_state_root: self.prev_state_root,
        }
    }

    fn txs(&self) -> Vec<Transaction> {
        self.eth_block
            .transactions
            .iter()
            .map(Transaction::from)
            .collect()
    }

    fn get_pi<const MAX_TXS: usize, const MAX_CALLDATA: usize>(&self) -> H256 {
        let rpi_bytes = raw_public_input_bytes::<MAX_TXS, MAX_CALLDATA>(self);
        let rpi_keccak = keccak256(&rpi_bytes);
        H256(rpi_keccak)
    }
}

fn rlc_be_bytes<F: Field, const N: usize>(bytes: [u8; N], rand: Value<F>) -> Value<F> {
    bytes
        .into_iter()
        .fold(Value::known(F::zero()), |acc, byte| {
            acc.zip(rand)
                .and_then(|(acc, rand)| Value::known(acc * rand + F::from(byte as u64)))
        })
}

/// Config for PiCircuit
#[derive(Clone, Debug)]
pub struct PiCircuitConfig<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> {
    block_table: BlockTable,
    tx_table: TxTable,
    keccak_table: KeccakTable,

    raw_public_inputs: Column<Advice>, // block, extra, tx hashes
    rpi_field_bytes: Column<Advice>,   // rpi in bytes
    rpi_field_bytes_acc: Column<Advice>,
    rpi_rlc_acc: Column<Advice>, // RLC(rpi) as the input to Keccak table

    q_field_start: Selector,
    q_field_step: Selector,
    is_field_rlc: Column<Fixed>,
    q_field_end: Selector,

    q_start: Selector,
    q_not_end: Selector,
    q_keccak: Selector,

    challenges: Challenges,

    pi: Column<Instance>, // hi(keccak(rpi)), lo(keccak(rpi))

    _marker: PhantomData<F>,
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>
    PiCircuitConfig<F, MAX_TXS, MAX_CALLDATA>
{
    /// Return a new PiCircuitConfig
    pub fn new(
        meta: &mut ConstraintSystem<F>,
        block_table: BlockTable,
        tx_table: TxTable,
        keccak_table: KeccakTable,
        challenges: Challenges,
    ) -> Self {
        let rpi = meta.advice_column_in(SecondPhase);
        let rpi_bytes = meta.advice_column();
        let rpi_bytes_acc = meta.advice_column_in(SecondPhase);
        let rpi_rlc_acc = meta.advice_column_in(SecondPhase);

        let pi = meta.instance_column();

        let q_field_start = meta.complex_selector();
        let q_field_step = meta.complex_selector();
        let q_field_end = meta.complex_selector();
        let is_field_rlc = meta.fixed_column();

        let q_start = meta.complex_selector();
        let q_not_end = meta.complex_selector();
        let q_keccak = meta.complex_selector();

        meta.enable_equality(rpi);
        meta.enable_equality(rpi_rlc_acc);
        meta.enable_equality(block_table.value); // copy block to rpi
        meta.enable_equality(tx_table.value); // copy tx hashes to rpi
        meta.enable_equality(pi);

        let challenge_exprs = challenges.exprs(meta);

        // field bytes
        meta.create_gate(
            "rpi_bytes_acc[i+1] = rpi_bytes_acc[i] * t + rpi_bytes[i+1]",
            |meta| {
                let q_field_step = meta.query_selector(q_field_step);
                let bytes_acc_next = meta.query_advice(rpi_bytes_acc, Rotation::next());
                let bytes_acc = meta.query_advice(rpi_bytes_acc, Rotation::cur());
                let bytes_next = meta.query_advice(rpi_bytes, Rotation::next());
                let is_field_rlc = meta.query_fixed(is_field_rlc, Rotation::cur());
                let evm_rand = challenge_exprs.evm_word();
                let t = is_field_rlc.expr() * evm_rand
                    + (1.expr() - is_field_rlc) * BYTE_POW_BASE.expr();

                vec![q_field_step * (bytes_acc_next - (bytes_acc * t + bytes_next))]
            },
        );
        meta.create_gate("rpi_bytes_acc = rpi_bytes for field start", |meta| {
            let q_field_start = meta.query_selector(q_field_start);
            let rpi_field_bytes_acc = meta.query_advice(rpi_bytes_acc, Rotation::cur());
            let rpi_field_bytes = meta.query_advice(rpi_bytes, Rotation::cur());

            vec![q_field_start * (rpi_field_bytes_acc - rpi_field_bytes)]
        });
        meta.create_gate("rpi_bytes_acc = rpi for field end", |meta| {
            let q_field_end = meta.query_selector(q_field_end);
            let rpi_bytes_acc = meta.query_advice(rpi_bytes_acc, Rotation::cur());
            let rpi = meta.query_advice(rpi, Rotation::cur());

            vec![q_field_end * (rpi - rpi_bytes_acc)]
        });
        meta.create_gate("rpi_next = rpi", |meta| {
            let q_field_step = meta.query_selector(q_field_step);
            let rpi_next = meta.query_advice(rpi, Rotation::next());
            let rpi = meta.query_advice(rpi, Rotation::cur());

            vec![q_field_step * (rpi_next - rpi)]
        });

        // rpi_rlc
        meta.create_gate(
            "rpi_rlc_acc[i+1] = keccak_rand * rpi_rlc_acc[i] + rpi_bytes[i+1]",
            |meta| {
                // q_not_end * row_next.rpi_rlc_acc ==
                // (q_not_end * row.rpi_rlc_acc * keccak_rand + row_next.rpi_bytes)
                let q_not_end = meta.query_selector(q_not_end);
                let rpi_rlc_acc_cur = meta.query_advice(rpi_rlc_acc, Rotation::cur());
                let rpi_rlc_acc_next = meta.query_advice(rpi_rlc_acc, Rotation::next());
                let keccak_rand = challenge_exprs.keccak_input();
                let rpi_bytes_next = meta.query_advice(rpi_bytes, Rotation::next());

                vec![
                    q_not_end * (rpi_rlc_acc_cur * keccak_rand + rpi_bytes_next - rpi_rlc_acc_next),
                ]
            },
        );
        meta.create_gate("rpi_rlc_acc[0] = rpi_bytes[0]", |meta| {
            let q_start = meta.query_selector(q_start);
            let rpi_rlc_acc = meta.query_advice(rpi_rlc_acc, Rotation::cur());
            let rpi_bytes = meta.query_advice(rpi_bytes, Rotation::cur());

            vec![q_start * (rpi_rlc_acc - rpi_bytes)]
        });

        meta.lookup_any("keccak(rpi)", |meta| {
            let is_enabled = meta.query_advice(keccak_table.is_enabled, Rotation::cur());
            let input_rlc = meta.query_advice(keccak_table.input_rlc, Rotation::cur());
            let input_len = meta.query_advice(keccak_table.input_len, Rotation::cur());
            let output_rlc = meta.query_advice(keccak_table.output_rlc, Rotation::cur());
            let q_keccak = meta.query_selector(q_keccak);

            let rpi_rlc = meta.query_advice(rpi, Rotation::cur());
            let output = meta.query_advice(rpi_rlc_acc, Rotation::cur());

            vec![
                (q_keccak.expr() * 1.expr(), is_enabled),
                (q_keccak.expr() * rpi_rlc, input_rlc),
                (
                    q_keccak.expr()
                        * (BLOCK_HEADER_BYTES_NUM + (MAX_TXS + 256) * KECCAK_DIGEST_SIZE).expr(),
                    input_len,
                ),
                (q_keccak * output, output_rlc),
            ]
        });

        // The 32 bytes of keccak output are combined into (hi, lo)
        //  where r = challenges.evm_word().
        // And the layout will be like this.
        // | rpi | rpi_bytes | rpi_bytes_acc | rpi_rlc_acc |
        // | hi  |    b31    |      b31      |     b31     |
        // | hi  |    b30    | b31*2^8 + b30 | b31*r + b30 |
        // | hi  |    ...    |      ...      |     ...     |
        // | hi  |    b16    | b31*2^120+... | b31*r^15+...|
        // | lo  |    b15    |      b15      | b31*r^16+...|
        // | lo  |    b14    | b15*2^8 + b14 | b31*r^17+...|
        // | lo  |    ...    |      ...      |     ...     |
        // | lo  |     b0    | b15*2^120+... | b31*r^31+...|

        Self {
            block_table,
            tx_table,
            keccak_table,
            raw_public_inputs: rpi,
            rpi_field_bytes: rpi_bytes,
            rpi_field_bytes_acc: rpi_bytes_acc,
            rpi_rlc_acc,
            q_field_start,
            q_field_step,
            is_field_rlc,
            q_field_end,
            q_start,
            q_not_end,
            q_keccak,
            challenges,
            pi,
            _marker: PhantomData,
        }
    }

    /// Assign `rpi_rlc_acc` and `rand_rpi` columns
    #[allow(clippy::type_complexity)]
    pub fn assign_rlc_pi(
        &self,
        region: &mut Region<'_, F>,
        public_data: &PublicData,
        block_values: BlockValues,
        challenges: &Challenges<Value<F>>,
        tx_hashes: Vec<H256>,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        let mut offset = 0;
        let mut block_copy_cells = vec![];
        let mut tx_copy_cells = vec![];
        let mut rpi_rlc_acc = Value::known(F::zero());
        let dummy_tx_hash = get_dummy_tx_hash(block_values.chain_id);

        self.q_start.enable(region, offset)?;
        // Assign fields in block table
        // coinbase
        let mut cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &block_values.coinbase.to_fixed_bytes(),
            &mut rpi_rlc_acc,
            challenges,
            false,
        )?;
        debug_assert_eq!(cells.len(), 2);
        block_copy_cells.push(cells[RPI_CELL_IDX].clone());

        // gas_limit
        cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &block_values.gas_limit.to_be_bytes(),
            &mut rpi_rlc_acc,
            challenges,
            false,
        )?;
        block_copy_cells.push(cells[RPI_CELL_IDX].clone());

        // number
        cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &block_values.number.to_be_bytes(),
            &mut rpi_rlc_acc,
            challenges,
            false,
        )?;
        block_copy_cells.push(cells[RPI_CELL_IDX].clone());

        // timestamp
        cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &block_values.timestamp.to_be_bytes(),
            &mut rpi_rlc_acc,
            challenges,
            false,
        )?;
        block_copy_cells.push(cells[RPI_CELL_IDX].clone());

        // difficulty
        cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &block_values.difficulty.to_be_bytes(),
            &mut rpi_rlc_acc,
            challenges,
            false,
        )?;
        block_copy_cells.push(cells[RPI_CELL_IDX].clone());

        // base_fee
        cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &block_values.base_fee.to_be_bytes(),
            &mut rpi_rlc_acc,
            challenges,
            false,
        )?;
        block_copy_cells.push(cells[RPI_CELL_IDX].clone());

        // chain_id
        cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &block_values.chain_id.to_be_bytes(),
            &mut rpi_rlc_acc,
            challenges,
            false,
        )?;
        block_copy_cells.push(cells[RPI_CELL_IDX].clone());

        debug_assert_eq!(offset, BLOCK_HEADER_BYTES_NUM);

        // assign history block hashes
        debug_assert_eq!(block_values.history_hashes.len(), 256);
        for prev_hash in block_values.history_hashes.iter() {
            let mut prev_hash_le_bytes = prev_hash.to_fixed_bytes();
            prev_hash_le_bytes.reverse();
            let cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &prev_hash.to_fixed_bytes(),
                &mut rpi_rlc_acc,
                challenges,
                false,
            )?;
            block_copy_cells.push(cells[RPI_CELL_IDX].clone());
        }

        // assign tx hashes
        let num_txs = tx_hashes.len();
        let mut rpi_rlc_cell = None;
        for tx_hash in tx_hashes
            .into_iter()
            .chain((0..MAX_TXS - num_txs).into_iter().map(|_| dummy_tx_hash))
        {
            let cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &tx_hash.to_fixed_bytes(),
                &mut rpi_rlc_acc,
                challenges,
                false,
            )?;
            tx_copy_cells.push(cells[RPI_CELL_IDX].clone());
            rpi_rlc_cell = Some(cells[RPI_RLC_ACC_CELL_IDX].clone());
        }

        debug_assert_eq!(
            offset,
            BLOCK_HEADER_BYTES_NUM
                + (MAX_TXS + block_values.history_hashes.len()) * KECCAK_DIGEST_SIZE
        );

        for i in 0..(offset - 1) {
            self.q_not_end.enable(region, i)?;
        }

        for (i, block_cell) in block_copy_cells.into_iter().enumerate() {
            block_cell.copy_advice(
                || "copy to block table",
                region,
                self.block_table.value,
                i + 1, // starts from 1
            )?;
        }
        for (i, tx_hash_cell) in tx_copy_cells.into_iter().enumerate() {
            tx_hash_cell.copy_advice(
                || "copy to tx table",
                region,
                self.tx_table.value,
                1 + i * 14 + 14,
            )?;
        }
        // assign rpi_acc, keccak_rpi
        let keccak_row = offset;
        let rpi_rlc_cell = rpi_rlc_cell.unwrap();
        rpi_rlc_cell.copy_advice(
            || "keccak(rpi)_input",
            region,
            self.raw_public_inputs,
            keccak_row,
        )?;
        let keccak = public_data.get_pi::<MAX_TXS, MAX_CALLDATA>();
        let keccak_rlc =
            keccak
                .to_fixed_bytes()
                .iter()
                .fold(Value::known(F::zero()), |acc, byte| {
                    acc.zip(challenges.evm_word())
                        .and_then(|(acc, rand)| Value::known(acc * rand + F::from(*byte as u64)))
                });
        let keccak_output_cell = region.assign_advice(
            || "keccak(rpi)_output",
            self.rpi_rlc_acc,
            keccak_row,
            || keccak_rlc,
        )?;
        self.q_keccak.enable(region, keccak_row)?;

        // start over to accumulate big-endian bytes of keccak output
        rpi_rlc_acc = Value::known(F::zero());
        offset += 1;
        // the high 16 bytes of keccak output
        cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &keccak.to_fixed_bytes()[..16],
            &mut rpi_rlc_acc,
            challenges,
            true,
        )?;
        let keccak_hi_cell = cells[RPI_CELL_IDX].clone();

        // the low 16 bytes of keccak output
        cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &keccak.to_fixed_bytes()[16..],
            &mut rpi_rlc_acc,
            challenges,
            true,
        )?;
        let keccak_lo_cell = cells[RPI_CELL_IDX].clone();

        region.constrain_equal(
            keccak_output_cell.cell(),
            cells[RPI_RLC_ACC_CELL_IDX].cell(),
        )?;

        Ok((keccak_hi_cell, keccak_lo_cell))
    }

    fn assign_field_in_pi(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        value_bytes: &[u8],
        rpi_rlc_acc: &mut Value<F>,
        challenges: &Challenges<Value<F>>,
        keccak_hi_lo: bool,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let len = value_bytes.len();

        let mut value_bytes_acc = Value::known(F::zero());
        let (use_rlc, t) = if len * 8 > F::CAPACITY as usize {
            (F::one(), challenges.evm_word())
        } else {
            (F::zero(), Value::known(F::from(BYTE_POW_BASE)))
        };
        let r = if keccak_hi_lo {
            challenges.evm_word()
        } else {
            challenges.keccak_input()
        };
        let value = value_bytes
            .iter()
            .fold(Value::known(F::zero()), |acc, byte| {
                acc.zip(t)
                    .and_then(|(acc, t)| Value::known(acc * t + F::from(*byte as u64)))
            });

        let mut cells = vec![None, None];
        for (i, byte) in value_bytes.iter().enumerate() {
            let row_offset = *offset + i;

            // calculate acc
            value_bytes_acc = value_bytes_acc
                .zip(t)
                .and_then(|(acc, t)| Value::known(acc * t + F::from(*byte as u64)));

            *rpi_rlc_acc = rpi_rlc_acc
                .zip(r)
                .and_then(|(acc, rand)| Value::known(acc * rand + F::from(*byte as u64)));

            // set field-related selectors
            if i == 0 {
                self.q_field_start.enable(region, row_offset)?;
            }
            if i == len - 1 {
                self.q_field_end.enable(region, row_offset)?;
            } else {
                self.q_field_step.enable(region, row_offset)?;
            }

            region.assign_fixed(
                || "is_field_rlc",
                self.is_field_rlc,
                row_offset,
                || Value::known(use_rlc),
            )?;
            region.assign_advice(
                || "field byte",
                self.rpi_field_bytes,
                row_offset,
                || Value::known(F::from(*byte as u64)),
            )?;
            region.assign_advice(
                || "field byte acc",
                self.rpi_field_bytes_acc,
                row_offset,
                || value_bytes_acc,
            )?;
            let rpi_cell = region.assign_advice(
                || "field value",
                self.raw_public_inputs,
                row_offset,
                || value,
            )?;
            let rpi_rlc_cell = region.assign_advice(
                || "rpi_rlc_acc",
                self.rpi_rlc_acc,
                row_offset,
                || *rpi_rlc_acc,
            )?;

            if i == len - 1 {
                cells[RPI_CELL_IDX] = Some(rpi_cell);
                cells[RPI_RLC_ACC_CELL_IDX] = Some(rpi_rlc_cell);
            }
        }
        *offset += len;

        Ok(cells.into_iter().map(|cell| cell.unwrap()).collect())
    }

    /// Assigns a tx_table row and stores the values in a vec for the
    /// raw_public_inputs column
    #[allow(clippy::too_many_arguments)]
    fn assign_tx_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        tx_id: usize,
        tag: TxFieldTag,
        index: usize,
        tx_value: Value<F>,
    ) -> Result<(), Error> {
        let tx_id = F::from(tx_id as u64);
        let tag = F::from(tag as u64);
        let index = F::from(index as u64);

        // Assign vals to Tx_table
        region.assign_advice(
            || "tx_id",
            self.tx_table.tx_id,
            offset,
            || Value::known(tx_id),
        )?;
        region.assign_fixed(|| "tag", self.tx_table.tag, offset, || Value::known(tag))?;
        region.assign_advice(
            || "index",
            self.tx_table.index,
            offset,
            || Value::known(index),
        )?;
        region.assign_advice(|| "tx_value", self.tx_table.value, offset, || tx_value)?;

        Ok(())
    }

    /// Assigns the values for block table in the block_table column
    /// and in the raw_public_inputs column. A copy is also stored in
    /// a vector for computing RLC(raw_public_inputs)
    fn assign_block_table(
        &self,
        region: &mut Region<'_, F>,
        block_values: BlockValues,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let mut offset = 0;

        // zero row
        region.assign_advice(
            || "zero",
            self.block_table.value,
            offset,
            || Value::known(F::zero()),
        )?;
        offset += 1;

        // coinbase
        let coinbase: F = block_values.coinbase.to_scalar().unwrap();
        region.assign_advice(
            || "coinbase",
            self.block_table.value,
            offset,
            || Value::known(coinbase),
        )?;
        offset += 1;

        // gas_limit
        let gas_limit = F::from(block_values.gas_limit);
        region.assign_advice(
            || "gas_limit",
            self.block_table.value,
            offset,
            || Value::known(gas_limit),
        )?;
        offset += 1;

        // number
        let number = F::from(block_values.number);
        region.assign_advice(
            || "number",
            self.block_table.value,
            offset,
            || Value::known(number),
        )?;
        offset += 1;

        // timestamp
        let timestamp = F::from(block_values.timestamp);
        region.assign_advice(
            || "timestamp",
            self.block_table.value,
            offset,
            || Value::known(timestamp),
        )?;
        offset += 1;

        // difficulty
        let difficulty = rlc_be_bytes(block_values.difficulty.to_be_bytes(), challenges.evm_word());
        region.assign_advice(
            || "difficulty",
            self.block_table.value,
            offset,
            || difficulty,
        )?;
        offset += 1;

        // base_fee
        let base_fee = rlc_be_bytes(block_values.base_fee.to_be_bytes(), challenges.evm_word());
        region.assign_advice(|| "base_fee", self.block_table.value, offset, || base_fee)?;
        offset += 1;

        // chain_id
        let chain_id = F::from(block_values.chain_id);
        region.assign_advice(
            || "chain_id",
            self.block_table.value,
            offset,
            || Value::known(chain_id),
        )?;
        offset += 1;

        for prev_hash in block_values.history_hashes {
            let prev_hash = rlc_be_bytes(prev_hash.to_fixed_bytes(), challenges.evm_word());
            region.assign_advice(|| "prev_hash", self.block_table.value, offset, || prev_hash)?;
            offset += 1;
        }

        Ok(())
    }

    /// Assigns the extra fields (not in block or tx tables):
    ///   - state root
    ///   - previous block state root
    /// to the raw_public_inputs column and stores a copy in a
    /// vector for computing RLC(raw_public_inputs).
    fn assign_extra_fields(
        &self,
        region: &mut Region<'_, F>,
        extra: ExtraValues,
        randomness: F,
    ) -> Result<[AssignedCell<F, F>; 2], Error> {
        let mut offset = BLOCK_LEN + 1;
        // block hash
        // let block_hash = rlc(extra.block_hash.to_fixed_bytes(), randomness);
        // region.assign_advice(
        //     || "block.hash",
        //     self.raw_public_inputs,
        //     offset,
        //     || Ok(block_hash),
        // )?;
        // raw_pi_vals[offset] = block_hash;
        // offset += 1;

        // block state root
        let state_root = rlc(extra.state_root.to_fixed_bytes(), randomness);
        let state_root_cell = region.assign_advice(
            || "state.root",
            self.raw_public_inputs,
            offset,
            || Value::known(state_root),
        )?;
        offset += 1;

        // previous block state root
        let prev_state_root = rlc(extra.prev_state_root.to_fixed_bytes(), randomness);
        let prev_state_root_cell = region.assign_advice(
            || "parent_block.hash",
            self.raw_public_inputs,
            offset,
            || Value::known(prev_state_root),
        )?;
        Ok([state_root_cell, prev_state_root_cell])
    }
}

/// Public Inputs Circuit
#[derive(Clone, Default, Debug)]
pub struct PiCircuit<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> {
    /// PublicInputs data known by the verifier
    pub public_data: PublicData,

    _marker: PhantomData<F>,
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>
    PiCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    /// Creates a new PiCircuit
    pub fn new(public_data: PublicData) -> Self {
        Self {
            public_data,
            _marker: PhantomData,
        }
    }
}
impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> Circuit<F>
    for PiCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    type Config = PiCircuitConfig<F, MAX_TXS, MAX_CALLDATA>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let block_table = BlockTable::construct(meta);
        let tx_table = TxTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let challenges = Challenges::construct(meta);
        PiCircuitConfig::new(meta, block_table, tx_table, keccak_table, challenges)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = config.challenges.values(&mut layouter);
        let pi_cells = layouter.assign_region(
            || "region 0",
            |mut region| {
                // Assign block table
                let block_values = self.public_data.get_block_table_values();
                config.assign_block_table(&mut region, block_values.clone(), &challenges)?;

                // Assign extra fields
                // let extra_vals = self.public_data.get_extra_values();
                // let [state_root, prev_state_root] = config.assign_extra_fields(
                //     &mut region,
                //     extra_vals,
                //     self.randomness,
                // )?;

                let mut offset = 0;
                // Assign Tx table
                let txs = self.public_data.get_tx_table_values();
                assert!(txs.len() <= MAX_TXS);
                let tx_default = TxValues::default();

                // Add empty row
                config.assign_tx_row(
                    &mut region,
                    offset,
                    0,
                    TxFieldTag::Null,
                    0,
                    Value::known(F::zero()),
                )?;
                offset += 1;

                for i in 0..MAX_TXS {
                    let tx = if i < txs.len() { &txs[i] } else { &tx_default };

                    for (tag, value) in &[
                        (TxFieldTag::Nonce, Value::known(F::from(tx.nonce))),
                        (TxFieldTag::Gas, Value::known(F::from(tx.gas))),
                        (
                            TxFieldTag::GasPrice,
                            rlc_be_bytes(tx.gas_price.to_be_bytes(), challenges.evm_word()),
                        ),
                        (
                            TxFieldTag::CallerAddress,
                            Value::known(tx.from_addr.to_scalar().expect("tx.from too big")),
                        ),
                        (
                            TxFieldTag::CalleeAddress,
                            Value::known(tx.to_addr.to_scalar().expect("tx.to too big")),
                        ),
                        (TxFieldTag::IsCreate, Value::known(F::from(tx.is_create))),
                        (
                            TxFieldTag::Value,
                            rlc_be_bytes(tx.value.to_be_bytes(), challenges.evm_word()),
                        ),
                        (
                            TxFieldTag::CallDataLength,
                            Value::known(F::from(tx.call_data_len)),
                        ),
                        (
                            TxFieldTag::CallDataGasCost,
                            Value::known(F::from(tx.call_data_gas_cost)),
                        ),
                        (TxFieldTag::SigV, Value::known(F::from(tx.v))),
                        (
                            TxFieldTag::SigR,
                            rlc_be_bytes(tx.r.to_be_bytes(), challenges.evm_word()),
                        ),
                        (
                            TxFieldTag::SigV,
                            rlc_be_bytes(tx.s.to_be_bytes(), challenges.evm_word()),
                        ),
                        (
                            TxFieldTag::TxSignHash,
                            rlc_be_bytes(tx.tx_sign_hash, challenges.evm_word()),
                        ),
                        (
                            TxFieldTag::TxHash,
                            rlc_be_bytes(tx.tx_hash.to_fixed_bytes(), challenges.evm_word()),
                        ),
                    ] {
                        config.assign_tx_row(&mut region, offset, i + 1, *tag, 0, *value)?;
                        offset += 1;
                    }
                }
                // Tx Table CallData
                let mut calldata_count = 0;
                for (i, tx) in self.public_data.txs().iter().enumerate() {
                    for (index, byte) in tx.call_data.0.iter().enumerate() {
                        assert!(calldata_count < MAX_CALLDATA);
                        config.assign_tx_row(
                            &mut region,
                            offset,
                            i + 1,
                            TxFieldTag::CallData,
                            index,
                            Value::known(F::from(*byte as u64)),
                        )?;
                        offset += 1;
                        calldata_count += 1;
                    }
                }
                for _ in calldata_count..MAX_CALLDATA {
                    config.assign_tx_row(
                        &mut region,
                        offset,
                        0, // tx_id
                        TxFieldTag::CallData,
                        0,
                        Value::known(F::zero()),
                    )?;
                    offset += 1;
                }

                // rpi_rlc and rand_rpi cols
                let (keccak_hi_cell, keccak_lo_cell) = config.assign_rlc_pi(
                    &mut region,
                    &self.public_data,
                    block_values,
                    &challenges,
                    self.public_data
                        .get_tx_table_values()
                        .iter()
                        .map(|tx| tx.tx_hash)
                        .collect(),
                )?;

                Ok(vec![keccak_hi_cell, keccak_lo_cell])
            },
        )?;

        // assign keccak table
        let rpi_bytes = raw_public_input_bytes::<MAX_TXS, MAX_CALLDATA>(&self.public_data);
        config
            .keccak_table
            .dev_load(&mut layouter, vec![&rpi_bytes], &challenges)?;

        // Constrain raw_public_input cells to public inputs
        for (i, pi_cell) in pi_cells.iter().enumerate() {
            layouter.constrain_instance(pi_cell.cell(), config.pi, i)?;
        }

        Ok(())
    }
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>
    PiCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    /// Compute the public inputs for this circuit.
    pub fn instance(&self) -> Vec<Vec<F>> {
        let keccak_rpi = self.public_data.get_pi::<MAX_TXS, MAX_CALLDATA>();
        let keccak_hi = keccak_rpi
            .to_fixed_bytes()
            .iter()
            .take(16)
            .fold(F::zero(), |acc, byte| {
                acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
            });

        let keccak_lo = keccak_rpi
            .to_fixed_bytes()
            .iter()
            .skip(16)
            .fold(F::zero(), |acc, byte| {
                acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
            });

        // let block_hash = public_data
        //     .eth_block
        //     .hash
        //     .unwrap_or_else(H256::zero)
        //     .to_fixed_bytes();

        let public_inputs = vec![keccak_hi, keccak_lo];

        vec![public_inputs]
    }
}

/// Get the tx hash of the dummy tx (nonce=0, gas=0, gas_price=0, to=0, value=0,
/// data="") for any chain_id
fn get_dummy_tx_hash(chain_id: u64) -> H256 {
    let (tx, sig) = get_dummy_tx(chain_id);

    let tx_hash = keccak256(tx.rlp_signed(&sig));
    log::debug!("tx hash: {}", hex::encode(tx_hash));

    H256(tx_hash)
}

/// Compute the raw_public_inputs bytes from the verifier's perspective.
fn raw_public_input_bytes<const MAX_TXS: usize, const MAX_CALLDATA: usize>(
    public_data: &PublicData,
) -> Vec<u8> {
    let block = public_data.get_block_table_values();
    // let extra = public_data.get_extra_values();
    let txs = public_data.get_tx_table_values();
    let dummy_tx_hash = get_dummy_tx_hash(public_data.chain_id.as_u64());

    let result = iter::empty()
        // Block Values
        .chain(block.coinbase.to_fixed_bytes())
        .chain(block.gas_limit.to_be_bytes())
        .chain(block.number.to_be_bytes())
        .chain(block.timestamp.to_be_bytes())
        .chain(block.difficulty.to_be_bytes())
        .chain(block.base_fee.to_be_bytes())
        .chain(block.chain_id.to_be_bytes())
        .chain(
            block
                .history_hashes
                .iter()
                .flat_map(|tx_hash| tx_hash.to_fixed_bytes()),
        )
        // .chain(
        //     extra.state_root.to_fixed_bytes()
        // )
        // .chain(
        //     extra.prev_state_root.to_fixed_bytes()
        // )
        // Tx Hashes
        .chain(txs.iter().flat_map(|tx| tx.tx_hash.to_fixed_bytes()))
        .chain(
            (0..(MAX_TXS - txs.len()))
                .into_iter()
                .flat_map(|_| dummy_tx_hash.to_fixed_bytes()),
        )
        .collect::<Vec<u8>>();

    assert_eq!(
        result.len(),
        20 + 96 + 32 * block.history_hashes.len() + 32 * MAX_TXS
    );
    result
}

#[cfg(test)]
mod pi_circuit_test {
    use super::*;

    use crate::test_util::rand_tx;
    use eth_types::U256;
    use halo2_proofs::{
        dev::{MockProver, VerifyFailure},
        halo2curves::bn256::Fr,
    };
    use pretty_assertions::assert_eq;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn run<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>(
        k: u32,
        public_data: PublicData,
    ) -> Result<(), Vec<VerifyFailure>> {
        let circuit = PiCircuit::<F, MAX_TXS, MAX_CALLDATA>::new(public_data);
        let public_inputs = circuit.instance();

        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        prover.verify()
    }

    #[test]
    fn test_default_pi() {
        const MAX_TXS: usize = 2;
        const MAX_CALLDATA: usize = 8;
        let public_data = PublicData::default();

        let k = 16;
        assert_eq!(run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data), Ok(()));
    }

    #[test]
    fn test_simple_pi() {
        const MAX_TXS: usize = 4;
        const MAX_CALLDATA: usize = 20;

        let mut rng = ChaCha20Rng::seed_from_u64(2);

        let mut public_data = PublicData::default();
        let chain_id = 1337u64;
        public_data.chain_id = Word::from(chain_id);
        public_data.block_constants.coinbase = Address::random();
        public_data.block_constants.difficulty = U256::one();

        let n_tx = 2;
        for _ in 0..n_tx {
            let eth_tx = eth_types::Transaction::from(&rand_tx(&mut rng, chain_id));
            public_data.eth_block.transactions.push(eth_tx);
        }

        let k = 16;
        assert_eq!(run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data), Ok(()));
    }
}
