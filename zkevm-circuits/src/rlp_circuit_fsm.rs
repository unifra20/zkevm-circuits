use std::marker::PhantomData;

use eth_types::Field;
use gadgets::binary_number::BinaryNumberConfig;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression},
};

use crate::{
    table::{RlpFsmDataTable, RlpFsmRlpTable, RlpFsmRomTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{Block, GenericSignedTransaction, RlpFsmWitnessGen, State, Tag},
};

#[derive(Clone, Debug)]
pub struct RlpCircuitConfig<F> {
    state: BinaryNumberConfig<State, 3>,
    tag: BinaryNumberConfig<Tag, 4>,
    tag_next: BinaryNumberConfig<Tag, 4>,
    byte_idx: Column<Advice>,
    tag_idx: Column<Advice>,
    tag_length: Column<Advice>,
    depth: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: Field> RlpCircuitConfig<F> {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        rom_table: &RlpFsmRomTable,
        data_table: &RlpFsmDataTable,
        rlp_table: &RlpFsmRlpTable,
        challenges: &Challenges<Expression<F>>,
    ) -> Self {
        unimplemented!("RlpCircuitConfig::configure")
    }

    pub(crate) fn assign<RLP: RlpFsmWitnessGen<F>>(
        &self,
        layouter: &mut impl Layouter<F>,
        inputs: Vec<RLP>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        unimplemented!("RlpCircuitConfig::assign")
    }
}

pub struct RlpCircuitConfigArgs<F: Field> {
    pub rom_table: RlpFsmRomTable,
    pub data_table: RlpFsmDataTable,
    pub rlp_table: RlpFsmRlpTable,
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for RlpCircuitConfig<F> {
    type ConfigArgs = RlpCircuitConfigArgs<F>;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        Self::configure(
            meta,
            &args.rom_table,
            &args.data_table,
            &args.rlp_table,
            &args.challenges,
        )
    }
}

#[derive(Clone, Debug)]
pub struct RlpCircuit<F, RLP> {
    pub inputs: Vec<RLP>,
    pub max_txs: usize,
    pub size: usize,
    _marker: PhantomData<F>,
}

impl<F: Field, RLP> Default for RlpCircuit<F, RLP> {
    fn default() -> Self {
        Self {
            inputs: vec![],
            max_txs: 0,
            size: 0,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> SubCircuit<F> for RlpCircuit<F, GenericSignedTransaction> {
    type Config = RlpCircuitConfig<F>;

    fn new_from_block(block: &Block<F>) -> Self {
        let max_txs = block.circuits_params.max_txs;
        debug_assert!(block.txs.len() <= max_txs);

        todo!("RlpCircuit::new_from_block")
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        unimplemented!("RlpCircuit::synthesize_sub")
    }

    fn min_num_rows_block(block: &crate::witness::Block<F>) -> (usize, usize) {
        unimplemented!("RlpCircuit::min_num_rows_block")
    }
}

impl<F: Field> Circuit<F> for RlpCircuit<F, GenericSignedTransaction> {
    type Config = (RlpCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        unimplemented!("RlpCircuit::configure")
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        unimplemented!("RlpCircuit::synthesize")
    }
}

#[cfg(test)]
mod tests {}
