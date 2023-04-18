use std::marker::PhantomData;

use eth_types::Field;
use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    is_equal::{IsEqualChip, IsEqualConfig},
    util::{and, not, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed},
    poly::Rotation,
};

use crate::{
    evm_circuit::util::constraint_builder::BaseConstraintBuilder,
    table::{RlpFsmDataTable, RlpFsmRlpTable, RlpFsmRomTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{Block, GenericSignedTransaction, RlpFsmWitnessGen, State, Tag},
};

/// The RLP Circuit is implemented as a finite state machine. Refer the
/// [design doc][doclink] for design decisions and specification details.
///
/// [doclink]: https://hackmd.io/VMjQdO0SRu2azN6bR_aOrQ?view
#[derive(Clone, Debug)]
pub struct RlpCircuitConfig<F> {
    /// Whether the row is enabled.
    q_enabled: Column<Fixed>,
    /// The state of RLP verifier at the current row.
    state: Column<Advice>,
    /// A utility gadget to compare/query what state we are at.
    state_bits: BinaryNumberConfig<State, 3>,
    /// The tag, i.e. what field is being decoded at the current row.
    tag: Column<Advice>,
    /// A utility gadget to compare/query what tag we are at.
    tag_bits: BinaryNumberConfig<Tag, 4>,
    /// The tag that follows the tag on the current row.
    tag_next: Column<Advice>,
    /// The incremental index of this specific byte in the RLP-encoded bytes.
    byte_idx: Column<Advice>,
    /// The reverse index for the above index.
    byte_rev_idx: Column<Advice>,
    /// The byte value at this index in the RLP encoded data.
    byte_value: Column<Advice>,
    /// When the tag occupies several bytes, this index denotes the
    /// incremental index of the byte within this tag instance.
    tag_idx: Column<Advice>,
    /// The length of bytes that hold this tag's value.
    tag_length: Column<Advice>,
    /// The depth at this row. Since RLP encoded data can be nested, we use
    /// the depth to go a level deeper and eventually leave that depth level.
    /// At depth == 0 we know that we are at the outermost level.
    depth: Column<Advice>,
    /// Enabled if it is a padding row.
    padding: Column<Advice>,

    /// Data table checks.
    tx_id_check: IsEqualConfig<F>,
    format_check: IsEqualConfig<F>,
}

impl<F: Field> RlpCircuitConfig<F> {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        rom_table: &RlpFsmRomTable,
        data_table: &RlpFsmDataTable,
        rlp_table: &RlpFsmRlpTable,
        challenges: &Challenges<Expression<F>>,
    ) -> Self {
        let (tx_id, format) = (rlp_table.tx_id, rlp_table.format);
        let (
            q_enabled,
            state,
            byte_idx,
            byte_rev_idx,
            byte_value,
            tag,
            tag_next,
            tag_idx,
            tag_length,
            depth,
            padding,
        ) = (
            meta.fixed_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        );
        let state_bits = BinaryNumberChip::configure(meta, q_enabled, Some(state.into()));
        let tag_bits = BinaryNumberChip::configure(meta, q_enabled, Some(tag.into()));

        // data table checks.
        let tx_id_check = IsEqualChip::configure(
            meta,
            |meta| not::expr(meta.query_advice(padding, Rotation::cur())),
            |meta| meta.query_advice(data_table.tx_id, Rotation::cur()),
            |meta| meta.query_advice(data_table.tx_id, Rotation::next()),
        );
        let format_check = IsEqualChip::configure(
            meta,
            |meta| not::expr(meta.query_advice(padding, Rotation::cur())),
            |meta| meta.query_advice(data_table.format, Rotation::cur()),
            |meta| meta.query_advice(data_table.format, Rotation::next()),
        );

        meta.create_gate("data table checks", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // if tx_id' != tx_id then:
            //      tx_id' == tx_id + 1
            //      byte_idx' == 1
            //      byte_rev_idx == 1
            cb.condition(not::expr(tx_id_check.is_equal_expression.expr()), |cb| {
                cb.require_equal(
                    "tx_id increments",
                    meta.query_advice(data_table.tx_id, Rotation::cur()),
                    meta.query_advice(data_table.tx_id, Rotation::next()),
                );
                cb.require_equal(
                    "byte_idx starts at 1 for new tx",
                    meta.query_advice(data_table.byte_idx, Rotation::next()),
                    1.expr(),
                );
                cb.require_equal(
                    "byte_idx starts at 1 for new tx",
                    meta.query_advice(data_table.byte_rev_idx, Rotation::cur()),
                    1.expr(),
                );
            });

            // if tx_id' == tx_id then:
            //      format' == format or format' == format + 1
            cb.condition(tx_id_check.is_equal_expression.expr(), |cb| {
                let (format_cur, format_next) = (
                    meta.query_advice(data_table.format, Rotation::cur()),
                    meta.query_advice(data_table.format, Rotation::next()),
                );
                cb.require_zero(
                    "format unchanged or increments",
                    and::expr([
                        format_next.expr() - format_cur.expr(),
                        format_next.expr() - format_cur.expr() - 1.expr(),
                    ]),
                );
            });

            // if tx_id' == tx_id and format' == format then:
            //      byte_idx' == byte_idx + 1
            //      byte_rev_idx' + 1 == byte_rev_idx
            cb.condition(
                and::expr([
                    tx_id_check.is_equal_expression.expr(),
                    format_check.is_equal_expression.expr(),
                ]),
                |cb| {
                    cb.require_equal(
                        "byte_idx increments",
                        meta.query_advice(data_table.byte_idx, Rotation::next()),
                        meta.query_advice(data_table.byte_idx, Rotation::cur()) + 1.expr(),
                    );
                    cb.require_equal(
                        "byte_rev_idx decrements",
                        meta.query_advice(data_table.byte_rev_idx, Rotation::next()) + 1.expr(),
                        meta.query_advice(data_table.byte_rev_idx, Rotation::cur()),
                    );
                },
            );

            cb.gate(not::expr(meta.query_advice(padding, Rotation::cur())))
        });

        Self {
            q_enabled,
            state,
            state_bits,
            tag,
            tag_bits,
            tag_next,
            byte_idx,
            byte_rev_idx,
            byte_value,
            tag_idx,
            tag_length,
            depth,
            padding,

            // data table checks.
            tx_id_check,
            format_check,
        }
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
