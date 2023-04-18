use std::marker::PhantomData;

use eth_types::Field;
use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    is_equal::{IsEqualChip, IsEqualConfig},
    util::{and, not, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};

use crate::{
    evm_circuit::util::constraint_builder::BaseConstraintBuilder,
    table::{LookupTable, RlpFsmDataTable, RlpFsmRlpTable, RlpFsmRomTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{Block, GenericSignedTransaction, RlpFsmWitnessGen, State, Tag},
};

struct Range256Table(Column<Fixed>);

impl<F: Field> LookupTable<F> for Range256Table {
    fn columns(&self) -> Vec<Column<halo2_proofs::plonk::Any>> {
        vec![self.0.into()]
    }

    fn annotations(&self) -> Vec<String> {
        vec![String::from("byte_value")]
    }
}

/// The RLP Circuit is implemented as a finite state machine. Refer the
/// [design doc][doclink] for design decisions and specification details.
///
/// [doclink]: https://hackmd.io/VMjQdO0SRu2azN6bR_aOrQ?view
#[derive(Clone, Debug)]
pub struct RlpCircuitConfig<F> {
    /// Whether the row is enabled.
    q_enabled: Column<Fixed>,
    /// Whether we should do a lookup to the data table or not.
    q_lookup_data: Selector,
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
    /// Boolean check whether or not the current tag represents a list or not.
    is_list: Column<Advice>,
    /// The maximum length, in terms of number of bytes that this tag can occupy.
    max_length: Column<Advice>,
    /// The depth at this row. Since RLP encoded data can be nested, we use
    /// the depth to go a level deeper and eventually leave that depth level.
    /// At depth == 0 we know that we are at the outermost level.
    depth: Column<Advice>,

    /// Check tx_id == 0 to know if it is meant to be padding row or not.
    padding: IsEqualConfig<F>,

    /// Check equality between tx_id' and tx_id in the data table.
    tx_id_check: IsEqualConfig<F>,
    /// Check equality between format' and format in the data table.
    format_check: IsEqualConfig<F>,
}

impl<F: Field> RlpCircuitConfig<F> {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        rom_table: &RlpFsmRomTable,
        data_table: &RlpFsmDataTable,
        rlp_table: &RlpFsmRlpTable,
        range256_table: &Range256Table,
        challenges: &Challenges<Expression<F>>,
    ) -> Self {
        let (tx_id, format) = (rlp_table.tx_id, rlp_table.format);
        let (
            q_enabled,
            q_lookup_data,
            state,
            byte_idx,
            byte_rev_idx,
            byte_value,
            tag,
            tag_next,
            tag_idx,
            tag_length,
            is_list,
            max_length,
            depth,
        ) = (
            meta.fixed_column(),
            meta.complex_selector(),
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
            meta.advice_column(),
        );
        let padding = IsEqualChip::configure(
            meta,
            |meta| meta.query_fixed(q_enabled, Rotation::cur()),
            |meta| meta.query_advice(tx_id, Rotation::cur()),
            |_meta| 0.expr(),
        );
        let (is_padding, is_not_padding) = (
            padding.is_equal_expression.expr(),
            not::expr(padding.is_equal_expression.expr()),
        );
        let state_bits = BinaryNumberChip::configure(meta, q_enabled, Some(state.into()));
        let tag_bits = BinaryNumberChip::configure(meta, q_enabled, Some(tag.into()));

        // data table checks.
        let tx_id_check = IsEqualChip::configure(
            meta,
            |meta| {
                and::expr([
                    meta.query_fixed(q_enabled, Rotation::cur()),
                    is_not_padding.expr(),
                ])
            },
            |meta| meta.query_advice(data_table.tx_id, Rotation::cur()),
            |meta| meta.query_advice(data_table.tx_id, Rotation::next()),
        );
        let format_check = IsEqualChip::configure(
            meta,
            |meta| {
                and::expr([
                    meta.query_fixed(q_enabled, Rotation::cur()),
                    is_not_padding.expr(),
                ])
            },
            |meta| meta.query_advice(data_table.format, Rotation::cur()),
            |meta| meta.query_advice(data_table.format, Rotation::next()),
        );

        // randomness values.
        let evm_word_rand = challenges.evm_word();
        let keccak_input_rand = challenges.keccak_input();

        meta.create_gate("data table checks", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // if tx_id' == tx_id and format' == format then:
            cb.condition(
                and::expr([
                    tx_id_check.is_equal_expression.expr(),
                    format_check.is_equal_expression.expr(),
                ]),
                |cb| {
                    // byte_idx' == byte_idx + 1
                    cb.require_equal(
                        "byte_idx increments",
                        meta.query_advice(data_table.byte_idx, Rotation::next()),
                        meta.query_advice(data_table.byte_idx, Rotation::cur()) + 1.expr(),
                    );
                    // byte_rev_idx' + 1 == byte_rev_idx
                    cb.require_equal(
                        "byte_rev_idx decrements",
                        meta.query_advice(data_table.byte_rev_idx, Rotation::next()) + 1.expr(),
                        meta.query_advice(data_table.byte_rev_idx, Rotation::cur()),
                    );
                    // bytes_rlc' == bytes_rlc * r + byte_value'
                    cb.require_equal(
                        "correct random linear combination of byte value",
                        meta.query_advice(data_table.bytes_rlc, Rotation::next()),
                        meta.query_advice(data_table.bytes_rlc, Rotation::cur())
                            * keccak_input_rand
                            + meta.query_advice(data_table.byte_value, Rotation::next()),
                    );
                },
            );

            // if tx_id' != tx_id then:
            cb.condition(not::expr(tx_id_check.is_equal_expression.expr()), |cb| {
                // tx_id' == tx_id + 1
                cb.require_equal(
                    "tx_id increments",
                    meta.query_advice(data_table.tx_id, Rotation::cur()),
                    meta.query_advice(data_table.tx_id, Rotation::next()),
                );
                // byte_idx' == 1
                cb.require_equal(
                    "byte_idx starts at 1 for new tx",
                    meta.query_advice(data_table.byte_idx, Rotation::next()),
                    1.expr(),
                );
                // bytes_rlc' == byte_value'
                cb.require_equal(
                    "byte_value and bytes_rlc are equal at the first index",
                    meta.query_advice(data_table.bytes_rlc, Rotation::next()),
                    meta.query_advice(data_table.byte_value, Rotation::next()),
                );
            });

            // if tx_id' == tx_id then:
            cb.condition(tx_id_check.is_equal_expression.expr(), |cb| {
                let (format_cur, format_next) = (
                    meta.query_advice(data_table.format, Rotation::cur()),
                    meta.query_advice(data_table.format, Rotation::next()),
                );
                // format' == format or format' == format + 1
                cb.require_zero(
                    "format unchanged or increments",
                    and::expr([
                        format_next.expr() - format_cur.expr(),
                        format_next.expr() - format_cur.expr() - 1.expr(),
                    ]),
                );
            });

            // if tx_id' == tx_id and format' != format then:
            cb.condition(
                not::expr(and::expr([
                    tx_id_check.is_equal_expression.expr(),
                    format_check.is_equal_expression.expr(),
                ])),
                |cb| {
                    // byte_rev_idx == 1
                    cb.require_equal(
                        "byte_rev_idx is 1 at the last index",
                        meta.query_advice(data_table.byte_rev_idx, Rotation::cur()),
                        1.expr(),
                    );
                    // byte_idx' == 1
                    cb.require_equal(
                        "byte_idx resets to 1 for new format",
                        meta.query_advice(data_table.byte_idx, Rotation::next()),
                        1.expr(),
                    );
                    // bytes_rlc' == byte_value'
                    cb.require_equal(
                        "bytes_value and bytes_rlc are equal at the first index",
                        meta.query_advice(data_table.byte_value, Rotation::next()),
                        meta.query_advice(data_table.bytes_rlc, Rotation::next()),
                    );
                },
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_not_padding.expr(),
            ]))
        });

        meta.lookup_any("byte value check", |meta| {
            let cond = and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_not_padding.expr(),
            ]);
            vec![meta.query_advice(data_table.byte_value, Rotation::cur())]
                .into_iter()
                .zip(range256_table.table_exprs(meta).into_iter())
                .map(|(arg, table)| (cond.expr() * arg, table))
                .collect()
        });

        meta.create_gate("padding checks", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // if the current row is padding, the next row is also padding.
            cb.require_zero(
                "if tx_id == 0 then tx_id' == 0",
                meta.query_advice(tx_id, Rotation::next()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_padding.expr(),
            ]))
        });

        meta.lookup_any("data table lookup", |meta| {
            let cond = meta.query_selector(q_lookup_data);
            vec![
                meta.query_advice(tx_id, Rotation::cur()),
                meta.query_advice(format, Rotation::cur()),
                meta.query_advice(byte_idx, Rotation::cur()),
                meta.query_advice(byte_rev_idx, Rotation::cur()),
                meta.query_advice(byte_value, Rotation::cur()),
            ]
            .into_iter()
            .zip(data_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (cond.expr() * arg, table))
            .collect()
        });

        meta.lookup_any("ROM table lookup", |meta| {
            let cond = and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_not_padding.expr(),
                not::expr(state_bits.value_equals(State::End, Rotation::cur())(meta)),
            ]);
            vec![
                meta.query_advice(tag, Rotation::cur()),
                meta.query_advice(tag_next, Rotation::cur()),
                meta.query_advice(max_length, Rotation::cur()),
                meta.query_advice(is_list, Rotation::cur()),
                meta.query_advice(format, Rotation::cur()),
            ]
            .into_iter()
            .zip(rom_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (cond.expr() * arg, table))
            .collect()
        });

        // TODO(rohit): state transition constraints.

        Self {
            q_enabled,
            q_lookup_data,
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
            is_list,
            max_length,
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
    pub range256_table: Range256Table,
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
            &args.range256_table,
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
