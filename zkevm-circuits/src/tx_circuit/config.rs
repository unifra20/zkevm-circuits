use crate::{
    evm_circuit::util::{not, rlc},
    table::KeccakTable,
    tx_circuit::param::{CELLS_PER_SIG, TOTAL_NUM_ROWS},
    util::{Challenges, Expr},
};
use eth_types::Field;
use halo2_base::gates::range::{RangeConfig, RangeStrategy};
use halo2_proofs::{
    circuit::{Cell, Layouter, Region, Value},
    halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine},
    plonk::{Advice, Column, ConstraintSystem, Error, FirstPhase, SecondPhase, Selector},
    poly::Rotation,
};

use super::param::{SignVerifyCircuitParams, MAX_NUM_SIG};

/// SignVerify Configuration
#[derive(Debug, Clone)]
pub(crate) struct SignVerifyConfig<F: Field> {
    // range configuration that is to be used by ecdsa circuit
    pub(crate) range_config: RangeConfig<F>,
    // Keccak
    pub(crate) q_keccak: Selector,
    pub(crate) rlc_column: Column<Advice>,
    pub(crate) keccak_table: KeccakTable,
    pub(crate) params: SignVerifyCircuitParams,
}

impl<F: Field> SignVerifyConfig<F> {
    pub(crate) fn new(meta: &mut ConstraintSystem<F>, keccak_table: KeccakTable) -> Self {
        #[cfg(feature = "onephase")]
        let num_advice = &[calc_required_advices(MAX_NUM_SIG) + 1];
        #[cfg(not(feature = "onephase"))]
        let num_advice = &[calc_required_advices(MAX_NUM_SIG), 2];

        let range_config = RangeConfig::configure(
            meta,
            RangeStrategy::Vertical,
            num_advice,
            &[17],
            1,
            13,
            20, // maximum k of the chip
        );

        // TODO: remove, not used
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // ensure that the RLC column is a second phase column
        #[cfg(not(feature = "onephase"))]
        let rlc_column = meta.advice_column_in(SecondPhase);
        #[cfg(feature = "onephase")]
        let rlc_column = meta.advice_column_in(FirstPhase);

        // Ref. spec SignVerifyChip 1. Verify that keccak(pub_key_bytes) = pub_key_hash
        // by keccak table lookup, where pub_key_bytes is built from the pub_key
        // in the ecdsa_chip.
        let q_keccak = meta.complex_selector();

        meta.lookup_any("keccak lookup table", |meta| {
            // When address is 0, we disable the signature verification by using a dummy pk,
            // msg_hash and signature which is not constrained to match msg_hash_rlc nor
            // the address.
            // Layout:
            // | q_keccak |       rlc       |
            // | -------- | --------------- |
            // |     1    | is_address_zero |
            // |          |    pk_rlc       |
            // |          |    pk_hash_rlc  |
            let q_keccak = meta.query_selector(q_keccak);
            let is_address_zero = meta.query_advice(rlc_column, Rotation::cur());
            let is_enable = q_keccak * not::expr(is_address_zero);

            let input = [
                is_enable.clone(),
                is_enable.clone(),
                is_enable.clone() * meta.query_advice(rlc_column, Rotation(1)),
                is_enable.clone() * 64usize.expr(),
                is_enable * meta.query_advice(rlc_column, Rotation(2)),
            ];
            let table = [
                meta.query_fixed(keccak_table.q_enable, Rotation::cur()),
                meta.query_advice(keccak_table.is_final, Rotation::cur()),
                meta.query_advice(keccak_table.input_rlc, Rotation::cur()),
                meta.query_advice(keccak_table.input_len, Rotation::cur()),
                meta.query_advice(keccak_table.output_rlc, Rotation::cur()),
            ];

            input.into_iter().zip(table).collect()
        });

        Self {
            range_config,
            rlc_column,
            keccak_table,
            q_keccak,
            params: SignVerifyCircuitParams::new(),
        }
    }
}

impl<F: Field> SignVerifyConfig<F> {
    pub(crate) fn load_range(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.range_config.load_lookup_table(layouter)
    }
}

fn calc_required_advices(num_verif: usize) -> usize {
    let mut num_adv = 1;
    let total_cells = num_verif * CELLS_PER_SIG;
    while num_adv < 150 {
        if num_adv << TOTAL_NUM_ROWS > total_cells {
            log::info!(
                "ecdsa chip uses {} advice columns for {} signatures",
                num_adv,
                num_verif
            );
            return num_adv;
        }
        num_adv += 1;
    }
    panic!(
        "the required advice columns exceeds 100 for {} signatures",
        num_verif
    );
}
