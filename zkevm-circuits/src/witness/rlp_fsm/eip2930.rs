use halo2_proofs::arithmetic::FieldExt;

use crate::witness::tx::{SignedTxEip2930, TxEip2930};

use super::{RlpFsmWitnessGen, RomTableRow};

impl<F: FieldExt> RlpFsmWitnessGen<F> for TxEip2930 {
    fn gen_witness(
        &self,
        challenges: &crate::util::Challenges<halo2_proofs::circuit::Value<F>>,
    ) -> Vec<super::RlpFsmWitnessRow<halo2_proofs::circuit::Value<F>>> {
        unimplemented!()
    }
}

impl<F: FieldExt> RlpFsmWitnessGen<F> for SignedTxEip2930 {
    fn gen_witness(
        &self,
        challenges: &crate::util::Challenges<halo2_proofs::circuit::Value<F>>,
    ) -> Vec<super::RlpFsmWitnessRow<halo2_proofs::circuit::Value<F>>> {
        unimplemented!()
    }
}

pub fn tx_sign_rom_table_rows() -> Vec<RomTableRow> {
    unimplemented!()
}

pub fn tx_hash_rom_table_rows() -> Vec<RomTableRow> {
    unimplemented!()
}
