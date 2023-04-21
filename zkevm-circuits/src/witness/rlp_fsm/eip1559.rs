use halo2_proofs::arithmetic::FieldExt;

use crate::witness::tx::{SignedTxEip1559, TxEip1559};

use super::{RlpFsmWitnessGen, RomTableRow};

impl<F: FieldExt> RlpFsmWitnessGen<F> for TxEip1559 {
    fn gen_witness(
        &self,
        challenges: &crate::util::Challenges<halo2_proofs::circuit::Value<F>>,
    ) -> Vec<super::RlpFsmWitnessRow<halo2_proofs::circuit::Value<F>>> {
        unimplemented!()
    }
}

impl<F: FieldExt> RlpFsmWitnessGen<F> for SignedTxEip1559 {
    fn gen_witness(
        &self,
        challenges: &crate::util::Challenges<halo2_proofs::circuit::Value<F>>,
    ) -> Vec<super::RlpFsmWitnessRow<halo2_proofs::circuit::Value<F>>> {
        unimplemented!()
    }
}

pub fn tx_sign_rom_table_rows<F: FieldExt>() -> Vec<RomTableRow<F>> {
    unimplemented!()
}

pub fn tx_hash_rom_table_rows<F: FieldExt>() -> Vec<RomTableRow<F>> {
    unimplemented!()
}
