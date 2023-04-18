use halo2_proofs::arithmetic::FieldExt;

use crate::witness::tx::{SignedTxPreEip155, TxPreEip155};

use super::RlpFsmWitnessGen;

impl<F: FieldExt> RlpFsmWitnessGen<F> for TxPreEip155 {
    fn gen_witness(
        &self,
        challenges: &crate::util::Challenges<halo2_proofs::circuit::Value<F>>,
    ) -> Vec<super::RlpFsmWitnessRow<halo2_proofs::circuit::Value<F>>> {
        unimplemented!()
    }
}

impl<F: FieldExt> RlpFsmWitnessGen<F> for SignedTxPreEip155 {
    fn gen_witness(
        &self,
        challenges: &crate::util::Challenges<halo2_proofs::circuit::Value<F>>,
    ) -> Vec<super::RlpFsmWitnessRow<halo2_proofs::circuit::Value<F>>> {
        unimplemented!()
    }
}
