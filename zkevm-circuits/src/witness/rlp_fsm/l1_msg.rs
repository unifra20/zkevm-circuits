use halo2_proofs::arithmetic::FieldExt;

use crate::witness::tx::L1MsgTx;

use super::RlpFsmWitnessGen;

impl<F: FieldExt> RlpFsmWitnessGen<F> for L1MsgTx {
    fn gen_witness(
        &self,
        challenges: &crate::util::Challenges<halo2_proofs::circuit::Value<F>>,
    ) -> Vec<super::RlpFsmWitnessRow<halo2_proofs::circuit::Value<F>>> {
        unimplemented!()
    }
}
