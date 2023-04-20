use halo2_proofs::arithmetic::FieldExt;

use crate::{
    evm_circuit::param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_U64, N_BYTES_WORD},
    witness::{
        tx::{SignedTxEip155, TxEip155},
        Format::{TxHashEip155, TxSignEip155},
        Tag::{
            BeginList, ChainId, Data, EndList, Gas, GasPrice, Nonce, SigR, SigS, SigV, To, Value,
            Zero,
        },
    },
};

use super::{RlpFsmWitnessGen, RomTableRow};

impl<F: FieldExt> RlpFsmWitnessGen<F> for TxEip155 {
    fn gen_witness(
        &self,
        challenges: &crate::util::Challenges<halo2_proofs::circuit::Value<F>>,
    ) -> Vec<super::RlpFsmWitnessRow<halo2_proofs::circuit::Value<F>>> {
        unimplemented!()
    }
}

impl<F: FieldExt> RlpFsmWitnessGen<F> for SignedTxEip155 {
    fn gen_witness(
        &self,
        challenges: &crate::util::Challenges<halo2_proofs::circuit::Value<F>>,
    ) -> Vec<super::RlpFsmWitnessRow<halo2_proofs::circuit::Value<F>>> {
        unimplemented!()
    }
}

pub fn tx_sign_rom_table_rows() -> Vec<RomTableRow> {
    vec![
        (BeginList, Nonce, N_BYTES_U64, TxSignEip155).into(),
        (Nonce, GasPrice, N_BYTES_U64, TxSignEip155).into(),
        (GasPrice, Gas, N_BYTES_WORD, TxSignEip155).into(),
        (Gas, To, N_BYTES_U64, TxSignEip155).into(),
        (To, Value, N_BYTES_ACCOUNT_ADDRESS, TxSignEip155).into(),
        (Value, Data, N_BYTES_WORD, TxSignEip155).into(),
        (Data, ChainId, 2usize.pow(24), TxSignEip155).into(),
        (ChainId, Zero, N_BYTES_U64, TxSignEip155).into(),
        (Zero, Zero, 1, TxSignEip155).into(),
        (Zero, EndList, 1, TxSignEip155).into(),
        (EndList, BeginList, 0, TxSignEip155).into(),
    ]
}

pub fn tx_hash_rom_table_rows() -> Vec<RomTableRow> {
    vec![
        (BeginList, Nonce, N_BYTES_U64, TxHashEip155).into(),
        (Nonce, GasPrice, N_BYTES_U64, TxHashEip155).into(),
        (GasPrice, Gas, N_BYTES_WORD, TxHashEip155).into(),
        (Gas, To, N_BYTES_U64, TxHashEip155).into(),
        (To, Value, N_BYTES_ACCOUNT_ADDRESS, TxHashEip155).into(),
        (Value, Data, N_BYTES_WORD, TxHashEip155).into(),
        (Data, SigV, 2usize.pow(24), TxHashEip155).into(),
        (SigV, SigR, N_BYTES_U64, TxHashEip155).into(),
        (SigR, SigS, N_BYTES_WORD, TxHashEip155).into(),
        (SigS, EndList, N_BYTES_WORD, TxHashEip155).into(),
        (EndList, BeginList, 0, TxHashEip155).into(),
    ]
}
