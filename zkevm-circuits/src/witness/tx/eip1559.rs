use ethers_core::utils::rlp::Encodable;

#[derive(Clone, Debug)]
pub struct TxEip1559;

impl Encodable for TxEip1559 {
    fn rlp_append(&self, s: &mut ethers_core::utils::rlp::RlpStream) {
        unimplemented!()
    }
}

#[derive(Clone, Debug)]
pub struct SignedTxEip1559;

impl Encodable for SignedTxEip1559 {
    fn rlp_append(&self, s: &mut ethers_core::utils::rlp::RlpStream) {
        unimplemented!()
    }
}
