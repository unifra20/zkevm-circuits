use ethers_core::utils::rlp::Encodable;

#[derive(Clone, Debug)]
pub struct TxEip2930;

impl Encodable for TxEip2930 {
    fn rlp_append(&self, s: &mut ethers_core::utils::rlp::RlpStream) {
        unimplemented!()
    }
}

#[derive(Clone, Debug)]
pub struct SignedTxEip2930;

impl Encodable for SignedTxEip2930 {
    fn rlp_append(&self, s: &mut ethers_core::utils::rlp::RlpStream) {
        unimplemented!()
    }
}
