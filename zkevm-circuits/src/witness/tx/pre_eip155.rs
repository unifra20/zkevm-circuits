use ethers_core::utils::rlp::Encodable;

#[derive(Clone, Debug)]
pub struct TxPreEip155;

impl Encodable for TxPreEip155 {
    fn rlp_append(&self, s: &mut ethers_core::utils::rlp::RlpStream) {
        unimplemented!()
    }
}

#[derive(Clone, Debug)]
pub struct SignedTxPreEip155;

impl Encodable for SignedTxPreEip155 {
    fn rlp_append(&self, s: &mut ethers_core::utils::rlp::RlpStream) {
        unimplemented!()
    }
}
