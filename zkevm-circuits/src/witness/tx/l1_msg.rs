use ethers_core::utils::rlp::Encodable;

#[derive(Clone, Debug)]
pub struct L1MsgTx;

impl Encodable for L1MsgTx {
    fn rlp_append(&self, s: &mut ethers_core::utils::rlp::RlpStream) {
        unimplemented!()
    }
}
