use ethers_core::utils::rlp::Encodable;
use gadgets::{impl_expr, util::Expr};
use halo2_proofs::{arithmetic::FieldExt, circuit::Value, plonk::Expression};

use crate::{
    evm_circuit::param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_U64, N_BYTES_WORD},
    util::Challenges,
};

mod common;
mod eip155;
mod eip1559;
mod eip2930;
mod l1_msg;
mod pre_eip155;

#[derive(Clone, Copy, Debug)]
pub enum Tag {
    BeginList = 0,
    EndList,
    BeginVector,
    EndVector,
    Nonce,
    GasPrice,
    Gas,
    To,
    Value,
    Data,
    SigV,
    SigR,
    SigS,
    ChainId,
    AccessListAddress,
    AccessListStorageKey,
    MaxPriorityFeePerGas,
    MaxFeePerGas,
}

impl Tag {
    pub fn is_list(&self) -> bool {
        match &self {
            Self::BeginList | Self::BeginVector | Self::EndList | Self::EndVector => true,
            _ => false,
        }
    }

    pub fn max_len(&self) -> usize {
        match &self {
            Self::EndList | Self::EndVector => 0,
            Self::BeginList | Self::BeginVector | Self::Nonce | Self::Gas | Self::SigV => {
                N_BYTES_U64
            }
            Self::To | Self::AccessListAddress => N_BYTES_ACCOUNT_ADDRESS,
            Self::GasPrice
            | Self::Value
            | Self::SigR
            | Self::SigS
            | Self::ChainId
            | Self::AccessListStorageKey
            | Self::MaxPriorityFeePerGas
            | Self::MaxFeePerGas => N_BYTES_WORD,
            Self::Data => 2usize.pow(24),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum RlpTag {
    Tag(Tag),
    Len,
    Rlp,
}

impl RlpTag {
    pub fn is_output(&self) -> bool {
        match &self {
            Self::Rlp => true,
            _ => false,
        }
    }
}

impl From<RlpTag> for u64 {
    fn from(value: RlpTag) -> Self {
        match value {
            RlpTag::Tag(tag) => tag as u64,
            RlpTag::Len => 123,
            RlpTag::Rlp => 124,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Format {
    TxSignEip155 = 0,
    TxHashEip155,
    TxSignPreEip155,
    TxHashPreEip155,
    L1MsgHash,
}

#[derive(Clone, Copy, Debug)]
pub enum State {
    DecodeTagStart = 0,
    Bytes,
    LongBytes,
    LongList,
    End,
}

impl_expr!(Tag);
impl_expr!(Format);
impl_expr!(State);
impl<F: FieldExt> Expr<F> for RlpTag {
    fn expr(&self) -> Expression<F> {
        match self {
            Self::Tag(tag) => tag.expr(),
            rlp_tag => Expression::Constant(F::from(u64::from(*rlp_tag))),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DataTable {
    pub tx_id: u64,
    pub format: Format,
    pub byte_idx: usize,
    pub byte_rev_idx: usize,
    pub byte_value: u8,
}

#[derive(Clone, Copy, Debug)]
pub struct RlpTable<F> {
    pub rlp_tag: RlpTag,
    pub tag_value_acc: F,
    pub is_output: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct StateMachine {
    pub state: State,
    pub tag: Tag,
    pub tag_next: Tag,
    pub tag_idx: usize,
    pub tag_length: usize,
    pub depth: usize,
}

/// Represents the witness in a single row of the RLP circuit.
#[derive(Clone, Debug)]
pub struct RlpFsmWitnessRow<F> {
    data_table: DataTable,
    rlp_table: RlpTable<F>,
    state_machine: StateMachine,
}

/// The RlpFsmWitnessGen trait is implemented by data types who's RLP encoding can
/// be verified by the RLP-encoding circuit.
pub trait RlpFsmWitnessGen<F: FieldExt>: Encodable + Sized {
    /// Generate witness to the RLP-encoding verifier circuit, as a vector of
    /// RlpFsmWitnessRow.
    fn gen_witness(&self, challenges: &Challenges<Value<F>>) -> Vec<RlpFsmWitnessRow<Value<F>>>;
}
