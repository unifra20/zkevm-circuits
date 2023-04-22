//! precompile helpers

use eth_types::Address;
use revm_precompile::{Precompile, Precompiles};

/// addresses and configs for scroll's l2 precompile
pub mod l2_address {
    use super::*;
    use eth_types::U256;
    use once_cell::sync::Lazy;
    use std::str::FromStr;

    /// address of L2MessageQueue predeploy
    pub static MESSAGE_QUEUE: Lazy<Address> =
        Lazy::new(|| Address::from_str("0x5300000000000000000000000000000000000000").unwrap());
    /// the slot of withdraw root in L2MessageQueue
    pub static WITHDRAW_TRIE_ROOT_SLOT: Lazy<U256> = Lazy::new(U256::zero);
}

/// Check if address is a precompiled or not.
pub fn is_precompiled(address: &Address) -> bool {
    Precompiles::latest()
        .get(address.as_fixed_bytes())
        .is_some()
}

pub(crate) fn execute_precompiled(address: &Address, input: &[u8], gas: u64) -> (Vec<u8>, u64) {
    let Some(Precompile::Standard(precompile_fn)) = Precompiles::latest()
        .get(address.as_fixed_bytes())  else {
        panic!("calling non-exist precompiled contract address")
    };

    match precompile_fn(input, gas) {
        Ok((gas_cost, return_value)) => (return_value, gas_cost),
        Err(_) => (vec![], gas),
    }
}
