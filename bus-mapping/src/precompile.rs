//! precompile helpers

use eth_types::Address;
use fp_evm::{
    Context, ExitError, ExitReason, ExitSucceed, Precompile, PrecompileFailure, PrecompileHandle,
    PrecompileOutput, Transfer,
};
use gadgets::impl_expr;
use halo2_proofs::plonk::Expression;
use pallet_evm_precompile_blake2::Blake2F;
use pallet_evm_precompile_bn128::{Bn128Add, Bn128Mul, Bn128Pairing};
use pallet_evm_precompile_modexp::Modexp;
use pallet_evm_precompile_simple::{ECRecover, Identity, Ripemd160, Sha256};

/// Addresses of the precompiled contracts.
#[derive(Copy, Clone, Debug)]
pub enum PrecompileAddress {
    /// Elliptic Curve Recovery
    ECRecover = 0x01,
    /// SHA2-256 hash function
    Sha256 = 0x02,
    /// Ripemd-160 hash function
    Ripemd160 = 0x03,
    /// Identity function
    Identity = 0x04,
    /// Modular exponentiation
    Modexp = 0x05,
    /// Point addition
    Bn128Add = 0x06,
    /// Scalar multiplication
    Bn128Mul = 0x07,
    /// Bilinear function
    Bn128Pairing = 0x08,
    /// Compression function
    Blake2F = 0x09,
}

impl From<u8> for PrecompileAddress {
    fn from(value: u8) -> Self {
        match value {
            0x01 => Self::ECRecover,
            0x02 => Self::Sha256,
            0x03 => Self::Ripemd160,
            0x04 => Self::Identity,
            0x05 => Self::Modexp,
            0x06 => Self::Bn128Add,
            0x07 => Self::Bn128Mul,
            0x08 => Self::Bn128Pairing,
            0x09 => Self::Blake2F,
            _ => panic!("calling non-exist precompiled contract address"),
        }
    }
}

impl From<PrecompileAddress> for usize {
    fn from(a: PrecompileAddress) -> Self {
        a as usize
    }
}

impl_expr!(PrecompileAddress);

/// Check if address is a precompiled or not.
pub fn is_precompiled(address: &Address) -> bool {
    address.0[0..19] == [0u8; 19] && (1..=9).contains(&address.0[19])
}

pub(crate) fn execute_precompiled(address: &Address, input: &[u8], gas: u64) -> (Vec<u8>, u64) {
    match address.as_bytes()[19].into() {
        PrecompileAddress::ECRecover => execute::<ECRecover>(input, gas),
        PrecompileAddress::Sha256 => execute::<Sha256>(input, gas),
        PrecompileAddress::Ripemd160 => execute::<Ripemd160>(input, gas),
        PrecompileAddress::Identity => execute::<Identity>(input, gas),
        PrecompileAddress::Modexp => execute::<Modexp>(input, gas),
        PrecompileAddress::Bn128Add => execute::<Bn128Add>(input, gas),
        PrecompileAddress::Bn128Mul => execute::<Bn128Mul>(input, gas),
        PrecompileAddress::Bn128Pairing => execute::<Bn128Pairing>(input, gas),
        PrecompileAddress::Blake2F => execute::<Blake2F>(input, gas),
    }
}

fn execute<T: Precompile>(input: &[u8], gas: u64) -> (Vec<u8>, u64) {
    let mut handler = Handler::new(input, gas);
    match T::execute(&mut handler) {
        Ok(PrecompileOutput {
            exit_status,
            output,
        }) => {
            assert_eq!(exit_status, ExitSucceed::Returned);
            (output, handler.gas_cost)
        }
        Err(failure) => {
            match failure {
                // invalid input, consume all gas and return empty
                PrecompileFailure::Error { .. } => (vec![], gas),
                _ => unreachable!("{:?} should not happen in precompiled contract", failure),
            }
        }
    }
}

struct Handler<'a> {
    input: &'a [u8],
    gas_cost: u64,
    available_gas: u64,
}

impl<'a> Handler<'a> {
    fn new(input: &'a [u8], gas: u64) -> Self {
        Self {
            input,
            gas_cost: 0,
            available_gas: gas,
        }
    }
}

impl<'a> PrecompileHandle for Handler<'a> {
    fn call(
        &mut self,
        _to: primitive_types_12::H160,
        _transfer: Option<Transfer>,
        _input: Vec<u8>,
        _gas_limit: Option<u64>,
        _is_static: bool,
        _context: &Context,
    ) -> (ExitReason, Vec<u8>) {
        unreachable!("we don't use this")
    }

    fn record_cost(&mut self, delta: u64) -> Result<(), ExitError> {
        self.gas_cost += delta;
        debug_assert!(
            self.gas_cost <= self.available_gas,
            "exceeded available gas"
        );
        Ok(())
    }

    fn remaining_gas(&self) -> u64 {
        self.available_gas - self.gas_cost
    }

    fn log(
        &mut self,
        _: primitive_types_12::H160,
        _: Vec<primitive_types_12::H256>,
        _: Vec<u8>,
    ) -> Result<(), ExitError> {
        unreachable!("we don't use this")
    }

    fn code_address(&self) -> primitive_types_12::H160 {
        unreachable!("we don't use this")
    }

    fn input(&self) -> &[u8] {
        self.input
    }

    fn context(&self) -> &Context {
        unreachable!("we don't use this")
    }

    fn is_static(&self) -> bool {
        unreachable!("we don't use this")
    }

    fn gas_limit(&self) -> Option<u64> {
        Some(self.available_gas)
    }
}
