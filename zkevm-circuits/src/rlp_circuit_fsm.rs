use eth_types::Field;
use halo2_proofs::plonk::Circuit;

use crate::{util::{SubCircuitConfig, SubCircuit}, witness::SignedTransaction};

#[derive(Clone, Debug)]
pub struct RlpCircuitConfig<F> {
}

impl<F: Field> RlpCircuitConfig<F> {
}

pub struct RlppCircuitConfigArgs<F: Field> {
}

impl<F: Field> SubCircuitConfig<F> for RlpCircuitConfig<F> {
}

#[derive(Clone, Debug)]
pub struct RlpCircuit<F, RLP> {
}

impl<F: Field> SubCircuit<F> for RlpCircuit<F, SignedTransaction> {
}

impl<F: Field> Circuit<F> for RlpCircuit<F, SignedTransaction> {
}

#[cfg(test)]
mod tests {
}
