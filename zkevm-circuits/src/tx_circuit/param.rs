//! Parameters for ECDSA chip

use halo2_ecc::fields::FpStrategy;

// Hard coded parameters.
// FIXME: allow for a configurable param.
pub(crate) const MAX_NUM_SIG: usize = 100;
// Each ecdsa signature requires 534042 cells
// We set CELLS_PER_SIG = 535000 to allows for a few buffer
pub(crate) const CELLS_PER_SIG: usize = 535000;
// Total number of rows allocated for ecdsa chip
pub(crate) const TOTAL_NUM_ROWS: usize = 20;

#[derive(Clone, Copy, Debug)]
pub(crate) struct SignVerifyCircuitParams {
    pub(crate) strategy: FpStrategy,
    pub(crate) degree: u32,
    pub(crate) num_advice: usize,
    pub(crate) num_lookup_advice: usize,
    pub(crate) num_fixed: usize,
    pub(crate) lookup_bits: usize,
    pub(crate) limb_bits: usize,
    pub(crate) num_limbs: usize,
}

impl SignVerifyCircuitParams {
    /// TODO: read parameters from config
    pub(crate) fn new() -> Self {
        SignVerifyCircuitParams {
            strategy: FpStrategy::Simple,
            degree: 20,
            num_advice: 34,
            num_lookup_advice: 17,
            num_fixed: 1,
            lookup_bits: 13,
            limb_bits: 88,
            num_limbs: 3,
        }
    }
}
