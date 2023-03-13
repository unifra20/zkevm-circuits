use bus_mapping::precompile::PrecompileAddress;
use eth_types::Field;
use halo2_proofs::plonk::Expression;

use super::{constraint_builder::ConstraintBuilder, math_gadget::BinaryNumberGadget};

#[derive(Clone, Debug)]
pub struct PrecompileGadget<F> {
    address: BinaryNumberGadget<F, 4>,
}

impl<F: Field> PrecompileGadget<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>, precompile_addr: Expression<F>) -> Self {
        let address = BinaryNumberGadget::construct(cb, precompile_addr);

        cb.condition(address.value_equals(PrecompileAddress::Sha256), |cb| {
            // TODO: lookup SHA2 table.
        });

        cb.condition(address.value_equals(PrecompileAddress::Ripemd160), |cb| {
            // TODO: lookup Ripemd160 table.
        });

        cb.condition(address.value_equals(PrecompileAddress::Blake2F), |cb| {
            // TODO: lookup Blake2F table.
        });

        Self { address }
    }
}
