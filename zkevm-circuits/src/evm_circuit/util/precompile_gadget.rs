use bus_mapping::precompile::PrecompileAddress;
use eth_types::Field;
use halo2_proofs::plonk::Expression;

use super::{constraint_builder::ConstraintBuilder, math_gadget::BinaryNumberGadget, Cell};

#[derive(Clone, Debug)]
pub struct PrecompileGadget<F> {
    address: BinaryNumberGadget<F, 4>,
    id: Cell<F>,
}

impl<F: Field> PrecompileGadget<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>, precompile_addr: Expression<F>) -> Self {
        let address = BinaryNumberGadget::construct(cb, precompile_addr);
        let id = cb.query_cell();

        cb.condition(address.value_equals(PrecompileAddress::Sha256), |cb| {
            cb.sha2_table_lookup(&id);
        });

        cb.condition(address.value_equals(PrecompileAddress::Ripemd160), |cb| {
            cb.ripemd160_table_lookup(&id);
        });

        cb.condition(address.value_equals(PrecompileAddress::Blake2F), |cb| {
            cb.blake2f_table_lookup(&id);
        });

        Self { address, id }
    }
}
