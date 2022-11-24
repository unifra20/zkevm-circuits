use crate::evm_circuit::execution::ExecutionGadget;
use crate::evm_circuit::step::ExecutionState;
use crate::evm_circuit::util::constraint_builder::{
    ConstraintBuilder, StepStateTransition, Transition,
};
use crate::evm_circuit::util::math_gadget::IsEqualGadget;
use crate::evm_circuit::util::{CachedRegion, Cell, Word};
use crate::table::CallContextFieldTag;
use crate::witness::{Block, Call, ExecStep, Transaction};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, ToLittleEndian, U256};
use gadgets::util::{select, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorDepthGadget<F> {
    opcode: Cell<F>,
    gas: Word<F>,
    address: Word<F>,
    value: Word<F>,
    args_offset: Word<F>,
    args_size: Word<F>,
    ret_offset: Word<F>,
    ret_size: Word<F>,
    is_call: IsEqualGadget<F>,
    is_callcode: IsEqualGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorDepthGadget<F> {
    const NAME: &'static str = "ErrorDepth";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorDepth;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());

        // constraint opcode types
        cb.require_in_set(
            "call-family opcode",
            opcode.expr(),
            vec![
                OpcodeId::CALL.expr(),
                OpcodeId::CALLCODE.expr(),
                OpcodeId::DELEGATECALL.expr(),
                OpcodeId::STATICCALL.expr(),
            ],
        );

        // current depth should be 1025
        cb.call_context_lookup(false.expr(), None, CallContextFieldTag::Depth, 1025.expr());

        // constraint stack pops
        let is_call = IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::CALL.expr());
        let is_callcode = IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::CALLCODE.expr());
        // is_call || is_callcode = !(!is_call && !is_callcode)
        let is_call_or_callcode =
            1.expr() - (1.expr() - is_call.expr()) * (1.expr() - is_callcode.expr());

        let gas = cb.query_word();
        let address = cb.query_word();
        let value = cb.query_word();
        let args_offset = cb.query_word();
        let args_size = cb.query_word();
        let ret_offset = cb.query_word();
        let ret_size = cb.query_word();

        cb.stack_pop(gas.expr());
        cb.stack_pop(address.expr());
        // pop the 7th element if CALL or CALLCODE, and discard
        cb.condition(is_call_or_callcode.expr(), |cb| cb.stack_pop(value.expr()));
        cb.stack_pop(args_offset.expr());
        cb.stack_pop(args_size.expr());
        cb.stack_pop(ret_offset.expr());
        cb.stack_pop(ret_size.expr());

        // the call attempt must fail immediately (sub context reverts)
        cb.stack_push(0.expr());

        let rw_delta = select::expr(is_call_or_callcode.expr(), 9.expr(), 8.expr());
        let stack_delta = select::expr(is_call_or_callcode.expr(), 6.expr(), 5.expr());

        cb.require_step_state_transition(StepStateTransition {
            call_id: Transition::Same,
            rw_counter: Transition::Delta(rw_delta),
            program_counter: Transition::Delta(1.expr()),
            stack_pointer: Transition::Delta(stack_delta),
            ..StepStateTransition::any()
        });

        Self {
            opcode,
            gas,
            address,
            value,
            args_offset,
            args_size,
            ret_offset,
            ret_size,
            is_call,
            is_callcode,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _transaction: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        self.is_call.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::CALL.as_u64()),
        )?;
        self.is_callcode.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::CALLCODE.as_u64()),
        )?;

        let mut rw_offset = 0;
        let gas = block.rws[step.rw_indices[rw_offset]].stack_value();
        rw_offset += 1;
        self.gas.assign(region, offset, Some(gas.to_le_bytes()))?;

        let address = block.rws[step.rw_indices[rw_offset]].stack_value();
        rw_offset += 1;
        self.address
            .assign(region, offset, Some(address.to_le_bytes()))?;

        let value = match opcode {
            OpcodeId::CALL | OpcodeId::CALLCODE => {
                let value = block.rws[step.rw_indices[rw_offset]].stack_value();
                rw_offset += 1;
                value
            }
            OpcodeId::STATICCALL | OpcodeId::DELEGATECALL => U256::zero(),
            _ => unreachable!(),
        };
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;

        let args_offset = block.rws[step.rw_indices[rw_offset]].stack_value();
        rw_offset += 1;
        self.args_offset
            .assign(region, offset, Some(args_offset.to_le_bytes()))?;

        let args_size = block.rws[step.rw_indices[rw_offset]].stack_value();
        rw_offset += 1;
        self.args_size
            .assign(region, offset, Some(args_size.to_le_bytes()))?;

        let ret_offset = block.rws[step.rw_indices[rw_offset]].stack_value();
        rw_offset += 1;
        self.ret_offset
            .assign(region, offset, Some(ret_offset.to_le_bytes()))?;

        let ret_size = block.rws[step.rw_indices[rw_offset]].stack_value();
        self.ret_size
            .assign(region, offset, Some(ret_size.to_le_bytes()))?;

        Ok(())
    }
}

#[cfg(test)]
mod test_depth {
    use crate::test_util::run_test_circuits_with_params;
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{bytecode, word};
    use mock::test_ctx::helpers::account_0_code_account_1_no_code;
    use mock::TestContext;

    #[test]
    fn test_depth() {
        let code = bytecode! {
            PUSH32(word!("0x7f602060006000376000600060206000600060003561ffff5a03f16001030000"))
            PUSH1(0x0)
            MSTORE
            PUSH32(word!("0x0060005260206000F30000000000000000000000000000000000000000000000"))
            PUSH1(0x20)
            MSTORE

            PUSH1(0x40)
            PUSH1(0x0)
            PUSH1(0x0)
            CREATE

            DUP1
            PUSH1(0x40)
            MSTORE

            PUSH1(0x0) // retSize
            PUSH1(0x0) // retOffset
            PUSH1(0x20) // argSize
            PUSH1(0x40) // argOffset
            PUSH1(0x0) // Value
            DUP6
            PUSH2(0xFF)
            GAS
            SUB
            CALL
        };
        assert_eq!(
            run_test_circuits_with_params(
                TestContext::<2, 1>::new(
                    None,
                    account_0_code_account_1_no_code(code),
                    |mut txs, accs| {
                        txs[0]
                            .to(accs[0].address)
                            .from(accs[1].address)
                            .gas(word!("0x2386F26FC10000"));
                    },
                    |block, _tx| block.number(0xcafeu64),
                )
                .unwrap(),
                None,
                CircuitsParams {
                    max_rws: 200000,
                    ..Default::default()
                }
            ),
            Ok(())
        );
    }
}
