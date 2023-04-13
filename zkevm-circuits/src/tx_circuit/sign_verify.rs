//! Circuit to verify multiple ECDSA secp256k1 signatures.
// This module uses two different types of chip configurations
// - halo2-ecc's ecdsa chip, which is used
//    - to prove the correctness of secp signatures
//    - to compute the RLC in circuit
// - halo2wrong's main gate chip: this is used for keccak lookup table
//
//
//
// Naming notes:
// - *_be: Big-Endian bytes
// - *_le: Little-Endian bytes

use crate::{
    evm_circuit::util::{not, rlc},
    table::KeccakTable,
    tx_circuit::param::{MAX_NUM_SIG, TOTAL_NUM_ROWS},
    util::{Challenges, Expr},
};
use bus_mapping::operation::Op;
use eth_types::{
    self,
    sign_types::{pk_bytes_le, pk_bytes_swap_endianness, SignData},
    Bytes, Field,
};
use halo2_base::{
    gates::{
        builder::GateThreadBuilder,
        range::{RangeConfig, RangeStrategy},
        GateChip, GateInstructions, RangeChip,
    },
    utils::modulus,
    AssignedValue, Context, QuantumCell, SKIP_FIRST_PASS,
};
use halo2_ecc::{
    bigint::CRTInteger,
    ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EcPoint, EccChip},
    fields::{
        fp::{FpChip as Halo2EccFpchip, FpConfig},
        FieldChip, FpStrategy,
    },
    secp256k1::{FpChip, FqChip},
};
use halo2_proofs::{
    circuit::{Cell, Layouter, Region, Value},
    halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine},
    plonk::{Advice, Column, ConstraintSystem, Error, FirstPhase, SecondPhase, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use keccak256::plain::Keccak;
use log::error;
use num::iter::Range;
use std::{iter, marker::PhantomData};

use super::{config::SignVerifyConfig, param::SignVerifyCircuitParams};

#[derive(Debug, Clone, Default)]
/// Inputs to the ECDSA circuits
pub struct SignVerifyCircuit<F: Field> {
    max_sigs: usize,
    sign_data: Vec<SignData>,
    _phantom: PhantomData<F>,
}

impl<F: Field> SignVerifyCircuit<F> {
    pub(crate) fn new(max_sigs: usize) -> Self {
        Self {
            max_sigs,
            sign_data: Vec::with_capacity(max_sigs),
            _phantom: PhantomData::default(),
        }
    }
    pub(crate) fn min_num_rows(num_sigs: usize) -> usize {
        assert!(num_sigs <= MAX_NUM_SIG);
        TOTAL_NUM_ROWS
    }
}

#[derive(Debug, Clone)]
/// Output of the ECDSA circuit
pub(crate) struct AssignedECDSA<F: Field, FC: FieldChip<F>> {
    pk: EcPoint<F, FC::FieldPoint>,
    /// Message being hashed before signing.
    msg: Bytes,
    msg_hash: CRTInteger<F>,
    sig_is_valid: AssignedValue<F>,
}

#[derive(Debug, Clone)]
/// Output of the Sign Verify circuit
pub(crate) struct AssignedSignatureVerify<F: Field> {
    pub(crate) address: Value<F>,
    pub(crate) msg_len: usize,
    pub(crate) msg_rlc: Value<F>,
    pub(crate) msg_hash_rlc: Value<F>,
    pub(crate) sig_is_valid: Value<F>,
}

#[derive(Debug, Clone)]
/// Temp data struct to host intermediate variables.
struct SignDataDecomposed<F: Field> {
    pk_hash_cells: Vec<QuantumCell<F>>,
    msg_hash_cells: Vec<QuantumCell<F>>,
    pk_cells: Vec<QuantumCell<F>>,
    address: AssignedValue<F>,
    is_address_zero: AssignedValue<F>,
}

#[derive(Debug, Clone)]
/// Temp data struct to host intermediate variables.
struct DeferredKeccakCheck<F: Field> {
    is_address_zero: AssignedValue<F>,
    pk_rlc: AssignedValue<F>,
    pk_hash_rlc: AssignedValue<F>,
}

impl<F: Field> SignVerifyCircuit<F> {
    // Verifies the ecdsa relationship. I.e., prove that the signature
    /// is (in)valid or not under the given public key and the message hash in
    /// the circuit. Does not enforce the signature is valid.
    ///
    /// Returns the cells for
    /// - public keys
    /// - message hashes
    /// - a boolean whether the signature is correct or not
    ///
    /// WARNING: this circuit does not enforce the returned value to be true
    /// make sure the caller checks this result!
    fn assign_ecdsas(
        &self,
        ctx: &mut Context<F>,
        params: &SignVerifyCircuitParams,
    ) -> Result<Vec<AssignedECDSA<F, FpChip<F>>>, Error> {
        log::trace!("begin ECDSA assignments");

        // assemble chips
        let range = RangeChip::<F>::default(params.lookup_bits);
        let fp_chip = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
        let fq_chip = FqChip::<F>::new(&range, params.limb_bits, params.num_limbs);
        let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);

        // assign ecdsa witnesses
        let sign_data_pad = vec![SignData::default(); self.max_sigs - self.sign_data.len()];
        let res: Vec<AssignedECDSA<F, FpChip<F>>> = self
            .sign_data
            .iter()
            .chain(sign_data_pad.iter())
            .enumerate()
            .map(|(index, sign_data)| {
                log::trace!(
                    "assigning {}-th out of {} sign data",
                    index,
                    self.sign_data.len()
                );

                let SignData {
                    signature,
                    pk,
                    msg: _,
                    msg_hash,
                } = sign_data;

                let (sig_r, sig_s) = signature;

                log::trace!("r: {:?}", sig_r);
                log::trace!("s: {:?}", sig_s);
                log::trace!("msg: {:?}", msg_hash);

                let integer_r = fq_chip.load_private(ctx, FqChip::<F>::fe_to_witness(sig_r));
                let integer_s = fq_chip.load_private(ctx, FqChip::<F>::fe_to_witness(sig_s));
                let msg_hash = fq_chip.load_private(ctx, FqChip::<F>::fe_to_witness(msg_hash));

                let pk_assigned = ecc_chip.load_private(ctx, (pk.x, pk.y));

                // returns the verification result of ecdsa signature
                //
                // WARNING: this circuit does not enforce the returned value to be true
                // make sure the caller checks this result!
                let ecdsa_is_valid = ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
                    &fp_chip,
                    ctx,
                    &pk_assigned,
                    &integer_r,
                    &integer_s,
                    &msg_hash,
                    4,
                    4,
                );
                log::trace!("ECDSA res {:?}", ecdsa_is_valid.value());

                AssignedECDSA {
                    pk: pk_assigned,
                    msg: sign_data.msg.clone(),
                    msg_hash,
                    sig_is_valid: ecdsa_is_valid,
                }
            })
            .collect();
        log::trace!("finished ECDSA assignments");
        Ok(res)
    }

    fn enable_keccak_lookup(
        &self,
        config: &SignVerifyConfig<F>,
        region: &mut Region<F>,
        offset: &mut usize,
        is_address_zero: &AssignedValue<F>,
        pk_rlc: &AssignedValue<F>,
        pk_hash_rlc: &AssignedValue<F>,
    ) -> Result<(), Error> {
        log::trace!("keccak lookup");

        // // Layout:
        // // | q_keccak |        rlc      |
        // // | -------- | --------------- |
        // // |     1    | is_address_zero |
        // // |          |    pk_rlc       |
        // // |          |    pk_hash_rlc  |
        // config.q_keccak.enable(&mut region, *offset)?;

        // // is_address_zero
        // let tmp_cell = region.assign_advice(
        //     || "is_address_zero",
        //     config.rlc_column,
        //     *offset,
        //     || Value::known(is_address_zero.value().clone()),
        // )?;
        // region.constrain_equal(is_address_zero.cell.unwrap(), tmp_cell.cell())?;

        Ok(())
    }

    /// Input the signature data,
    /// Output the cells for byte decomposition of the keys and messages
    fn sign_data_decomposition(
        &self,
        ctx: &mut Context<F>,
        params: &SignVerifyCircuitParams,
    ) -> Result<Vec<SignDataDecomposed<F>>, Error> {
        let range_chip = RangeChip::<F>::default(params.lookup_bits);
        let fq_chip = FqChip::<F>::new(&range_chip, params.limb_bits, params.num_limbs);
        let fp_chip = FpChip::<F>::new(&range_chip, params.limb_bits, params.num_limbs);
        let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);

        let zero = ctx.load_zero();
        // ================================================
        // powers of aux parameters
        // ================================================
        let powers_of_256 =
            iter::successors(Some(F::one()), |coeff| Some(F::from(256) * coeff)).take(32);
        let powers_of_256_cells = powers_of_256
            .map(|x| QuantumCell::Constant(x))
            .collect_vec();

        let sign_data_pad = vec![SignData::default(); self.max_sigs - self.sign_data.len()];
        let mut res = vec![];

        for (index, sign_data) in self
            .sign_data
            .iter()
            .chain(sign_data_pad.iter())
            .enumerate()
        {
            let padding = index >= self.sign_data.len();

            // ================================================
            // pk hash cells
            // ================================================
            let pk_le = pk_bytes_le(&sign_data.pk);
            let pk_be = pk_bytes_swap_endianness(&pk_le);
            let pk_hash = (!padding)
                .then(|| {
                    let mut keccak = Keccak::default();
                    keccak.update(&pk_be);
                    let hash: [_; 32] =
                        keccak.digest().try_into().expect("vec to array of size 32");
                    hash
                })
                .unwrap_or_default()
                .map(|byte| F::from(byte as u64));

            let pk_hash_cells = pk_hash
                .iter()
                .map(|&x| QuantumCell::Witness(x))
                .rev()
                .collect_vec();

            // address is the random linear combination of the public key
            // it is fine to use a phase 1 gate here
            let address = range_chip.gate.inner_product(
                ctx,
                powers_of_256_cells[..20].to_vec(),
                pk_hash_cells[..20].to_vec(),
            );

            let is_address_zero = range_chip.gate.is_equal(
                ctx,
                QuantumCell::Existing(address),
                QuantumCell::Existing(zero),
            );
            let is_address_zero_cell = QuantumCell::Existing(is_address_zero);

            // ================================================
            // message hash cells
            // ================================================
            let assigned_msg_hash_le = (!padding)
                .then(|| sign_data.msg_hash.to_bytes())
                .unwrap_or_default()
                .iter()
                .map(|&x| QuantumCell::Witness(F::from_u128(x as u128)))
                .collect_vec();

            // assert the assigned_msg_hash_le is the right decomposition of msg_hash
            // msg_hash is an overflowing integer with 3 limbs, of sizes 88, 88, and 80
            let assigned_msg_hash =
                fq_chip.load_private(ctx, FqChip::<F>::fe_to_witness(&sign_data.msg_hash));

            assert_crt_int_byte_repr(
                ctx,
                &assigned_msg_hash,
                &assigned_msg_hash_le,
                &powers_of_256_cells,
                &Some(&is_address_zero_cell),
            )?;

            // ================================================
            // pk cells
            // ================================================
            let pk_x_le = sign_data
                .pk
                .x
                .to_bytes()
                .iter()
                .map(|&x| QuantumCell::Witness(F::from_u128(x as u128)))
                .collect_vec();

            let pk_y_le = sign_data
                .pk
                .y
                .to_bytes()
                .iter()
                .map(|&x| QuantumCell::Witness(F::from_u128(x as u128)))
                .collect_vec();
            let pk_assigned = ecc_chip.load_private(ctx, (sign_data.pk.x, sign_data.pk.y));

            assert_crt_int_byte_repr(ctx, &pk_assigned.x, &pk_x_le, &powers_of_256_cells, &None)?;

            assert_crt_int_byte_repr(ctx, &pk_assigned.y, &pk_y_le, &powers_of_256_cells, &None)?;

            let assigned_pk_le_selected = [pk_y_le, pk_x_le].concat();

            res.push(SignDataDecomposed {
                pk_hash_cells,
                msg_hash_cells: assigned_msg_hash_le,
                pk_cells: assigned_pk_le_selected,
                address,
                is_address_zero,
            })
        }
        Ok(res)
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_sig_verify(
        &self,
        ctx: &mut Context<F>,
        assigned_ecdsas: &[AssignedECDSA<F, FpChip<F>>],
        sign_data_decomposed_vec: &[SignDataDecomposed<F>],
        challenges: &Challenges<Value<F>>,
    ) -> Result<(Vec<DeferredKeccakCheck<F>>, Vec<AssignedSignatureVerify<F>>), Error> {
        assert_eq!(assigned_ecdsas.len(), sign_data_decomposed_vec.len());
        assert_eq!(assigned_ecdsas.len(), self.max_sigs);

        let gate_chip = GateChip::default();

        // ================================================
        // step 0. powers of aux parameters
        // ================================================
        let mut evm_word = F::zero();
        challenges.evm_word().map(|x| evm_word = x);
        let mut keccak_input = F::zero();
        challenges.keccak_input().map(|x| keccak_input = x);

        let evm_challenge_powers = iter::successors(Some(F::one()), |coeff| Some(evm_word * coeff))
            .take(32)
            .map(|x| QuantumCell::Witness(x))
            .collect_vec();

        let keccak_challenge_powers =
            iter::successors(Some(F::one()), |coeff| Some(keccak_input * coeff))
                .take(64)
                .map(|x| QuantumCell::Witness(x))
                .collect_vec();

        let sign_data_pad = vec![SignData::default(); self.max_sigs - self.sign_data.len()];
        let mut deferred_keccak_check = vec![];
        let mut assigned_sig_verif = vec![];

        for (index, (assigned_ecdsa, sign_data_decomposed)) in assigned_ecdsas
            .iter()
            .zip(sign_data_decomposed_vec.iter())
            .enumerate()
        {
            // ================================================
            // step 1 random linear combination of message hash
            // ================================================
            // Ref. spec SignVerifyChip 3. Verify that the signed message in the ecdsa_chip
            // with RLC encoding corresponds to msg_hash_rlc
            let msg_hash_rlc = gate_chip.inner_product(
                ctx,
                sign_data_decomposed
                    .msg_hash_cells
                    .iter()
                    .take(32)
                    .cloned()
                    .collect_vec(),
                evm_challenge_powers.clone(),
            );

            log::trace!("halo2ecc assigned msg hash rlc: {:?}", msg_hash_rlc.value());

            // ================================================
            // step 2 random linear combination of pk
            // ================================================
            let pk_rlc = gate_chip.inner_product(
                ctx,
                sign_data_decomposed.pk_cells.clone(),
                keccak_challenge_powers.clone(),
            );
            log::trace!("pk rlc halo2ecc: {:?}", pk_rlc.value());

            // ================================================
            // step 3 random linear combination of pk_hash
            // ================================================
            let pk_hash_rlc = gate_chip.inner_product(
                ctx,
                sign_data_decomposed.pk_hash_cells.clone(),
                evm_challenge_powers.clone(),
            );

            log::trace!("pk hash rlc halo2ecc: {:?}", pk_hash_rlc.value());

            deferred_keccak_check.push(DeferredKeccakCheck {
                is_address_zero: sign_data_decomposed.is_address_zero.clone(),
                pk_rlc,
                pk_hash_rlc,
            });
            assigned_sig_verif.push(AssignedSignatureVerify {
                address: Value::known(*sign_data_decomposed.address.value()),
                msg_len: assigned_ecdsa.msg.len(),
                msg_rlc: challenges
                    .keccak_input()
                    .map(|r| rlc::value(assigned_ecdsa.msg.iter().rev(), r)),
                msg_hash_rlc: Value::known(*msg_hash_rlc.value()),
                sig_is_valid: Value::known(*assigned_ecdsa.sig_is_valid.value()),
            })
        }
        Ok((deferred_keccak_check, assigned_sig_verif))
    }

    pub(crate) fn assign(
        &self,
        config: &SignVerifyConfig<F>,
        layouter: &mut impl Layouter<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<Vec<AssignedSignatureVerify<F>>, Error> {
        let mut first_pass = SKIP_FIRST_PASS;

        // assemble chips
        let range = RangeChip::<F>::default(config.params.lookup_bits);
        let fp_chip = FpChip::<F>::new(&range, config.params.limb_bits, config.params.num_limbs);
        let fq_chip = FqChip::<F>::new(&range, config.params.limb_bits, config.params.num_limbs);
        let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);

        // let (deferred_keccak_check, assigned_sig_verifs) =

        let assigned_sig_verifs = layouter.assign_region(
            || "ecdsa chip verification",
            |region| {
                let mut builder = GateThreadBuilder::<F>::mock();
                //
                // if first_pass {
                //     first_pass = false;
                //     return Ok(())
                //     // return Ok((vec![], vec![]));
                // }

                // let mut ctx = range_config.new_context(region);

                // ================================================
                // step 1: assert the signature is valid in circuit
                // ================================================

                let assigned_ecdsas = self.assign_ecdsas(&mut builder.main(0), &config.params)?;

                // ================================================
                // step 2: decompose the keys and messages
                // ================================================
                let sign_data_decomposed_vec =
                    self.sign_data_decomposition(&mut builder.main(0), &config.params)?;

                // ================================================
                // step 3: compute RLC of keys and messages
                // ================================================
                let ( _deferred_keccak_check, assigned_sig_verifs) = self.assign_sig_verify(
                    &mut builder.main(1),
                    assigned_ecdsas.as_ref(),
                    sign_data_decomposed_vec.as_ref(),
                    challenges,
                )?;

                // // // IMPORTANT: this assigns all constants to the fixed columns
                // // // IMPORTANT: this copies cells to the lookup advice column to perform range
                // // // check lookups
                // // // This is not optional.
                // // let lookup_cells = ecdsa_chip.finalize(&mut ctx);
                // // log::info!("total number of lookup cells: {}", lookup_cells);

                // for sig_verif in assigned_sig_verifs.iter() {
                //     config.ecdsa_config.range.gate.assert_equal(
                //         &mut ctx,
                //         QuantumCell::Existing(&sig_verif.sig_is_valid.clone().into()),
                //         QuantumCell::Constant(F::one()),
                //     );
                // }
                // ctx.print_stats(&["Range"]);
                // Ok((deferred_keccak_check, assigned_sig_verifs))
                Ok(assigned_sig_verifs)
            },
        )?;

        // layouter.assign_region(
        //     || "keccak lookup",
        //     |region| {
        //         let mut ctx = RegionCtx::new(region, 0);
        //         for e in deferred_keccak_check.iter() {
        //             let [is_address_zero, pk_rlc, pk_hash_rlc] = e;
        //             self.enable_keccak_lookup(
        //                 config,
        //                 &mut ctx,
        //                 &is_address_zero,
        //                 &pk_rlc,
        //                 &pk_hash_rlc,
        //             )?;
        //         }
        //         Ok(())
        //     },
        // )?;
        // todo!()
        Ok(assigned_sig_verifs)
    }

    pub(crate) fn assert_sig_is_valid(
        &self,
        config: &SignVerifyConfig<F>,
        layouter: &mut impl Layouter<F>,
        sig_verifs: &[AssignedSignatureVerify<F>],
    ) -> Result<(), Error> {
        // let gate_chip = GateChip::default();

        layouter.assign_region(
            || "assert sigs are valid",
            |region| {
                // let mut ctx = config.ecdsa_config.new_context(region);
                // for sig_verif in sig_verifs {
                //     flex_gate_chip.assert_is_const(
                //         &mut ctx,
                //         &sig_verif.sig_is_valid.clone().into(),
                //         &F::one(),
                //     );
                // }

                Ok(())
            },
        )
    }
}

pub(crate) fn pub_key_hash_to_address<F: Field>(pk_hash: &[u8]) -> F {
    pk_hash[32 - 20..]
        .iter()
        .fold(F::zero(), |acc, b| acc * F::from(256) + F::from(*b as u64))
}

/// Assert an CRTInteger's byte representation is correct.
/// inputs
/// - crt_int with 3 limbs [88, 88, 80]
/// - byte representation of the integer
/// - a sequence of [1, 2^8, 2^16, ...]
/// - a overriding flag that sets output to 0 if set
fn assert_crt_int_byte_repr<F: Field>(
    ctx: &mut Context<F>,
    crt_int: &CRTInteger<F>,
    byte_repr: &[QuantumCell<F>],
    powers_of_256: &[QuantumCell<F>],
    overriding: &Option<&QuantumCell<F>>,
) -> Result<(), Error> {
    // length of byte representation is 32
    assert_eq!(byte_repr.len(), 32);
    // need to support decomposition of up to 88 bits
    assert!(powers_of_256.len() >= 11);

    let gate_chip = GateChip::default();

    let zero = ctx.load_zero();
    let zero_cell = ctx.load_zero();

    // apply the overriding flag
    let limb1_value = match overriding {
        Some(p) => gate_chip.select(
            ctx,
            zero_cell.clone(),
            crt_int.truncation.limbs[0],
            (*p).clone(),
        ),
        None => crt_int.truncation.limbs[0].clone(),
    };
    let limb2_value = match overriding {
        Some(p) => gate_chip.select(
            ctx,
            zero_cell.clone(),
            crt_int.truncation.limbs[1],
            (*p).clone(),
        ),
        None => crt_int.truncation.limbs[1].clone(),
    };
    let limb3_value = match overriding {
        Some(p) => gate_chip.select(ctx, zero_cell, crt_int.truncation.limbs[2], (*p).clone()),
        None => crt_int.truncation.limbs[2].clone(),
    };

    // assert the byte_repr is the right decomposition of overflow_int
    // overflow_int is an overflowing integer with 3 limbs, of sizes 88, 88, and 80
    // we reconstruct the three limbs from the bytes repr, and
    // then enforce equality with the CRT integer
    let limb1_recover = gate_chip.inner_product(
        ctx,
        byte_repr[0..11].to_vec(),
        powers_of_256[0..11].to_vec(),
    );
    let limb2_recover = gate_chip.inner_product(
        ctx,
        byte_repr[11..22].to_vec(),
        powers_of_256[0..11].to_vec(),
    );
    let limb3_recover =
        gate_chip.inner_product(ctx, byte_repr[22..].to_vec(), powers_of_256[0..10].to_vec());

    ctx.constrain_equal(&limb1_value, &limb1_recover);
    ctx.constrain_equal(&limb2_value, &limb2_recover);
    ctx.constrain_equal(&limb3_value, &limb3_recover);

    log::trace!(
        "limb 1 \ninput {:?}\nreconstructed {:?}",
        limb1_value.value(),
        limb1_recover.value()
    );
    log::trace!(
        "limb 2 \ninput {:?}\nreconstructed {:?}",
        limb2_value.value(),
        limb2_recover.value()
    );
    log::trace!(
        "limb 3 \ninput {:?}\nreconstructed {:?}",
        limb3_value.value(),
        limb3_recover.value()
    );

    Ok(())
}

#[cfg(test)]
mod sign_verify_tests {
    use super::*;

    #[cfg(not(feature = "onephase"))]
    use crate::util::Challenges;
    #[cfg(feature = "onephase")]
    use crate::util::MockChallenges as Challenges;

    use bus_mapping::circuit_input_builder::keccak_inputs_sign_verify;
    use eth_types::sign_types::sign;
    use halo2_proofs::{
        arithmetic::Field as HaloField,
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        halo2curves::{bn256::Fr, group::Curve, secp256k1},
        plonk::Circuit,
    };
    use pretty_assertions::assert_eq;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use sha3::{Digest, Keccak256};

    #[derive(Clone, Debug)]
    pub struct TestCircuitSignVerifyConfig<F: Field> {
        sign_verify: SignVerifyConfig<F>,
        challenges: Challenges,
    }

    impl<F: Field> TestCircuitSignVerifyConfig<F> {
        pub(crate) fn new(meta: &mut ConstraintSystem<F>, params: SignVerifyCircuitParams) -> Self {
            let keccak_table = KeccakTable::construct(meta);
            let challenges = Challenges::construct(meta);

            let sign_verify = SignVerifyConfig::new(meta, keccak_table);

            TestCircuitSignVerifyConfig {
                sign_verify,
                challenges,
            }
        }
    }

    impl<F: Field> Circuit<F> for SignVerifyCircuit<F> {
        type Config = TestCircuitSignVerifyConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            // todo: read from config
            let params = SignVerifyCircuitParams::new();
            TestCircuitSignVerifyConfig::new(meta, params)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenges = config.challenges.values(&layouter);
            config.sign_verify.load_range(&mut layouter)?;

            self.assign(&config.sign_verify, &mut layouter, &challenges)?;
            config.sign_verify.keccak_table.dev_load(
                &mut layouter,
                &keccak_inputs_sign_verify(&self.sign_data),
                &challenges,
            )?;
            Ok(())
        }
    }

    fn run<F: Field>(k: u32, max_verif: usize, signatures: Vec<SignData>) {
        let circuit = SignVerifyCircuit {
            sign_data: signatures,
            max_sigs: max_verif,
            _phantom: PhantomData::<F>::default(),
        };

        let prover = match MockProver::run(k, &circuit, vec![vec![]]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    // Generate a test key pair
    fn gen_key_pair(rng: impl RngCore) -> (secp256k1::Fq, Secp256k1Affine) {
        // generate a valid signature
        let generator = Secp256k1Affine::generator();
        let sk = secp256k1::Fq::random(rng);
        let pk = generator * sk;
        let pk = pk.to_affine();

        (sk, pk)
    }

    // Generate a test message hash
    fn gen_msg_hash(rng: impl RngCore) -> secp256k1::Fq {
        secp256k1::Fq::random(rng)
    }

    // Generate a test message.
    fn gen_msg(mut rng: impl RngCore) -> Vec<u8> {
        let msg_len: usize = rng.gen_range(0..128);
        let mut msg = vec![0; msg_len];
        rng.fill_bytes(&mut msg);
        msg
    }

    // Returns (r, s)
    fn sign_with_rng(
        rng: impl RngCore,
        sk: secp256k1::Fq,
        msg_hash: secp256k1::Fq,
    ) -> (secp256k1::Fq, secp256k1::Fq) {
        let randomness = secp256k1::Fq::random(rng);
        sign(randomness, sk, msg_hash)
    }

    #[test]
    fn sign_verify() {
        // Vectors using `XorShiftRng::seed_from_u64(1)`
        // sk: 0x771bd7bf6c6414b9370bb8559d46e1cedb479b1836ea3c2e59a54c343b0d0495
        // pk: (
        //   0x8e31a3586d4c8de89d4e0131223ecfefa4eb76215f68a691ae607757d6256ede,
        //   0xc76fdd462294a7eeb8ff3f0f698eb470f32085ba975801dbe446ed8e0b05400b
        // )
        // pk_hash: d90e2e9d267cbcfd94de06fa7adbe6857c2c733025c0b8938a76beeefc85d6c7
        // addr: 0x7adbe6857c2c733025c0b8938a76beeefc85d6c7
        let mut rng = XorShiftRng::seed_from_u64(1);
        const MAX_VERIF: usize = 2;
        const NUM_SIGS: usize = 2;
        let mut signatures = Vec::new();
        for _ in 0..NUM_SIGS {
            let (sk, pk) = gen_key_pair(&mut rng);
            let msg = gen_msg(&mut rng);
            let msg_hash: [u8; 32] = Keccak256::digest(&msg)
                .as_slice()
                .to_vec()
                .try_into()
                .expect("hash length isn't 32 bytes");
            let msg_hash = secp256k1::Fq::from_bytes(&msg_hash).unwrap();
            let sig = sign_with_rng(&mut rng, sk, msg_hash);
            signatures.push(SignData {
                signature: sig,
                pk,
                msg: msg.into(),
                msg_hash,
            });
        }

        let k = 19;
        run::<Fr>(k, MAX_VERIF, signatures);
    }
}
