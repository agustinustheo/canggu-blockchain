//! # Canggu zk-SNARK demo circuit: private payroll commitment
//!
//! Statement (public inputs `[total, commitment]`):
//!
//! > "I know a `salt` and `N` salaries `a_1..a_N`, each a 64-bit unsigned integer, such that
//! > `a_1 + .. + a_N = total` and `MiMC-MP(salt, a_1, .., a_N) = commitment`."
//!
//! An employer can publish `commitment` once (e.g. at the start of a pay period) and later prove
//! to the chain that the payroll it is about to fund sums to `total`, without revealing any
//! individual salary. The on-chain verifier ([`canggu_primitives::canggu_crypto`]) checks the
//! proof with a constant number of pairings, whatever `N` is.
//!
//! The commitment uses MiMC with exponent 5 (a permutation of the BLS12-381 scalar field, since
//! `gcd(5, r - 1) = 1`) in Miyaguchi–Preneel mode. **This is demonstration code**: the parameters
//! are standard but the implementation is not audited, and Groth16 on BLS12-381 is *not*
//! post-quantum (see the whitepaper's security section).

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{AdditiveGroup, Field, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::{
	gr1cs::{
		ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
	},
	lc,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

pub use ark_bls12_381::Fr as Scalar;

/// MiMC rounds: `ceil(log_5(r)) = 110` for the 255-bit BLS12-381 scalar field.
pub const MIMC_ROUNDS: usize = 110;
/// Bit width of each private salary.
pub const AMOUNT_BITS: usize = 64;

/// Deterministic, nothing-up-my-sleeve round constants: `blake2_256("canggu/mimc5/" ++ i)`.
fn round_constants() -> Vec<Fr> {
	(0..MIMC_ROUNDS as u32)
		.map(|i| {
			let mut input = b"canggu/mimc5/".to_vec();
			input.extend_from_slice(&i.to_le_bytes());
			Fr::from_le_bytes_mod_order(&sp_crypto_hashing::blake2_256(&input))
		})
		.collect()
}

fn pow5(x: Fr) -> Fr {
	let x2 = x.square();
	x2.square() * x
}

/// MiMC-5 block cipher `E_k(x)`.
fn mimc_encrypt(constants: &[Fr], key: Fr, mut x: Fr) -> Fr {
	for c in constants {
		x = pow5(x + key + c);
	}
	x + key
}

/// Native commitment: Miyaguchi–Preneel `h' = E_h(m) + h + m`, absorbing `salt` then amounts.
pub fn commit(salt: Fr, amounts: &[u64]) -> Fr {
	let constants = round_constants();
	core::iter::once(salt)
		.chain(amounts.iter().map(|a| Fr::from(*a)))
		.fold(Fr::ZERO, |h, m| mimc_encrypt(&constants, h, m) + h + m)
}

/// A linear combination together with its concrete value.
#[derive(Clone)]
struct Num {
	lc: LinearCombination<Fr>,
	value: Fr,
}

impl Num {
	fn constant(value: Fr) -> Self {
		Self { lc: lc![(value, Variable::One)], value }
	}

	fn witness(cs: &ConstraintSystemRef<Fr>, value: Fr) -> Result<Self, SynthesisError> {
		let var = cs.new_witness_variable(|| Ok(value))?;
		Ok(Self { lc: lc![var], value })
	}

	fn add(&self, other: &Num) -> Num {
		Num { lc: self.lc.clone() + &other.lc, value: self.value + other.value }
	}

	/// `self * other`, as one new witness and one R1CS constraint.
	fn mul(&self, cs: &ConstraintSystemRef<Fr>, other: &Num) -> Result<Num, SynthesisError> {
		let out = Num::witness(cs, self.value * other.value)?;
		let (a, b, c) = (self.lc.clone(), other.lc.clone(), out.lc.clone());
		cs.enforce_r1cs_constraint(|| a, || b, || c)?;
		Ok(out)
	}

	/// Replace the linear combination by a single fresh variable (one constraint).
	///
	/// Without this, values that feed many later constraints (the running hash, each amount) would
	/// drag their whole symbolic history along, and the R1CS matrices would grow quadratically.
	fn materialize(&self, cs: &ConstraintSystemRef<Fr>) -> Result<Num, SynthesisError> {
		let var = cs.new_witness_variable(|| Ok(self.value))?;
		self.enforce_equal(cs, var)?;
		Ok(Num { lc: lc![var], value: self.value })
	}

	fn pow5(&self, cs: &ConstraintSystemRef<Fr>) -> Result<Num, SynthesisError> {
		let x2 = self.mul(cs, self)?;
		let x4 = x2.mul(cs, &x2)?;
		x4.mul(cs, self)
	}

	fn enforce_equal(
		&self,
		cs: &ConstraintSystemRef<Fr>,
		var: Variable,
	) -> Result<(), SynthesisError> {
		let a = self.lc.clone();
		cs.enforce_r1cs_constraint(|| a, || lc![Variable::One], || lc![var])
	}
}

fn mimc_encrypt_gadget(
	cs: &ConstraintSystemRef<Fr>,
	constants: &[Fr],
	key: &Num,
	x: &Num,
) -> Result<Num, SynthesisError> {
	let mut x = x.clone();
	for c in constants {
		x = x.add(key).add(&Num::constant(*c)).pow5(cs)?;
	}
	Ok(x.add(key))
}

/// The payroll circuit. The number of salaries is fixed per verifying key.
#[derive(Clone)]
pub struct PayrollCircuit {
	pub salt: Fr,
	pub amounts: Vec<u64>,
}

impl PayrollCircuit {
	/// A placeholder instance with the right shape, used for the trusted setup.
	pub fn blank(recipients: usize) -> Self {
		Self { salt: Fr::ZERO, amounts: vec![0; recipients] }
	}

	pub fn total(&self) -> Fr {
		self.amounts.iter().map(|a| Fr::from(*a)).sum()
	}

	/// Public inputs, in the order the verifier expects them.
	pub fn public_inputs(&self) -> [Fr; 2] {
		[self.total(), commit(self.salt, &self.amounts)]
	}
}

impl ConstraintSynthesizer<Fr> for PayrollCircuit {
	fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
		let [total, commitment] = self.public_inputs();
		let total_var = cs.new_input_variable(|| Ok(total))?;
		let commitment_var = cs.new_input_variable(|| Ok(commitment))?;

		let constants = round_constants();
		let salt = Num::witness(&cs, self.salt)?;
		let mut h = Num::constant(Fr::ZERO);
		h = mimc_encrypt_gadget(&cs, &constants, &h, &salt)?
			.add(&h)
			.add(&salt)
			.materialize(&cs)?;

		let mut sum = Num::constant(Fr::ZERO);
		for amount in &self.amounts {
			// Range check: amount = sum(b_j * 2^j) with every b_j boolean.
			let mut amount_num = Num::constant(Fr::ZERO);
			let mut weight = Fr::ONE;
			for j in 0..AMOUNT_BITS {
				let bit_value = Fr::from((amount >> j) & 1);
				let bit = cs.new_witness_variable(|| Ok(bit_value))?;
				// b * (1 - b) = 0
				cs.enforce_r1cs_constraint(|| lc![bit], || lc![Variable::One] - bit, || lc!())?;
				amount_num = Num {
					lc: amount_num.lc + (weight, bit),
					value: amount_num.value + weight * bit_value,
				};
				weight.double_in_place();
			}
			let amount_num = amount_num.materialize(&cs)?;
			sum = sum.add(&amount_num);
			h = mimc_encrypt_gadget(&cs, &constants, &h, &amount_num)?
				.add(&h)
				.add(&amount_num)
				.materialize(&cs)?;
		}

		sum.enforce_equal(&cs, total_var)?;
		h.enforce_equal(&cs, commitment_var)
	}
}

/// Number of R1CS constraints of the payroll circuit for `recipients` salaries.
pub fn constraint_count(recipients: usize) -> Result<usize, SynthesisError> {
	let cs = ark_relations::gr1cs::ConstraintSystem::<Fr>::new_ref();
	PayrollCircuit::blank(recipients).generate_constraints(cs.clone())?;
	Ok(cs.num_constraints())
}

/// Circuit-specific Groth16 setup. `rng` *is* the toxic waste: production deployments must use a
/// multi-party ceremony instead (see the whitepaper).
pub fn setup<R: RngCore + CryptoRng>(
	recipients: usize,
	rng: &mut R,
) -> Result<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>), SynthesisError> {
	Groth16::<Bls12_381>::circuit_specific_setup(PayrollCircuit::blank(recipients), rng)
}

pub fn prove<R: RngCore + CryptoRng>(
	pk: &ProvingKey<Bls12_381>,
	circuit: PayrollCircuit,
	rng: &mut R,
) -> Result<Proof<Bls12_381>, SynthesisError> {
	Groth16::<Bls12_381>::prove(pk, circuit, rng)
}

/// Encode any arkworks value in the compressed form the runtime expects.
pub fn encode<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
	let mut out = Vec::new();
	value.serialize_compressed(&mut out).expect("writing to a Vec cannot fail; qed");
	out
}

pub fn decode<T: CanonicalDeserialize>(bytes: &[u8]) -> Option<T> {
	T::deserialize_compressed(bytes).ok()
}

/// A scalar as the 32-byte little-endian array used in extrinsics.
pub fn scalar_bytes(value: &Fr) -> [u8; 32] {
	encode(value).try_into().expect("BLS12-381 scalars are 32 bytes; qed")
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark_relations::gr1cs::ConstraintSystem;

	fn rng() -> impl RngCore + CryptoRng {
		use ark_std::rand::SeedableRng;
		ark_std::rand::rngs::StdRng::seed_from_u64(7)
	}

	fn circuit() -> PayrollCircuit {
		PayrollCircuit { salt: Fr::from(42u64), amounts: vec![3_000, 4_500, 1_250, u64::MAX] }
	}

	#[test]
	fn circuit_is_satisfied_and_gadget_matches_native_hash() {
		let cs = ConstraintSystem::<Fr>::new_ref();
		circuit().generate_constraints(cs.clone()).unwrap();
		assert!(cs.is_satisfied().unwrap());
		println!("constraints: {}", cs.num_constraints());
	}

	#[test]
	fn proof_verifies_only_for_its_statement() {
		let c = circuit();
		let (pk, vk) = setup(4, &mut rng()).unwrap();
		let proof = prove(&pk, c.clone(), &mut rng()).unwrap();
		let [total, com] = c.public_inputs();
		let bytes = |xs: &[Fr]| xs.iter().flat_map(scalar_bytes).collect::<Vec<u8>>();
		let (vk_b, proof_b) = (encode(&vk), encode(&proof));
		assert!(canggu_primitives::zk::verify(&vk_b, &bytes(&[total, com]), &proof_b));
		assert!(!canggu_primitives::zk::verify(&vk_b, &bytes(&[total + Fr::ONE, com]), &proof_b));
		assert!(!canggu_primitives::zk::verify(&vk_b, &bytes(&[total, com + Fr::ONE]), &proof_b));
		assert!(!canggu_primitives::zk::verify(&vk_b, &bytes(&[total]), &proof_b));
		assert!(!canggu_primitives::zk::verify(&vk_b, &bytes(&[total, com]), &proof_b[1..]));
		assert_eq!(proof_b.len(), 192);
	}
}
