//! Reference (CPU) Groth16 / BLS12-381 verification. Backs the `groth16_bls12_381_verify` host
//! function and is reused by the CLI prover for local self-checks.

use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;

/// Size of one encoded public input (a BLS12-381 scalar, little endian).
pub const SCALAR_LEN: usize = 32;

/// Decode concatenated 32-byte little-endian scalars, rejecting non-canonical encodings.
pub fn decode_inputs(bytes: &[u8]) -> Option<Vec<Fr>> {
	if !bytes.len().is_multiple_of(SCALAR_LEN) {
		return None;
	}
	bytes
		.chunks_exact(SCALAR_LEN)
		.map(|chunk| Fr::deserialize_compressed(chunk).ok())
		.collect()
}

/// `true` iff `proof` is a valid Groth16 proof for `public_inputs` under `vk`.
///
/// Malformed encodings, points off the curve/subgroup and input-count mismatches all yield
/// `false`; this function never panics on untrusted bytes.
pub fn verify(vk: &[u8], public_inputs: &[u8], proof: &[u8]) -> bool {
	let Ok(vk) = VerifyingKey::<Bls12_381>::deserialize_compressed(vk) else { return false };
	let Ok(proof) = Proof::<Bls12_381>::deserialize_compressed(proof) else { return false };
	let Some(inputs) = decode_inputs(public_inputs) else { return false };
	if inputs.len() + 1 != vk.gamma_abc_g1.len() {
		return false;
	}
	let pvk = ark_groth16::prepare_verifying_key(&vk);
	Groth16::<Bls12_381>::verify_proof(&pvk, &proof, &inputs).unwrap_or(false)
}
