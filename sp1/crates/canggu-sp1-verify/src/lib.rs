//! Verification of canggu-sp1 compressed SP1 proofs (post-quantum: hash-based STARK over
//! KoalaBear with Poseidon2 Merkle commitments, no pairings or elliptic curves).
//!
//! Dependencies: `sp1-verifier` (feature `full`) and `bincode` 1.3.3, which `sp1-verifier` already
//! uses for exactly this encoding; nothing from the SP1 SDK. Inputs are untrusted bytes:
//! [`verify`] never panics on garbage (see its docs).
//!
//! On top of `sp1_verifier::compressed::SP1CompressedVerifierRaw`, this crate enforces a
//! *canonical* encoding, so that a valid proof has exactly one accepted byte string (useful if
//! the chain deduplicates, stores or hashes proofs):
//! * `bincode` ignores trailing bytes, so `proof || garbage` would otherwise verify;
//! * KoalaBear elements deserialize with `from_canonical_u32`, which wraps values `>= p` in
//!   release builds, so `x` and `x + p` would otherwise decode to the same proof.
//!
//! Both are rejected by requiring `bincode(deserialize(proof)) == proof` and every vkey word
//! `< p`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use sp1_verifier::{
	compressed::{CompressedError, SP1CompressedVerifier},
	SP1Proof,
};

// No entropy source exists (or is needed) inside a wasm runtime; fail loudly if anything asks.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
getrandom::register_custom_getrandom!(no_entropy);

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn no_entropy(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
	Err(getrandom::Error::UNSUPPORTED)
}

/// `bincode(vk.hash_koalabear())` of the `mldsa-batch` guest (`elf/mldsa-batch.elf`).
pub const MLDSA_BATCH_VKEY_HASH: &[u8] = include_bytes!("../vkeys/mldsa-batch.vkey_hash.bin");
/// `bincode(vk.hash_koalabear())` of the `payroll` guest (`elf/payroll.elf`).
pub const PAYROLL_VKEY_HASH: &[u8] = include_bytes!("../vkeys/payroll.vkey_hash.bin");

/// Length of the `mldsa-batch` public values: `n: u32 LE | keccak256(ctx) | digest`.
pub const MLDSA_BATCH_PUBLIC_VALUES_BYTES: usize = 68;
/// Length of the `payroll` public values: `n: u32 LE | total: u128 LE | commitment`.
pub const PAYROLL_PUBLIC_VALUES_BYTES: usize = 52;

/// Length of a vkey hash: 8 KoalaBear elements as little-endian `u32`.
pub const VKEY_HASH_BYTES: usize = 32;

/// The KoalaBear prime `2^31 - 2^24 + 1`.
const KOALABEAR_P: u32 = 0x7f00_0001;

/// Why a proof was rejected (for logging; consensus code should only look at the `bool`).
#[derive(Debug)]
pub enum Error {
	/// The vkey hash is not 8 canonical KoalaBear elements.
	BadVkeyHash,
	/// The proof bytes do not deserialize.
	Deserialize,
	/// The proof deserializes, but is not the canonical encoding of what it decodes to.
	NonCanonical,
	/// Not a compressed proof (core/PLONK/Groth16 proofs are not accepted).
	NotCompressed,
	/// `sp1-verifier` rejected the proof.
	Rejected(CompressedError),
}

impl core::fmt::Display for Error {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Error::BadVkeyHash => write!(f, "vkey hash is not 8 canonical KoalaBear elements"),
			Error::Deserialize => write!(f, "proof does not deserialize"),
			Error::NonCanonical => write!(f, "proof encoding is not canonical"),
			Error::NotCompressed => write!(f, "not a compressed proof"),
			Error::Rejected(e) => write!(f, "proof rejected: {e}"),
		}
	}
}

/// Building the verifier (recursion machine, vk Merkle root) is not free; do it once per process.
#[cfg(feature = "std")]
fn verifier() -> &'static SP1CompressedVerifier {
	static V: std::sync::OnceLock<SP1CompressedVerifier> = std::sync::OnceLock::new();
	V.get_or_init(SP1CompressedVerifier::new)
}

/// Verify `proof` (`bincode(SP1Proof::Compressed(..))`) of the program with vkey hash
/// `vkey_hash` (`bincode(vk.hash_koalabear())`, 32 bytes) committing exactly `public_values`.
///
/// Does not catch panics; see [`verify`].
pub fn try_verify(proof: &[u8], public_values: &[u8], vkey_hash: &[u8]) -> Result<(), Error> {
	if vkey_hash.len() != VKEY_HASH_BYTES
		|| vkey_hash
			.chunks_exact(4)
			.any(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) >= KOALABEAR_P)
	{
		return Err(Error::BadVkeyHash);
	}
	// The element type is inferred from `verify_compressed_with_public_values`.
	let vkey_hash: [_; 8] = bincode::deserialize(vkey_hash).map_err(|_| Error::BadVkeyHash)?;

	let parsed: SP1Proof = bincode::deserialize(proof).map_err(|_| Error::Deserialize)?;
	// Canonical encoding: re-encoding must reproduce the input exactly (catches trailing bytes
	// and non-reduced field elements). Costs ~1 ms for a 1.27 MB proof.
	match bincode::serialized_size(&parsed) {
		Ok(len) if len == proof.len() as u64 => {},
		_ => return Err(Error::NonCanonical),
	}
	if bincode::serialize(&parsed).map_err(|_| Error::NonCanonical)? != proof {
		return Err(Error::NonCanonical);
	}
	let SP1Proof::Compressed(compressed) = parsed else {
		return Err(Error::NotCompressed);
	};

	#[cfg(feature = "std")]
	let verifier = verifier();
	#[cfg(not(feature = "std"))]
	let verifier = &SP1CompressedVerifier::new();
	verifier
		.verify_compressed_with_public_values(&compressed, public_values, &vkey_hash)
		.map_err(Error::Rejected)
}

/// `true` iff `proof` is the canonical encoding of a valid compressed proof for `vkey_hash` and
/// `public_values`.
///
/// Never panics: with the default `std` feature, panics inside `sp1-verifier` (none are expected,
/// but the input is attacker-controlled and the verifier is large) are caught and turn into
/// `false`. Without `std` a panic would abort the caller, which is one more reason to run this
/// natively (host function) rather than inside a runtime.
pub fn verify(proof: &[u8], public_values: &[u8], vkey_hash: &[u8]) -> bool {
	#[cfg(feature = "std")]
	{
		std::panic::catch_unwind(|| try_verify(proof, public_values, vkey_hash).is_ok())
			.unwrap_or(false)
	}
	#[cfg(not(feature = "std"))]
	{
		try_verify(proof, public_values, vkey_hash).is_ok()
	}
}
