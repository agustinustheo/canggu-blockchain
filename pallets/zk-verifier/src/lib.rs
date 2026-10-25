//! # ZK verifier pallet
//!
//! On-chain verification of Groth16 proofs over BLS12-381, the "verifier" half of the
//! whitepaper's prover/verifier split:
//!
//! * Provers (GPU-equipped or not) generate proofs **off-chain**: this is the expensive, `O(n log
//!   n)` part and the natural home for GPU acceleration (MSM and NTT kernels).
//! * The chain verifies with a constant number of pairings, independent of circuit size, via the
//!   native `canggu_crypto::groth16_bls12_381_verify` host function.
//!
//! The pallet is circuit-agnostic: anyone can register a verifying key, and anyone can submit a
//! proof against it. A verified statement `(vk, public_inputs)` is recorded so other pallets or
//! off-chain consumers can rely on it. Failed verifications still pay their full fee.
//!
//! **Two proof systems.** Groth16/BLS12-381 proofs are 192 bytes but rest on pairings, which a
//! quantum computer breaks. SP1 *compressed* proofs ([`Pallet::submit_sp1_proof`]) are
//! hash-based STARKs: plausibly post-quantum and with no trusted setup, at ~1.27 MB per proof and
//! ~26 ms to verify. An SP1 statement is `(program vkey hash, public values)`; any program built
//! for SP1 v6.10 can be proven, e.g. `sp1/programs/payroll`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

#[cfg(test)]
mod tests;

use frame_support::weights::Weight;
use sp_runtime::traits::{BlakeTwo256, Hash};

/// Identifier of a registered verifying key: `blake2_256(vk_bytes)`.
pub type VkId = <BlakeTwo256 as Hash>::Output;

/// Upper bound on an encoded proof. A compressed BLS12-381 Groth16 proof is exactly 192 bytes.
pub const MAX_PROOF_LEN: u32 = 256;

/// Upper bound on the public values of an SP1 statement.
pub const MAX_SP1_PUBLIC_VALUES: u32 = 1024;

/// Identifier of an SP1 statement: `blake2_256("sp1/v6" ++ vkey_hash ++ public_values)`.
pub fn sp1_statement_id(vkey_hash: &[u8; 32], public_values: &[u8]) -> VkId {
	let mut data = b"sp1/v6".to_vec();
	data.extend_from_slice(vkey_hash);
	data.extend_from_slice(public_values);
	BlakeTwo256::hash(&data)
}

/// Identifier of a statement: `blake2_256(vk_id ++ public_inputs)`.
pub fn statement_id(vk: &VkId, public_inputs: &[[u8; 32]]) -> VkId {
	let mut data = vk.as_bytes().to_vec();
	public_inputs.iter().for_each(|input| data.extend_from_slice(input));
	BlakeTwo256::hash(&data)
}

/// Conservative, hand-set weights; replace with benchmarked values before any production use.
pub mod weights {
	use super::Weight;

	/// Native Groth16 verification incl. VK decoding with subgroup checks (~2 ms on an M4 Pro,
	/// charged at 4x headroom).
	pub const VERIFY_BASE: Weight = Weight::from_parts(8_000_000_000, 0);
	/// Per public input: one scalar multiplication in G1.
	pub const VERIFY_PER_INPUT: Weight = Weight::from_parts(200_000_000, 0);
	/// SP1 compressed-proof verification: 25.5 ms measured on an M4 Pro, charged at ~2.4x.
	pub const SP1_VERIFY: Weight = Weight::from_parts(60_000_000_000, 0);
	/// Hashing the proof bytes into the call's length fee is separate; this covers decoding.
	pub const SP1_PER_KIB: Weight = Weight::from_parts(2_000_000, 1024);
	/// Hashing and storing the key, per byte.
	pub const REGISTER_PER_BYTE: Weight = Weight::from_parts(5_000, 1);
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use alloc::vec::Vec;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// Maximum encoded size of a verifying key.
		#[pallet::constant]
		type MaxVerifyingKeyLen: Get<u32>;
		/// Maximum number of public inputs per proof.
		#[pallet::constant]
		type MaxPublicInputs: Get<u32>;
		/// Maximum size of an SP1 compressed proof (1,272,546 bytes for SP1 v6.10).
		#[pallet::constant]
		type MaxSp1ProofLen: Get<u32>;
	}

	/// Registered verifying keys (arkworks compressed encoding).
	#[pallet::storage]
	pub type VerifyingKeys<T: Config> =
		StorageMap<_, Identity, VkId, BoundedVec<u8, T::MaxVerifyingKeyLen>>;

	/// Statements that have been proven, and the block in which that happened.
	#[pallet::storage]
	pub type VerifiedStatements<T: Config> = StorageMap<_, Identity, VkId, BlockNumberFor<T>>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		VerifyingKeyRegistered {
			vk: VkId,
			who: T::AccountId,
		},
		ProofVerified {
			vk: VkId,
			statement: VkId,
			who: T::AccountId,
		},
		/// A post-quantum SP1 proof verified for `program` with these public values.
		Sp1ProofVerified {
			program: [u8; 32],
			statement: VkId,
			public_values: Vec<u8>,
			who: T::AccountId,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// This verifying key is already registered.
		VerifyingKeyExists,
		/// No verifying key with this id.
		UnknownVerifyingKey,
		/// The proof does not verify for these public inputs.
		InvalidProof,
		/// This statement has already been proven.
		AlreadyVerified,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Register a Groth16/BLS12-381 verifying key (arkworks compressed encoding).
		#[pallet::call_index(0)]
		#[pallet::weight(
			weights::REGISTER_PER_BYTE.saturating_mul(vk.len() as u64)
				.saturating_add(T::DbWeight::get().reads_writes(1, 1))
		)]
		pub fn register_verifying_key(
			origin: OriginFor<T>,
			vk: BoundedVec<u8, T::MaxVerifyingKeyLen>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let id = BlakeTwo256::hash(&vk);
			ensure!(!VerifyingKeys::<T>::contains_key(id), Error::<T>::VerifyingKeyExists);
			VerifyingKeys::<T>::insert(id, vk);
			Self::deposit_event(Event::VerifyingKeyRegistered { vk: id, who });
			Ok(())
		}

		/// Verify `proof` for `public_inputs` (32-byte little-endian scalars) under key `vk`.
		#[pallet::call_index(1)]
		#[pallet::weight(
			weights::VERIFY_BASE
				.saturating_add(weights::VERIFY_PER_INPUT.saturating_mul(public_inputs.len() as u64))
				.saturating_add(T::DbWeight::get().reads_writes(2, 1))
		)]
		pub fn submit_proof(
			origin: OriginFor<T>,
			vk: VkId,
			public_inputs: BoundedVec<[u8; 32], T::MaxPublicInputs>,
			proof: BoundedVec<u8, ConstU32<MAX_PROOF_LEN>>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let statement = statement_id(&vk, &public_inputs);
			ensure!(!VerifiedStatements::<T>::contains_key(statement), Error::<T>::AlreadyVerified);
			let key = VerifyingKeys::<T>::get(vk).ok_or(Error::<T>::UnknownVerifyingKey)?;
			let inputs: Vec<u8> = public_inputs.iter().flatten().copied().collect();

			ensure!(
				canggu_primitives::canggu_crypto::groth16_bls12_381_verify(&key, &inputs, &proof),
				Error::<T>::InvalidProof
			);

			VerifiedStatements::<T>::insert(statement, frame_system::Pallet::<T>::block_number());
			Self::deposit_event(Event::ProofVerified { vk, statement, who });
			Ok(())
		}

		/// Verify a post-quantum SP1 compressed proof that program `program` (its vkey hash)
		/// committed `public_values`.
		#[pallet::call_index(2)]
		#[pallet::weight(
			weights::SP1_VERIFY
				.saturating_add(weights::SP1_PER_KIB.saturating_mul(proof.len() as u64 / 1024))
				.saturating_add(T::DbWeight::get().reads_writes(1, 1))
		)]
		pub fn submit_sp1_proof(
			origin: OriginFor<T>,
			program: [u8; 32],
			public_values: BoundedVec<u8, ConstU32<MAX_SP1_PUBLIC_VALUES>>,
			proof: BoundedVec<u8, T::MaxSp1ProofLen>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let statement = sp1_statement_id(&program, &public_values);
			ensure!(!VerifiedStatements::<T>::contains_key(statement), Error::<T>::AlreadyVerified);
			ensure!(
				canggu_primitives::canggu_crypto::sp1_v6_verify_compressed(
					&proof,
					&public_values,
					&program
				),
				Error::<T>::InvalidProof
			);
			VerifiedStatements::<T>::insert(statement, frame_system::Pallet::<T>::block_number());
			Self::deposit_event(Event::Sp1ProofVerified {
				program,
				statement,
				public_values: public_values.into_inner(),
				who,
			});
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		/// Whether `(vk, public_inputs)` has been proven on-chain.
		pub fn is_verified(vk: &VkId, public_inputs: &[[u8; 32]]) -> bool {
			VerifiedStatements::<T>::contains_key(statement_id(vk, public_inputs))
		}
	}
}
