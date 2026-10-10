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
		VerifyingKeyRegistered { vk: VkId, who: T::AccountId },
		ProofVerified { vk: VkId, statement: VkId, who: T::AccountId },
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
	}

	impl<T: Config> Pallet<T> {
		/// Whether `(vk, public_inputs)` has been proven on-chain.
		pub fn is_verified(vk: &VkId, public_inputs: &[[u8; 32]]) -> bool {
			VerifiedStatements::<T>::contains_key(statement_id(vk, public_inputs))
		}
	}
}
