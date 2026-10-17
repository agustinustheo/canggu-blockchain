//! # Post-quantum intents pallet
//!
//! Users sign *transfer intents* off-chain with their ML-DSA-65 key; a relayer bundles hundreds of
//! them into one extrinsic and pays its fee. The runtime then verifies **the whole batch with one
//! host call**, `canggu_crypto::ml_dsa_65_batch_verify`, instead of one verification per
//! transaction.
//!
//! That single call is the closest a Polkadot SDK runtime can get to a GPU: the runtime stays
//! deterministic Wasm, while the node is free to run the batch on all CPU cores or on a GPU (see
//! `canggu-node --crypto-backend`), provided every backend returns the same verdicts.
//!
//! Each intent is executed independently: a bad signature, a stale nonce or a failing transfer
//! rejects that intent (with an event) without affecting the rest of the batch.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

#[cfg(test)]
mod tests;

use canggu_primitives::{MlDsa65Public, MlDsa65Signature};
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// Domain separator prepended to every signed intent.
pub const INTENT_DOMAIN: &[u8] = b"canggu/intent/v1";

/// "Pay `amount` to `to`; this is my intent number `nonce`."
#[derive(
	Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct Intent<AccountId, Balance> {
	pub to: AccountId,
	pub amount: Balance,
	pub nonce: u32,
}

/// An intent with the ML-DSA-65 key and signature of its author.
#[derive(
	Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct SignedIntent<AccountId, Balance> {
	pub public: MlDsa65Public,
	pub signature: MlDsa65Signature,
	pub intent: Intent<AccountId, Balance>,
}

/// The bytes an intent's author signs: `(INTENT_DOMAIN, genesis_hash, intent)`, SCALE encoded.
///
/// Binding the genesis hash prevents replay on other chains; the nonce prevents replay here.
pub fn signing_payload<Hash: Encode, AccountId: Encode, Balance: Encode>(
	genesis: &Hash,
	intent: &Intent<AccountId, Balance>,
) -> alloc::vec::Vec<u8> {
	(INTENT_DOMAIN, genesis, intent).encode()
}

/// Why an intent in a batch was not executed.
#[derive(
	Clone,
	Copy,
	PartialEq,
	Eq,
	Debug,
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo,
)]
pub enum RejectReason {
	BadSignature,
	BadNonce,
	TransferFailed,
}

/// Conservative, hand-set weights; replace with benchmarked values before any production use.
pub mod weights {
	use frame_support::weights::Weight;

	pub const BASE: Weight = Weight::from_parts(20_000_000, 0);
	/// Single-core ML-DSA-65 verification (~61 µs) plus a transfer, with headroom. Charged at the
	/// CPU price: an accelerated node is faster, but weights must hold for every validator.
	pub const PER_INTENT: Weight = Weight::from_parts(150_000_000, 0);
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use alloc::vec::Vec;
	use frame_support::{
		pallet_prelude::*,
		traits::{
			fungible::{Inspect, Mutate},
			tokens::Preservation,
		},
	};
	use frame_system::pallet_prelude::*;
	use sp_runtime::{traits::Zero, AccountId32};

	pub type BalanceOf<T> =
		<<T as Config>::Currency as Inspect<<T as frame_system::Config>::AccountId>>::Balance;
	pub type IntentOf<T> = Intent<<T as frame_system::Config>::AccountId, BalanceOf<T>>;
	pub type SignedIntentOf<T> = SignedIntent<<T as frame_system::Config>::AccountId, BalanceOf<T>>;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config<AccountId = AccountId32> {
		type Currency: Mutate<Self::AccountId>;
		/// Maximum number of intents in one batch.
		#[pallet::constant]
		type MaxIntents: Get<u32>;
	}

	/// Next expected intent nonce per account (independent of the transaction nonce).
	#[pallet::storage]
	pub type Nonces<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, u32, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A batch was processed: `executed + rejected` intents in total.
		BatchExecuted { relayer: T::AccountId, executed: u32, rejected: u32 },
		/// The intent at `index` in the batch was skipped.
		IntentRejected { index: u32, reason: RejectReason },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The batch is empty.
		NoIntents,
		/// The host returned the wrong number of verdicts (a broken node backend).
		VerdictCountMismatch,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Verify every intent's signature in one batch, then execute the valid ones.
		#[pallet::call_index(0)]
		#[pallet::weight({
			let n = intents.len() as u64;
			weights::BASE
				.saturating_add(weights::PER_INTENT.saturating_mul(n))
				.saturating_add(T::DbWeight::get().reads_writes(3 * n, 3 * n))
		})]
		pub fn submit_intents(
			origin: OriginFor<T>,
			intents: BoundedVec<SignedIntentOf<T>, T::MaxIntents>,
		) -> DispatchResult {
			let relayer = ensure_signed(origin)?;
			ensure!(!intents.is_empty(), Error::<T>::NoIntents);

			let genesis = frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero());
			let jobs: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = intents
				.iter()
				.map(|signed| {
					(
						signed.public.0.to_vec(),
						signing_payload(&genesis, &signed.intent),
						signed.signature.0.to_vec(),
					)
				})
				.collect();

			// One host call for the whole batch: this is where a GPU can take over.
			let verdicts = canggu_primitives::canggu_crypto::ml_dsa_65_batch_verify(jobs);
			ensure!(verdicts.len() == intents.len(), Error::<T>::VerdictCountMismatch);

			let (mut executed, mut rejected) = (0u32, 0u32);
			for (index, (signed, valid)) in intents.into_iter().zip(verdicts).enumerate() {
				match Self::execute(signed, valid) {
					Ok(()) => executed += 1,
					Err(reason) => {
						rejected += 1;
						Self::deposit_event(Event::IntentRejected { index: index as u32, reason });
					},
				}
			}
			Self::deposit_event(Event::BatchExecuted { relayer, executed, rejected });
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		fn execute(signed: SignedIntentOf<T>, valid: bool) -> Result<(), RejectReason> {
			if !valid {
				return Err(RejectReason::BadSignature);
			}
			let from = signed.public.to_account_id();
			let Intent { to, amount, nonce } = signed.intent;
			if nonce != Nonces::<T>::get(&from) {
				return Err(RejectReason::BadNonce);
			}
			frame_support::storage::with_storage_layer(|| {
				T::Currency::transfer(&from, &to, amount, Preservation::Preserve)?;
				Nonces::<T>::insert(&from, nonce + 1);
				Ok::<_, DispatchError>(())
			})
			.map_err(|_| RejectReason::TransferFailed)
		}
	}
}
