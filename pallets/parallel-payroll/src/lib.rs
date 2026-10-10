//! # Parallel payroll pallet
//!
//! The whitepaper's flagship use case: one employer pays many employees in a single transaction.
//! It is split into the two phases the whitepaper assigns to CPU and GPU:
//!
//! 1. **Sequential phase**: validate the payer's balance *once* and debit the *total* once.
//! 2. **Data-parallel phase**: credit every recipient. The pallet enforces that recipients are
//!    distinct and do not include the payer, so every credit touches a disjoint storage key and
//!    credits commute. That is precisely the property a parallel executor needs: the credit set has
//!    no read/write conflicts, so it could be applied in any order or concurrently.
//!
//! Today the credits are applied in a loop: a Substrate runtime is single-threaded Wasm and the
//! cost of each credit is dominated by state-trie I/O, which a GPU cannot accelerate. What this
//! pallet guarantees is the *conflict-freedom contract*, so that the batch can later be executed
//! by a parallel (multi-core, or JAM-style multi-core) executor without changing semantics.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

#[cfg(test)]
mod tests;

/// Conservative, hand-set weights; replace with benchmarked values before any production use.
pub mod weights {
	use frame_support::weights::Weight;

	/// Duplicate check, total computation and the single debit.
	pub const BASE: Weight = Weight::from_parts(60_000_000, 0);
	/// One credit (excluding the account read/write, which is charged via `DbWeight`).
	pub const PER_CREDIT: Weight = Weight::from_parts(30_000_000, 0);
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use alloc::vec::Vec;
	use frame_support::{
		pallet_prelude::*,
		traits::{
			fungible::{Balanced, Credit, Inspect, Mutate},
			tokens::{Fortitude, Precision, Preservation},
			Imbalance,
		},
	};
	use frame_system::pallet_prelude::*;
	use sp_runtime::traits::{CheckedAdd, Zero};

	pub type BalanceOf<T> =
		<<T as Config>::Currency as Inspect<<T as frame_system::Config>::AccountId>>::Balance;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type Currency: Balanced<Self::AccountId> + Mutate<Self::AccountId>;
		/// Maximum number of recipients in one batch.
		#[pallet::constant]
		type MaxRecipients: Get<u32>;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		PayrollExecuted { payer: T::AccountId, recipients: u32, total: BalanceOf<T> },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The batch is empty.
		NoPayments,
		/// A recipient appears twice: the credits would conflict.
		DuplicateRecipient,
		/// The payer is also a recipient: the credit would conflict with the debit.
		PayerIsRecipient,
		/// The sum of all payments overflows the balance type.
		Overflow,
		/// A credit could not be applied (e.g. below the existential deposit of a new account).
		CreditFailed,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Pay every `(recipient, amount)` in `payments` from the caller, debiting the total once.
		#[pallet::call_index(0)]
		#[pallet::weight({
			let n = payments.len() as u64;
			weights::BASE
				.saturating_add(weights::PER_CREDIT.saturating_mul(n))
				.saturating_add(T::DbWeight::get().reads_writes(n + 1, n + 1))
		})]
		pub fn batch_pay(
			origin: OriginFor<T>,
			payments: BoundedVec<(T::AccountId, BalanceOf<T>), T::MaxRecipients>,
		) -> DispatchResult {
			let payer = ensure_signed(origin)?;
			ensure!(!payments.is_empty(), Error::<T>::NoPayments);
			Self::ensure_conflict_free(&payer, &payments)?;

			// Phase 1, sequential: one balance check and one debit for the whole batch.
			let total = payments
				.iter()
				.try_fold(BalanceOf::<T>::zero(), |acc, (_, amount)| acc.checked_add(amount))
				.ok_or(Error::<T>::Overflow)?;
			let mut credit: Credit<T::AccountId, T::Currency> = T::Currency::withdraw(
				&payer,
				total,
				Precision::Exact,
				Preservation::Preserve,
				Fortitude::Polite,
			)?;

			// Phase 2, data-parallel: disjoint, commutative credits.
			let recipients = payments.len() as u32;
			for (recipient, amount) in payments {
				let (part, rest) = credit.split(amount);
				credit = rest;
				T::Currency::resolve(&recipient, part).map_err(|_| Error::<T>::CreditFailed)?;
			}
			debug_assert!(credit.peek().is_zero(), "split exactly the withdrawn total; qed");

			Self::deposit_event(Event::PayrollExecuted { payer, recipients, total });
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		/// Distinct recipients, none of them the payer: every write touches its own account.
		pub fn ensure_conflict_free(
			payer: &T::AccountId,
			payments: &[(T::AccountId, BalanceOf<T>)],
		) -> DispatchResult {
			let mut recipients: Vec<&T::AccountId> = payments.iter().map(|(who, _)| who).collect();
			recipients.sort();
			ensure!(
				recipients.windows(2).all(|pair| pair[0] != pair[1]),
				Error::<T>::DuplicateRecipient
			);
			ensure!(recipients.binary_search(&payer).is_err(), Error::<T>::PayerIsRecipient);
			Ok(())
		}
	}
}
