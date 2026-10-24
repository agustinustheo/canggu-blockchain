//! # Sealed ordering: order first, reveal later
//!
//! Front-running needs two things: seeing a transaction before it executes, and a way to get
//! ahead of it. Hiding transaction contents is not enough on its own, because whoever orders the
//! block can still order by metadata (Rand Protocol whitepaper, Proposition 14.2). Rand's
//! corrected result (Theorem 15.4) eliminates front-running under three conditions:
//!
//! 1. **order-then-reveal**: the order is fixed while contents are still hidden,
//! 2. **a canonical order**: there is exactly one valid order, and it binds the block producer,
//! 3. **uniform metadata**: what is visible before ordering does not distinguish transactions.
//!
//! Rand satisfies (1) with t-of-n threshold encryption, which today means pairing-based
//! cryptography and is not post-quantum. This pallet uses hash commitments instead:
//!
//! * **commit** (block `N`): anyone (the sender or a relayer) publishes a 32-byte commitment
//!   `blake2_256("canggu/sealed/v1", sender, call, salt)` and locks a deposit. Every commitment
//!   looks the same, and with a relayer the sender is not visible either (condition 3).
//! * **reveal** (blocks `N+1 ..= N+RevealWindow`): the sender publishes `(call, salt)`. The
//!   commitment binds the sender, so nobody else can reveal or copy it.
//! * **execute** (start of block `N+RevealWindow+1`): every revealed call of block `N` runs in the
//!   order of `blake2_256(commitment ‖ hash of block N)`. That order is fixed (condition 2): it
//!   does not depend on who included which commitment where, nor on reveal order, and it cannot be
//!   computed when committing (condition 1). A front-runner who sees a reveal can only commit in a
//!   later block, which executes after.
//!
//! What commit-reveal gives up compared to threshold encryption: a sender can decline to reveal
//! (the "free option"), which forfeits the deposit; and the leader of block `N` can try to
//! influence block `N`'s hash, which only reshuffles commitments whose contents nobody knows.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

#[cfg(test)]
mod tests;

use codec::Encode;

/// Domain separator of a commitment.
pub const COMMIT_DOMAIN: &[u8] = b"canggu/sealed/v1";

/// The commitment a sender publishes for `call` (SCALE encoded) and a random `salt`.
pub fn commitment_of<AccountId: Encode>(
	sender: &AccountId,
	encoded_call: &[u8],
	salt: &[u8; 32],
) -> [u8; 32] {
	sp_io::hashing::blake2_256(&(COMMIT_DOMAIN, sender, encoded_call, salt).encode())
}

/// The canonical position key of a commitment made in a block with hash `block_hash`.
pub fn order_key<Hash: Encode>(commitment: &[u8; 32], block_hash: &Hash) -> [u8; 32] {
	sp_io::hashing::blake2_256(&(commitment, block_hash).encode())
}

/// Conservative, hand-set weights; replace with benchmarked values before any production use.
pub mod weights {
	use frame_support::weights::Weight;

	pub const COMMIT: Weight = Weight::from_parts(30_000_000, 0);
	pub const REVEAL: Weight = Weight::from_parts(40_000_000, 0);
	/// Per commitment settled in `on_initialize` (deposit release or burn, storage cleanup).
	pub const SETTLE: Weight = Weight::from_parts(25_000_000, 0);
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use alloc::{boxed::Box, collections::BTreeSet, vec::Vec};
	use frame_support::{
		dispatch::{GetDispatchInfo, PostDispatchInfo},
		pallet_prelude::*,
		traits::{
			fungible::{Inspect, MutateHold},
			tokens::{Fortitude, Precision},
			Contains,
		},
	};
	use frame_system::pallet_prelude::*;
	use sp_runtime::traits::{Dispatchable, Saturating};

	pub type BalanceOf<T> =
		<<T as Config>::Currency as Inspect<<T as frame_system::Config>::AccountId>>::Balance;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::composite_enum]
	pub enum HoldReason {
		/// Deposit locked by a commitment until it is revealed or forfeited.
		#[codec(index = 0)]
		SealedCommitment,
	}

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeCall: Parameter
			+ Dispatchable<RuntimeOrigin = Self::RuntimeOrigin, PostInfo = PostDispatchInfo>
			+ GetDispatchInfo
			+ IsType<<Self as frame_system::Config>::RuntimeCall>;
		type RuntimeHoldReason: From<HoldReason>;
		type Currency: MutateHold<Self::AccountId, Reason = Self::RuntimeHoldReason>;
		/// Calls that may be sealed (e.g. no nested sealing, no root-only calls).
		type CallFilter: Contains<<Self as Config>::RuntimeCall>;
		/// Deposit per commitment, forfeited if the commitment is never revealed.
		#[pallet::constant]
		type CommitDeposit: Get<BalanceOf<Self>>;
		/// Number of blocks after the commit block in which a commitment can be revealed.
		#[pallet::constant]
		type RevealWindow: Get<BlockNumberFor<Self>>;
		/// Maximum number of commitments per block (bounds the work of `on_initialize`).
		#[pallet::constant]
		type MaxCommitsPerBlock: Get<u32>;
		/// Maximum encoded size of a sealed call.
		#[pallet::constant]
		type MaxCallLen: Get<u32>;
		/// Maximum dispatch weight of a sealed call.
		#[pallet::constant]
		type MaxCallWeight: Get<Weight>;
	}

	/// Commitments by commit block: who locked the deposit.
	#[pallet::storage]
	pub type Commitments<T: Config> =
		StorageDoubleMap<_, Twox64Concat, BlockNumberFor<T>, Identity, [u8; 32], T::AccountId>;

	/// Number of commitments made in a block.
	#[pallet::storage]
	pub type CommitCount<T: Config> =
		StorageMap<_, Twox64Concat, BlockNumberFor<T>, u32, ValueQuery>;

	/// Revealed calls by commit block: the sender and the encoded call.
	#[pallet::storage]
	pub type Revealed<T: Config> = StorageDoubleMap<
		_,
		Twox64Concat,
		BlockNumberFor<T>,
		Identity,
		[u8; 32],
		(T::AccountId, BoundedVec<u8, T::MaxCallLen>),
	>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		Committed {
			block: BlockNumberFor<T>,
			commitment: [u8; 32],
			depositor: T::AccountId,
		},
		Revealed {
			block: BlockNumberFor<T>,
			commitment: [u8; 32],
			sender: T::AccountId,
		},
		/// A sealed call ran at its canonical position.
		Executed {
			block: BlockNumberFor<T>,
			position: u32,
			commitment: [u8; 32],
			result: DispatchResult,
		},
		/// A commitment was never revealed; its deposit was burned.
		Forfeited {
			block: BlockNumberFor<T>,
			commitment: [u8; 32],
			depositor: T::AccountId,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		AlreadyCommitted,
		TooManyCommitments,
		/// No such commitment in that block for this sender, call and salt.
		UnknownCommitment,
		AlreadyRevealed,
		/// The reveal window of that block is not open (too early or too late).
		RevealWindowClosed,
		CallNotAllowed,
		CallTooLarge,
		CallTooHeavy,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_initialize(now: BlockNumberFor<T>) -> Weight {
			let delay = T::RevealWindow::get().saturating_add(1u32.into());
			if now <= delay {
				return Weight::zero();
			}
			Self::settle(now - delay)
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Commit to a call without revealing it. Anyone may commit on a sender's behalf.
		#[pallet::call_index(0)]
		#[pallet::weight(weights::COMMIT.saturating_add(T::DbWeight::get().reads_writes(2, 3)))]
		pub fn commit(origin: OriginFor<T>, commitment: [u8; 32]) -> DispatchResult {
			let depositor = ensure_signed(origin)?;
			let block = frame_system::Pallet::<T>::block_number();
			ensure!(
				!Commitments::<T>::contains_key(block, commitment),
				Error::<T>::AlreadyCommitted
			);
			let count = CommitCount::<T>::get(block);
			ensure!(count < T::MaxCommitsPerBlock::get(), Error::<T>::TooManyCommitments);

			T::Currency::hold(
				&HoldReason::SealedCommitment.into(),
				&depositor,
				T::CommitDeposit::get(),
			)?;
			Commitments::<T>::insert(block, commitment, &depositor);
			CommitCount::<T>::insert(block, count + 1);
			Self::deposit_event(Event::Committed { block, commitment, depositor });
			Ok(())
		}

		/// Reveal a committed call. Must come from the sender the commitment names. The sender
		/// pays for the call's weight here; it executes later, at its canonical position.
		#[pallet::call_index(1)]
		#[pallet::weight({
			let call_weight = call.get_dispatch_info().total_weight();
			weights::REVEAL
				.saturating_add(call_weight)
				.saturating_add(T::DbWeight::get().reads_writes(2, 1))
		})]
		pub fn reveal(
			origin: OriginFor<T>,
			block: BlockNumberFor<T>,
			call: Box<<T as Config>::RuntimeCall>,
			salt: [u8; 32],
		) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			let now = frame_system::Pallet::<T>::block_number();
			ensure!(
				now > block && now <= block.saturating_add(T::RevealWindow::get()),
				Error::<T>::RevealWindowClosed
			);
			ensure!(T::CallFilter::contains(&call), Error::<T>::CallNotAllowed);
			ensure!(
				call.get_dispatch_info().total_weight().all_lte(T::MaxCallWeight::get()),
				Error::<T>::CallTooHeavy
			);
			let encoded: BoundedVec<u8, T::MaxCallLen> =
				call.encode().try_into().map_err(|_| Error::<T>::CallTooLarge)?;
			let commitment = commitment_of(&sender, &encoded, &salt);
			ensure!(
				Commitments::<T>::contains_key(block, commitment),
				Error::<T>::UnknownCommitment
			);
			ensure!(!Revealed::<T>::contains_key(block, commitment), Error::<T>::AlreadyRevealed);

			Revealed::<T>::insert(block, commitment, (&sender, encoded));
			Self::deposit_event(Event::Revealed { block, commitment, sender });
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		/// Execute the revealed calls of `block` in canonical order and settle its deposits.
		pub(crate) fn settle(block: BlockNumberFor<T>) -> Weight {
			let block_hash = frame_system::Pallet::<T>::block_hash(block);
			let commitments: Vec<([u8; 32], T::AccountId)> =
				Commitments::<T>::drain_prefix(block).collect();
			CommitCount::<T>::remove(block);
			let mut weight = T::DbWeight::get().reads_writes(2, 1);

			struct Sealed<AccountId> {
				key: [u8; 32],
				commitment: [u8; 32],
				sender: AccountId,
				call: Vec<u8>,
			}
			let mut revealed: Vec<Sealed<T::AccountId>> = Revealed::<T>::drain_prefix(block)
				.map(|(commitment, (sender, call))| Sealed {
					key: order_key(&commitment, &block_hash),
					commitment,
					sender,
					call: call.into_inner(),
				})
				.collect();
			revealed.sort_by(|a, b| a.key.cmp(&b.key));
			let executed: BTreeSet<[u8; 32]> = revealed.iter().map(|r| r.commitment).collect();

			for (position, Sealed { commitment, sender, call, .. }) in
				revealed.into_iter().enumerate()
			{
				let result = match <T as Config>::RuntimeCall::decode(&mut &call[..]) {
					Ok(call) => {
						let info = call.get_dispatch_info();
						let origin = frame_system::RawOrigin::Signed(sender).into();
						let post = call.dispatch(origin);
						weight.saturating_accrue(frame_support::dispatch::extract_actual_weight(
							&post, &info,
						));
						post.map(|_| ()).map_err(|e| e.error)
					},
					// Decoding cannot fail for bytes this pallet encoded, unless a runtime
					// upgrade changed the call enum between reveal and execution.
					Err(_) => Err(DispatchError::Other("sealed call no longer decodes")),
				};
				Self::deposit_event(Event::Executed {
					block,
					position: position as u32,
					commitment,
					result,
				});
			}

			let reason = HoldReason::SealedCommitment.into();
			let deposit = T::CommitDeposit::get();
			for (commitment, depositor) in commitments {
				weight.saturating_accrue(weights::SETTLE);
				if executed.contains(&commitment) {
					let _ =
						T::Currency::release(&reason, &depositor, deposit, Precision::BestEffort);
				} else {
					let _ = T::Currency::burn_held(
						&reason,
						&depositor,
						deposit,
						Precision::BestEffort,
						Fortitude::Force,
					);
					Self::deposit_event(Event::Forfeited { block, commitment, depositor });
				}
			}
			weight
		}
	}
}
