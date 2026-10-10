//! # Canggu DAG ordering
//!
//! The whitepaper replaces a FIFO mempool with a DAG in which each transaction names the
//! transactions it depends on, so a block producer cannot reorder a transaction ahead of its
//! parents. Substrate's transaction pool is *already* a dependency graph: every transaction
//! `provides` and `requires` opaque tags, and the pool only releases a transaction to the block
//! builder once all of its `requires` are satisfied (Kahn's algorithm over the ready set).
//! `frame_system::CheckNonce` makes each signed transaction provide the tag `(who, nonce)`.
//!
//! This crate adds two transaction extensions on top of that:
//!
//! * [`CheckDagParents`]: a transaction may list up to [`MAX_PARENTS`] parent transactions, by
//!   `(account, nonce)`, from *any* account. They become `requires` tags, so the pool builds the
//!   cross-account DAG. The runtime re-checks the edges when the block is executed (`prepare`), so
//!   a producer that puts a child before its parent produces an *invalid block*: ordering is
//!   enforced by consensus, not by validator goodwill.
//! * [`ChargeTransactionPaymentNoTip`]: the standard fee extension with tips forbidden. Tips are
//!   how Substrate prioritises transactions, i.e. they are an on-chain priority-gas-auction, the
//!   main ordering lever MEV searchers pay for. Without them every transaction of the same class
//!   competes only on size/weight, never on bribes.
//!
//! What this does **not** do: it does not stop a producer from front-running a transaction that
//! does not declare the relevant dependency, nor from censoring it. See the whitepaper section on
//! limitations; the planned fix is an encrypted (threshold-decrypted) mempool.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode};
use frame_support::{
	dispatch::{DispatchInfo, PostDispatchInfo},
	pallet_prelude::TransactionSource,
	traits::Get,
	weights::Weight,
	BoundedVec, CloneNoBound, EqNoBound, PartialEqNoBound,
};
use scale_info::TypeInfo;
use sp_runtime::{
	traits::{
		AsSystemOriginSigner, DispatchInfoOf, Dispatchable, Implication, PostDispatchInfoOf,
		TransactionExtension, ValidateResult, Zero,
	},
	transaction_validity::{InvalidTransaction, TransactionValidityError, ValidTransaction},
	DispatchResult,
};

#[cfg(test)]
mod tests;

/// Maximum number of parents a single transaction may declare.
pub const MAX_PARENTS: u32 = 8;

/// A reference to another transaction: the signer and the nonce it was sent with.
pub type TxRef<T> = (<T as frame_system::Config>::AccountId, <T as frame_system::Config>::Nonce);

/// Declares the parents of a transaction in the mempool DAG. See the crate docs.
#[derive(
	Encode, Decode, DecodeWithMemTracking, CloneNoBound, EqNoBound, PartialEqNoBound, TypeInfo,
)]
#[scale_info(skip_type_params(T))]
pub struct CheckDagParents<T: frame_system::Config>(
	pub BoundedVec<TxRef<T>, frame_support::traits::ConstU32<MAX_PARENTS>>,
);

impl<T: frame_system::Config> CheckDagParents<T> {
	/// No dependencies (the common case).
	pub fn none() -> Self {
		Self(BoundedVec::new())
	}

	/// Depend on the given transactions. Fails if more than [`MAX_PARENTS`] are given.
	pub fn on(parents: Vec<TxRef<T>>) -> Result<Self, Vec<TxRef<T>>> {
		parents.try_into().map(Self)
	}

	/// A parent counts as executed once its sender's on-chain nonce has moved past it.
	pub fn is_executed((who, nonce): &TxRef<T>) -> bool {
		frame_system::Pallet::<T>::account_nonce(who) > *nonce
	}

	/// Parents that are still pending, encoded exactly like `CheckNonce`'s `provides` tag.
	fn pending_tags(&self) -> Vec<Vec<u8>> {
		self.0.iter().filter(|p| !Self::is_executed(p)).map(|p| p.encode()).collect()
	}
}

impl<T: frame_system::Config> core::fmt::Debug for CheckDagParents<T> {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "CheckDagParents({} parents)", self.0.len())
	}
}

impl<T: frame_system::Config> TransactionExtension<T::RuntimeCall> for CheckDagParents<T>
where
	T::RuntimeCall: Dispatchable<Info = DispatchInfo>,
	<T::RuntimeCall as Dispatchable>::RuntimeOrigin: AsSystemOriginSigner<T::AccountId> + Clone,
{
	const IDENTIFIER: &'static str = "CheckDagParents";
	type Implicit = ();
	type Val = ();
	type Pre = ();

	fn weight(&self, _: &T::RuntimeCall) -> Weight {
		// One `System::Account` read per declared parent.
		T::DbWeight::get().reads(self.0.len() as u64)
	}

	fn validate(
		&self,
		origin: <T::RuntimeCall as Dispatchable>::RuntimeOrigin,
		_call: &T::RuntimeCall,
		_info: &DispatchInfoOf<T::RuntimeCall>,
		_len: usize,
		_self_implicit: Self::Implicit,
		_inherited_implication: &impl Encode,
		_source: TransactionSource,
	) -> ValidateResult<Self::Val, T::RuntimeCall> {
		if self.0.is_empty() {
			return Ok((ValidTransaction::default(), (), origin));
		}
		if origin.as_system_origin_signer().is_none() {
			// Only signed transactions take part in the DAG.
			return Err(InvalidTransaction::BadSigner.into());
		}
		// Pending parents become pool dependencies. Already executed ones are simply satisfied.
		let validity = ValidTransaction { requires: self.pending_tags(), ..Default::default() };
		Ok((validity, (), origin))
	}

	fn prepare(
		self,
		_val: Self::Val,
		_origin: &<T::RuntimeCall as Dispatchable>::RuntimeOrigin,
		_call: &T::RuntimeCall,
		_info: &DispatchInfoOf<T::RuntimeCall>,
		_len: usize,
	) -> Result<Self::Pre, TransactionValidityError> {
		// Consensus-level enforcement: executing a child before its parents is invalid. In the
		// block builder this just postpones the transaction; in block import it rejects the block.
		if self.0.iter().all(Self::is_executed) {
			Ok(())
		} else {
			Err(InvalidTransaction::Future.into())
		}
	}
}

/// `pallet_transaction_payment::ChargeTransactionPayment` with tips disabled.
///
/// The SCALE encoding and the identifier are unchanged (a compact tip), so existing wallets keep
/// working as long as they send a zero tip.
#[derive(
	Encode, Decode, DecodeWithMemTracking, CloneNoBound, EqNoBound, PartialEqNoBound, TypeInfo,
)]
#[scale_info(skip_type_params(T))]
pub struct ChargeTransactionPaymentNoTip<T: pallet_transaction_payment::Config>(
	pub pallet_transaction_payment::ChargeTransactionPayment<T>,
);

impl<T: pallet_transaction_payment::Config> ChargeTransactionPaymentNoTip<T>
where
	T::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
{
	pub fn new() -> Self {
		Self(pallet_transaction_payment::ChargeTransactionPayment::from(Zero::zero()))
	}

	fn ensure_no_tip(&self) -> Result<(), TransactionValidityError> {
		if self.0.tip().is_zero() {
			Ok(())
		} else {
			Err(InvalidTransaction::Custom(TIPS_DISABLED).into())
		}
	}
}

/// `InvalidTransaction::Custom` code returned for transactions carrying a tip.
pub const TIPS_DISABLED: u8 = 0;

impl<T: pallet_transaction_payment::Config> core::fmt::Debug for ChargeTransactionPaymentNoTip<T> {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		self.0.fmt(f)
	}
}

impl<T: pallet_transaction_payment::Config> TransactionExtension<T::RuntimeCall>
	for ChargeTransactionPaymentNoTip<T>
where
	T::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
{
	const IDENTIFIER: &'static str = "ChargeTransactionPayment";
	type Implicit = ();
	type Val = pallet_transaction_payment::Val<T>;
	type Pre = pallet_transaction_payment::Pre<T>;

	fn weight(&self, call: &T::RuntimeCall) -> Weight {
		self.0.weight(call)
	}

	fn validate(
		&self,
		origin: <T::RuntimeCall as Dispatchable>::RuntimeOrigin,
		call: &T::RuntimeCall,
		info: &DispatchInfoOf<T::RuntimeCall>,
		len: usize,
		self_implicit: Self::Implicit,
		inherited_implication: &impl Implication,
		source: TransactionSource,
	) -> ValidateResult<Self::Val, T::RuntimeCall> {
		self.ensure_no_tip()?;
		self.0
			.validate(origin, call, info, len, self_implicit, inherited_implication, source)
	}

	fn prepare(
		self,
		val: Self::Val,
		origin: &<T::RuntimeCall as Dispatchable>::RuntimeOrigin,
		call: &T::RuntimeCall,
		info: &DispatchInfoOf<T::RuntimeCall>,
		len: usize,
	) -> Result<Self::Pre, TransactionValidityError> {
		self.ensure_no_tip()?;
		self.0.prepare(val, origin, call, info, len)
	}

	fn post_dispatch_details(
		pre: Self::Pre,
		info: &DispatchInfoOf<T::RuntimeCall>,
		post_info: &PostDispatchInfoOf<T::RuntimeCall>,
		len: usize,
		result: &DispatchResult,
	) -> Result<Weight, TransactionValidityError> {
		pallet_transaction_payment::ChargeTransactionPayment::<T>::post_dispatch_details(
			pre, info, post_info, len, result,
		)
	}
}
