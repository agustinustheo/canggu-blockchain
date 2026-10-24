//! Building, signing, submitting and tracking Canggu transactions.

use crate::rpc::Rpc;
use anyhow::{bail, Result};
use canggu_primitives::keyring::MlDsa65Pair;
use canggu_runtime::{
	AccountId, Address, Balance, Runtime, RuntimeCall, RuntimeEvent, SignedPayload, TxExtension,
	UncheckedExtrinsic,
};
use codec::Encode;
use frame_system::{EventRecord, Phase};
use sp_core::H256;
use sp_runtime::generic::Era;
use std::time::{Duration, Instant};

/// 1 CGU = 10^12 plancks.
pub const UNIT: Balance = canggu_runtime::UNIT;

pub fn format_units(amount: Balance) -> String {
	format!("{}.{:04} CGU", amount / UNIT, (amount % UNIT) / (UNIT / 10_000))
}

/// Parse a decimal amount of CGU ("1.5") into plancks.
pub fn parse_units(amount: &str) -> Result<Balance> {
	let (whole, frac) = amount.split_once('.').unwrap_or((amount, ""));
	if frac.len() > 12 {
		bail!("at most 12 decimals");
	}
	let frac_plancks = if frac.is_empty() { 0 } else { format!("{frac:0<12}").parse::<u128>()? };
	Ok(whole.parse::<u128>()? * UNIT + frac_plancks)
}

/// A transaction that has been submitted but not yet observed in a block.
pub struct Pending {
	pub encoded: Vec<u8>,
	pub hash: H256,
	submitted_after: u32,
}

/// A transaction observed in a block.
pub struct Included {
	pub block_number: u32,
	pub index: u32,
	pub events: Vec<RuntimeEvent>,
}

impl Included {
	/// The dispatch error, if the extrinsic was included but failed.
	pub fn failure(&self) -> Option<String> {
		self.events.iter().find_map(|event| match event {
			RuntimeEvent::System(frame_system::Event::ExtrinsicFailed {
				dispatch_error, ..
			}) => Some(crate::describe_dispatch_error(dispatch_error)),
			_ => None,
		})
	}
}

pub struct Chain {
	pub rpc: Rpc,
	pub genesis: H256,
	spec_version: u32,
	tx_version: u32,
}

impl Chain {
	pub fn connect(url: &str) -> Result<Self> {
		let rpc = Rpc::new(url);
		let genesis = rpc.block_hash(0)?;
		let (spec_version, tx_version) = rpc.runtime_version()?;
		Ok(Self { rpc, genesis, spec_version, tx_version })
	}

	pub fn account(
		&self,
		who: &AccountId,
	) -> Result<frame_system::AccountInfo<u32, pallet_balances::AccountData<Balance>>> {
		let key = frame_system::Account::<Runtime>::hashed_key_for(who);
		Ok(self.rpc.storage(&key, None)?.unwrap_or_default())
	}

	pub fn free_balance(&self, who: &AccountId) -> Result<Balance> {
		Ok(self.account(who)?.data.free)
	}

	/// Build and sign an extrinsic with an ML-DSA-65 key.
	pub fn sign(
		&self,
		signer: &MlDsa65Pair,
		call: RuntimeCall,
		nonce: u32,
		parents: Vec<(AccountId, u32)>,
		tip: Balance,
	) -> Result<UncheckedExtrinsic> {
		let parents = canggu_dag_ordering::CheckDagParents::<Runtime>::on(parents)
			.map_err(|p| anyhow::anyhow!("too many parents ({})", p.len()))?;
		let extension: TxExtension = (
			frame_system::AuthorizeCall::<Runtime>::new(),
			frame_system::CheckNonZeroSender::<Runtime>::new(),
			frame_system::CheckSpecVersion::<Runtime>::new(),
			frame_system::CheckTxVersion::<Runtime>::new(),
			frame_system::CheckGenesis::<Runtime>::new(),
			frame_system::CheckEra::<Runtime>::from(Era::Immortal),
			parents,
			frame_system::CheckNonce::<Runtime>::from(nonce),
			frame_system::CheckWeight::<Runtime>::new(),
			canggu_dag_ordering::ChargeTransactionPaymentNoTip(
				pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(tip),
			),
			frame_metadata_hash_extension::CheckMetadataHash::<Runtime>::new(false),
			frame_system::WeightReclaim::<Runtime>::new(),
		);
		// Data that is signed but not transmitted (`TransactionExtension::Implicit`).
		let implicit = (
			(),
			(),
			self.spec_version,
			self.tx_version,
			self.genesis,
			self.genesis, // Immortal era: the checkpoint block is genesis.
			(),
			(),
			(),
			(),
			None,
			(),
		);
		let payload = SignedPayload::from_raw(call.clone(), extension.clone(), implicit);
		let signature = payload.using_encoded(|bytes| signer.sign(bytes));
		Ok(UncheckedExtrinsic::new_signed(
			call,
			Address::Id(signer.account_id()),
			signature,
			extension,
		))
	}

	pub fn submit(&self, xt: &UncheckedExtrinsic) -> Result<Pending> {
		let submitted_after = self.rpc.best_number()?;
		let encoded = xt.encode();
		let hash = self.rpc.submit(&encoded)?;
		Ok(Pending { encoded, hash, submitted_after })
	}

	/// Poll new blocks until `pending` shows up, then collect its events.
	pub fn wait(&self, pending: &Pending) -> Result<Included> {
		let target = format!("0x{}", hex::encode(&pending.encoded));
		let deadline = Instant::now() + Duration::from_secs(60);
		let mut next = pending.submitted_after + 1;
		while Instant::now() < deadline {
			let best = self.rpc.best_number()?;
			while next <= best {
				let hash = self.rpc.block_hash(next)?;
				let extrinsics = self.rpc.block_extrinsics(hash)?;
				if let Some(index) = extrinsics.iter().position(|x| *x == target) {
					return Ok(Included {
						block_number: next,
						index: index as u32,
						events: self.events(hash, index as u32)?,
					});
				}
				next += 1;
			}
			std::thread::sleep(Duration::from_millis(250));
		}
		bail!("transaction {:?} not included within 60s", pending.hash)
	}

	/// Block number of `pending` if it was included in a block up to `last` (inclusive).
	pub fn included_by(&self, pending: &Pending, last: u32) -> Result<Option<u32>> {
		let target = format!("0x{}", hex::encode(&pending.encoded));
		for number in pending.submitted_after + 1..=last {
			if self.rpc.block_extrinsics(self.rpc.block_hash(number)?)?.contains(&target) {
				return Ok(Some(number));
			}
		}
		Ok(None)
	}

	pub fn submit_and_wait(&self, xt: &UncheckedExtrinsic) -> Result<Included> {
		let pending = self.submit(xt)?;
		self.wait(&pending)
	}

	fn events(&self, block: H256, index: u32) -> Result<Vec<RuntimeEvent>> {
		self.events_in_phase(block, Phase::ApplyExtrinsic(index))
	}

	fn events_in_phase(&self, block: H256, phase: Phase) -> Result<Vec<RuntimeEvent>> {
		let key = frame_support::storage::storage_prefix(b"System", b"Events");
		let records: Vec<EventRecord<RuntimeEvent, H256>> =
			self.rpc.storage(&key, Some(block))?.unwrap_or_default();
		Ok(records.into_iter().filter(|r| r.phase == phase).map(|r| r.event).collect())
	}

	/// Wait for block `number` and return the events of its `on_initialize` phase, where e.g.
	/// sealed calls execute.
	pub fn initialization_events(&self, number: u32) -> Result<Vec<RuntimeEvent>> {
		let deadline = Instant::now() + Duration::from_secs(60);
		while self.rpc.best_number()? < number {
			if Instant::now() > deadline {
				bail!("block #{number} not produced within 60s");
			}
			std::thread::sleep(Duration::from_millis(250));
		}
		self.events_in_phase(self.rpc.block_hash(number)?, Phase::Initialization)
	}
}
