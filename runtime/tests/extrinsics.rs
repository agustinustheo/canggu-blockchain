//! End-to-end checks of the runtime's transaction pipeline, driven through `Executive` exactly as
//! block authoring/import would: ML-DSA signature verification (via the native host function),
//! DAG parent enforcement and the no-tip fee extension.

use canggu_primitives::{dev_accounts, keyring, CangguSignature};
use canggu_runtime::{
	Address, Balance, BalancesCall, Executive, Header, Runtime, RuntimeCall, SignedPayload, System,
	TxExtension, UncheckedExtrinsic, UNIT, VERSION,
};
use codec::Encode;
use sp_runtime::{
	generic::Era,
	traits::Header as _,
	transaction_validity::{InvalidTransaction, TransactionSource, TransactionValidityError},
	BuildStorage,
};

fn new_test_ext() -> sp_io::TestExternalities {
	let mut storage = frame_system::GenesisConfig::<Runtime>::default().build_storage().unwrap();
	pallet_balances::GenesisConfig::<Runtime> {
		balances: dev_accounts::all().map(|who| (who, 1_000_000 * UNIT)).to_vec(),
		..Default::default()
	}
	.assimilate_storage(&mut storage)
	.unwrap();
	let mut ext: sp_io::TestExternalities = storage.into();
	ext.execute_with(|| {
		let header = Header::new(
			1,
			Default::default(),
			Default::default(),
			System::block_hash(0),
			Default::default(),
		);
		Executive::initialize_block(&header);
	});
	ext
}

fn transfer(to: &keyring::MlDsa65Pair, value: Balance) -> RuntimeCall {
	RuntimeCall::Balances(BalancesCall::transfer_keep_alive { dest: to.account_id().into(), value })
}

fn sign(
	signer: &keyring::MlDsa65Pair,
	call: RuntimeCall,
	nonce: u32,
	parents: Vec<(canggu_runtime::AccountId, u32)>,
	tip: Balance,
) -> UncheckedExtrinsic {
	let genesis = System::block_hash(0);
	let extension: TxExtension = (
		frame_system::AuthorizeCall::<Runtime>::new(),
		frame_system::CheckNonZeroSender::<Runtime>::new(),
		frame_system::CheckSpecVersion::<Runtime>::new(),
		frame_system::CheckTxVersion::<Runtime>::new(),
		frame_system::CheckGenesis::<Runtime>::new(),
		frame_system::CheckEra::<Runtime>::from(Era::Immortal),
		canggu_dag_ordering::CheckDagParents::<Runtime>::on(parents).unwrap(),
		frame_system::CheckNonce::<Runtime>::from(nonce),
		frame_system::CheckWeight::<Runtime>::new(),
		canggu_dag_ordering::ChargeTransactionPaymentNoTip(
			pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(tip),
		),
		frame_metadata_hash_extension::CheckMetadataHash::<Runtime>::new(false),
		frame_system::WeightReclaim::<Runtime>::new(),
	);
	let implicit = (
		(),
		(),
		VERSION.spec_version,
		VERSION.transaction_version,
		genesis,
		genesis,
		(),
		(),
		(),
		(),
		None,
		(),
	);
	let payload = SignedPayload::from_raw(call.clone(), extension.clone(), implicit);
	let signature = payload.using_encoded(|bytes| signer.sign(bytes));
	UncheckedExtrinsic::new_signed(call, Address::Id(signer.account_id()), signature, extension)
}

fn apply(xt: UncheckedExtrinsic) -> Result<(), TransactionValidityError> {
	Executive::apply_extrinsic(xt).map(|dispatch| dispatch.expect("dispatch succeeds"))
}

#[test]
fn ml_dsa_signed_transfer_executes() {
	new_test_ext().execute_with(|| {
		let (alice, bob) = (keyring::dev("Alice"), keyring::dev("Bob"));
		let before = pallet_balances::Pallet::<Runtime>::free_balance(bob.account_id());
		let xt = sign(&alice, transfer(&bob, 5 * UNIT), 0, vec![], 0);
		// ~1952 B key + 3309 B signature + call/extensions.
		assert!(xt.encoded_size() > 5_261, "size {}", xt.encoded_size());
		assert_eq!(apply(xt), Ok(()));
		assert_eq!(
			pallet_balances::Pallet::<Runtime>::free_balance(bob.account_id()),
			before + 5 * UNIT
		);
	});
}

#[test]
fn forged_signatures_are_rejected() {
	new_test_ext().execute_with(|| {
		let (alice, bob) = (keyring::dev("Alice"), keyring::dev("Bob"));

		// Flip one bit of a valid signature.
		let mut xt = sign(&alice, transfer(&bob, UNIT), 0, vec![], 0);
		if let sp_runtime::generic::Preamble::Signed(
			_,
			CangguSignature::MlDsa65 { signature, .. },
			_,
		) = &mut xt.preamble
		{
			signature.0[100] ^= 1;
		} else {
			panic!("expected an ML-DSA signed extrinsic");
		}
		assert_eq!(apply(xt), Err(InvalidTransaction::BadProof.into()));

		// Bob signs a transaction that claims to come from Alice.
		let call = transfer(&bob, UNIT);
		let mut xt = sign(&bob, call, 0, vec![], 0);
		if let sp_runtime::generic::Preamble::Signed(address, _, _) = &mut xt.preamble {
			*address = Address::Id(alice.account_id());
		}
		assert_eq!(apply(xt), Err(InvalidTransaction::BadProof.into()));
	});
}

#[test]
fn dag_child_cannot_execute_before_parent() {
	new_test_ext().execute_with(|| {
		let (bob, charlie, eve) =
			(keyring::dev("Bob"), keyring::dev("Charlie"), keyring::dev("Eve"));
		let parent = sign(&bob, transfer(&eve, UNIT), 0, vec![], 0);
		let child = sign(&charlie, transfer(&eve, UNIT), 0, vec![(bob.account_id(), 0)], 0);

		// The pool sees the dependency as a `requires` tag on Bob's nonce-0 transaction.
		let validity = Executive::validate_transaction(
			TransactionSource::External,
			child.clone(),
			System::block_hash(0),
		)
		.unwrap();
		assert_eq!(validity.requires, vec![(bob.account_id(), 0u32).encode()]);

		// A block that orders the child first is invalid...
		assert_eq!(apply(child.clone()), Err(InvalidTransaction::Future.into()));
		// ...and the correct order works.
		assert_eq!(apply(parent), Ok(()));
		assert_eq!(apply(child), Ok(()));
	});
}

#[test]
fn tips_are_rejected() {
	new_test_ext().execute_with(|| {
		let (alice, bob) = (keyring::dev("Alice"), keyring::dev("Bob"));
		let xt = sign(&alice, transfer(&bob, UNIT), 0, vec![], 1);
		assert_eq!(
			apply(xt),
			Err(InvalidTransaction::Custom(canggu_dag_ordering::TIPS_DISABLED).into())
		);
	});
}
