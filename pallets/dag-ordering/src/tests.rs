use super::*;
use frame_support::{derive_impl, dispatch::GetDispatchInfo};
use sp_runtime::{traits::TxBaseImplication, BuildStorage};

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Balances: pallet_balances,
		TransactionPayment: pallet_transaction_payment,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type AccountData = pallet_balances::AccountData<u64>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
	type AccountStore = System;
}

#[derive_impl(pallet_transaction_payment::config_preludes::TestDefaultConfig)]
impl pallet_transaction_payment::Config for Test {
	type OnChargeTransaction = pallet_transaction_payment::FungibleAdapter<Balances, ()>;
	type WeightToFee = frame_support::weights::IdentityFee<u64>;
	type LengthToFee = frame_support::weights::IdentityFee<u64>;
}

const ALICE: u64 = 1;
const BOB: u64 = 2;

fn new_test_ext() -> sp_io::TestExternalities {
	let mut storage = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	pallet_balances::GenesisConfig::<Test> {
		balances: vec![(ALICE, 1 << 60), (BOB, 1 << 60)],
		..Default::default()
	}
	.assimilate_storage(&mut storage)
	.unwrap();
	storage.into()
}

fn remark() -> RuntimeCall {
	RuntimeCall::System(frame_system::Call::remark { remark: vec![] })
}

fn validate<E: TransactionExtension<RuntimeCall, Implicit = ()>>(
	ext: &E,
	who: u64,
) -> Result<ValidTransaction, TransactionValidityError> {
	let call = remark();
	let info = call.get_dispatch_info();
	ext.validate(
		RuntimeOrigin::signed(who),
		&call,
		&info,
		0,
		(),
		&TxBaseImplication(()),
		TransactionSource::External,
	)
	.map(|(validity, _, _)| validity)
}

#[test]
fn pending_parent_becomes_pool_dependency_matching_check_nonce_tag() {
	new_test_ext().execute_with(|| {
		// Alice's tx depends on Bob's tx with nonce 0, which has not been executed yet.
		let child = CheckDagParents::<Test>::on(vec![(BOB, 0)]).unwrap();
		let child_validity = validate(&child, ALICE).unwrap();

		// The tag Bob's transaction provides through the stock `CheckNonce` extension.
		let parent_validity = validate(&frame_system::CheckNonce::<Test>::from(0), BOB).unwrap();

		assert_eq!(child_validity.requires, parent_validity.provides);
		assert!(child_validity.provides.is_empty());
	});
}

#[test]
fn executed_parent_no_longer_required() {
	new_test_ext().execute_with(|| {
		let child = CheckDagParents::<Test>::on(vec![(BOB, 0)]).unwrap();
		frame_system::Pallet::<Test>::inc_account_nonce(BOB);
		assert!(validate(&child, ALICE).unwrap().requires.is_empty());
	});
}

#[test]
fn block_execution_rejects_child_before_parent() {
	new_test_ext().execute_with(|| {
		let call = remark();
		let info = call.get_dispatch_info();
		let child = CheckDagParents::<Test>::on(vec![(BOB, 0), (BOB, 1)]).unwrap();

		let prepare = |ext: CheckDagParents<Test>| {
			ext.prepare((), &RuntimeOrigin::signed(ALICE), &call, &info, 0)
		};

		assert_eq!(prepare(child.clone()), Err(InvalidTransaction::Future.into()));
		// Only one of two parents executed: still invalid.
		frame_system::Pallet::<Test>::inc_account_nonce(BOB);
		assert_eq!(prepare(child.clone()), Err(InvalidTransaction::Future.into()));
		frame_system::Pallet::<Test>::inc_account_nonce(BOB);
		assert_eq!(prepare(child), Ok(()));
	});
}

#[test]
fn no_parents_is_a_no_op() {
	new_test_ext().execute_with(|| {
		assert_eq!(validate(&CheckDagParents::<Test>::none(), ALICE), Ok(Default::default()));
	});
}

#[test]
fn too_many_parents_cannot_be_encoded() {
	let parents = (0..=MAX_PARENTS).map(|n| (BOB, n)).collect::<Vec<_>>();
	assert!(CheckDagParents::<Test>::on(parents).is_err());
}

#[test]
fn tips_are_rejected() {
	new_test_ext().execute_with(|| {
		let tipped = ChargeTransactionPaymentNoTip::<Test>(
			pallet_transaction_payment::ChargeTransactionPayment::from(10),
		);
		assert_eq!(validate(&tipped, ALICE), Err(InvalidTransaction::Custom(TIPS_DISABLED).into()));
		assert!(validate(&ChargeTransactionPaymentNoTip::<Test>::new(), ALICE).is_ok());
	});
}

#[test]
fn equal_transactions_get_equal_priority_regardless_of_sender() {
	new_test_ext().execute_with(|| {
		let ext = ChargeTransactionPaymentNoTip::<Test>::new();
		assert_eq!(validate(&ext, ALICE).unwrap().priority, validate(&ext, BOB).unwrap().priority);
	});
}
