use crate::{self as pallet_parallel_payroll, *};
use frame_support::{assert_noop, assert_ok, derive_impl, traits::ConstU32, BoundedVec};
use sp_runtime::{BuildStorage, TokenError};

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Balances: pallet_balances,
		Payroll: pallet_parallel_payroll,
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
	type ExistentialDeposit = frame_support::traits::ConstU64<10>;
}

impl Config for Test {
	type Currency = Balances;
	type MaxRecipients = ConstU32<64>;
}

const EMPLOYER: u64 = 1;

fn new_test_ext() -> sp_io::TestExternalities {
	let mut storage = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	pallet_balances::GenesisConfig::<Test> {
		balances: vec![(EMPLOYER, 10_000), (2, 100)],
		..Default::default()
	}
	.assimilate_storage(&mut storage)
	.unwrap();
	let mut ext: sp_io::TestExternalities = storage.into();
	ext.execute_with(|| System::set_block_number(1));
	ext
}

fn pay(payments: Vec<(u64, u64)>) -> frame_support::dispatch::DispatchResult {
	Payroll::batch_pay(RuntimeOrigin::signed(EMPLOYER), BoundedVec::try_from(payments).unwrap())
}

#[test]
fn pays_everyone_with_a_single_debit() {
	new_test_ext().execute_with(|| {
		let issuance = Balances::total_issuance();
		assert_ok!(pay(vec![(2, 1_000), (3, 2_000), (4, 3_000)]));

		assert_eq!(Balances::free_balance(EMPLOYER), 4_000);
		assert_eq!(Balances::free_balance(2), 1_100);
		assert_eq!(Balances::free_balance(3), 2_000);
		assert_eq!(Balances::free_balance(4), 3_000);
		assert_eq!(Balances::total_issuance(), issuance, "payroll must not mint or burn");
		System::assert_last_event(
			Event::PayrollExecuted { payer: EMPLOYER, recipients: 3, total: 6_000 }.into(),
		);
	});
}

#[test]
fn rejects_conflicting_batches() {
	new_test_ext().execute_with(|| {
		assert_noop!(pay(vec![(2, 10), (3, 10), (2, 10)]), Error::<Test>::DuplicateRecipient);
		assert_noop!(pay(vec![(2, 10), (EMPLOYER, 10)]), Error::<Test>::PayerIsRecipient);
		assert_noop!(pay(vec![]), Error::<Test>::NoPayments);
	});
}

#[test]
fn insufficient_funds_fail_atomically() {
	new_test_ext().execute_with(|| {
		assert_noop!(pay(vec![(2, 6_000), (3, 6_000)]), TokenError::FundsUnavailable);
		assert_noop!(pay(vec![(2, u64::MAX), (3, 1)]), Error::<Test>::Overflow);
	});
}

#[test]
fn one_bad_credit_reverts_the_whole_batch() {
	new_test_ext().execute_with(|| {
		// Account 5 does not exist and 5 is below the existential deposit of 10.
		assert_noop!(pay(vec![(2, 1_000), (5, 5)]), Error::<Test>::CreditFailed);
		assert_eq!(Balances::free_balance(EMPLOYER), 10_000);
		assert_eq!(Balances::free_balance(2), 100);
	});
}
