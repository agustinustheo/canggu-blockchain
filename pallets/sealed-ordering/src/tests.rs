use crate::{self as pallet_sealed_ordering, *};
use frame_support::{
	assert_noop, assert_ok, derive_impl,
	traits::{ConstU32, ConstU64, Contains, Hooks},
	weights::Weight,
};
use sp_core::H256;
use sp_runtime::{BuildStorage, DispatchResult};

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Balances: pallet_balances,
		Sealed: pallet_sealed_ordering,
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

pub struct NotSealed;
impl Contains<RuntimeCall> for NotSealed {
	fn contains(call: &RuntimeCall) -> bool {
		!matches!(call, RuntimeCall::Sealed(_))
	}
}

frame_support::parameter_types! {
	pub MaxCallWeight: Weight = Weight::from_parts(1_000_000_000_000, u64::MAX);
}

impl Config for Test {
	type RuntimeCall = RuntimeCall;
	type RuntimeHoldReason = RuntimeHoldReason;
	type Currency = Balances;
	type CallFilter = NotSealed;
	type CommitDeposit = ConstU64<5>;
	type RevealWindow = ConstU64<2>;
	type MaxCommitsPerBlock = ConstU32<8>;
	type MaxCallLen = ConstU32<512>;
	type MaxCallWeight = MaxCallWeight;
}

const RELAYER: u64 = 100;
const SINK: u64 = 99;

fn new_test_ext() -> sp_io::TestExternalities {
	let mut storage = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	pallet_balances::GenesisConfig::<Test> {
		balances: (1..=5).chain([RELAYER, SINK]).map(|who| (who, 1_000)).collect(),
		..Default::default()
	}
	.assimilate_storage(&mut storage)
	.unwrap();
	let mut ext: sp_io::TestExternalities = storage.into();
	ext.execute_with(|| go_to(1));
	ext
}

/// Start block `n`; block `n - 1` gets a distinct, deterministic hash.
fn go_to(n: u64) {
	while System::block_number() < n {
		let next = System::block_number() + 1;
		System::initialize(&next, &H256::repeat_byte(next as u8 ^ 0x5a), &Default::default());
		Sealed::on_initialize(next);
	}
}

fn pay(amount: u64) -> RuntimeCall {
	RuntimeCall::Balances(pallet_balances::Call::transfer_allow_death { dest: SINK, value: amount })
}

fn salt(who: u64) -> [u8; 32] {
	[who as u8; 32]
}

fn commitment(who: u64, call: &RuntimeCall) -> [u8; 32] {
	commitment_of(&who, &call.encode(), &salt(who))
}

fn reveal(who: u64, block: u64, call: RuntimeCall) -> frame_support::dispatch::DispatchResult {
	Sealed::reveal(RuntimeOrigin::signed(who), block, Box::new(call), salt(who))
}

fn executed() -> Vec<(u32, [u8; 32], DispatchResult)> {
	System::events()
		.into_iter()
		.filter_map(|r| match r.event {
			RuntimeEvent::Sealed(Event::Executed { position, commitment, result, .. }) => {
				Some((position, commitment, result))
			},
			_ => None,
		})
		.collect()
}

/// Commit from senders 1..=4 (in the given commit order), reveal in `reveal_order`, and return
/// the commitments in the order they executed.
fn run(commit_order: [u64; 4], reveal_order: [u64; 4]) -> Vec<[u8; 32]> {
	let mut order = vec![];
	new_test_ext().execute_with(|| {
		for who in commit_order {
			assert_ok!(Sealed::commit(RuntimeOrigin::signed(RELAYER), commitment(who, &pay(who))));
		}
		go_to(2);
		for who in reveal_order {
			assert_ok!(reveal(who, 1, pay(who)));
		}
		go_to(4); // 1 + RevealWindow + 1
		order = executed().into_iter().map(|(_, c, _)| c).collect();
	});
	order
}

#[test]
fn execution_order_is_canonical() {
	let a = run([1, 2, 3, 4], [1, 2, 3, 4]);
	let b = run([4, 3, 2, 1], [3, 1, 4, 2]);
	assert_eq!(a.len(), 4);
	// Neither the order commitments were included in, nor the order they were revealed in,
	// changes the execution order.
	assert_eq!(a, b);
	// It is the order of blake2(commitment ‖ hash of the commit block).
	new_test_ext().execute_with(|| {
		go_to(2);
		let hash = System::block_hash(1);
		let mut expected: Vec<[u8; 32]> = (1..=4).map(|w| commitment(w, &pay(w))).collect();
		expected.sort_by_key(|c| order_key(c, &hash));
		assert_eq!(a, expected);
	});
}

#[test]
fn a_front_runner_reacting_to_a_reveal_executes_after_the_victim() {
	new_test_ext().execute_with(|| {
		let victim = pay(500);
		assert_ok!(Sealed::commit(RuntimeOrigin::signed(1), commitment(1, &victim)));
		go_to(2);
		assert_ok!(reveal(1, 1, victim));
		// The attacker saw the reveal and commits now, but block 2's commitments run after block
		// 1's.
		let attack = pay(400);
		assert_ok!(Sealed::commit(RuntimeOrigin::signed(2), commitment(2, &attack)));
		go_to(3);
		assert_ok!(reveal(2, 2, attack));
		go_to(4);
		assert_eq!(executed().len(), 1, "only the victim's block has settled");
		assert_eq!(Balances::free_balance(1), 1_000 - 500);
		go_to(5);
		assert_eq!(executed().len(), 2);
		assert_eq!(Balances::free_balance(2), 1_000 - 400);
	});
}

#[test]
fn deposits_are_returned_on_reveal_and_burned_otherwise() {
	new_test_ext().execute_with(|| {
		let issuance = Balances::total_issuance();
		assert_ok!(Sealed::commit(RuntimeOrigin::signed(1), commitment(1, &pay(1))));
		assert_ok!(Sealed::commit(RuntimeOrigin::signed(2), commitment(2, &pay(2))));
		assert_eq!(Balances::free_balance(1), 995);
		go_to(2);
		assert_ok!(reveal(1, 1, pay(1)));
		go_to(4);
		assert_eq!(Balances::free_balance(1), 1_000 - 1, "deposit back, call executed");
		assert_eq!(Balances::free_balance(2), 995, "never revealed: deposit burned");
		assert_eq!(Balances::total_issuance(), issuance - 5);
		System::assert_has_event(
			Event::Forfeited { block: 1, commitment: commitment(2, &pay(2)), depositor: 2 }.into(),
		);
	});
}

#[test]
fn reveals_are_bound_to_sender_salt_and_window() {
	new_test_ext().execute_with(|| {
		let call = pay(10);
		assert_ok!(Sealed::commit(RuntimeOrigin::signed(RELAYER), commitment(1, &call)));
		// Not before the commit block has ended.
		assert_noop!(reveal(1, 1, call.clone()), Error::<Test>::RevealWindowClosed);
		go_to(2);
		// Someone else cannot reveal it (the commitment binds the sender).
		assert_noop!(reveal(2, 1, call.clone()), Error::<Test>::UnknownCommitment);
		// A different call does not match.
		assert_noop!(reveal(1, 1, pay(11)), Error::<Test>::UnknownCommitment);
		// Sealed calls cannot be nested.
		let nested = RuntimeCall::Sealed(Call::commit { commitment: [0; 32] });
		assert_noop!(reveal(1, 1, nested), Error::<Test>::CallNotAllowed);
		assert_ok!(reveal(1, 1, call.clone()));
		assert_noop!(reveal(1, 1, call.clone()), Error::<Test>::AlreadyRevealed);
		go_to(4);
		assert_noop!(reveal(1, 1, call), Error::<Test>::RevealWindowClosed);
	});
}

#[test]
fn a_failing_sealed_call_does_not_affect_the_others() {
	new_test_ext().execute_with(|| {
		let (ok, too_much) = (pay(10), pay(10_000));
		assert_ok!(Sealed::commit(RuntimeOrigin::signed(1), commitment(1, &ok)));
		assert_ok!(Sealed::commit(RuntimeOrigin::signed(2), commitment(2, &too_much)));
		go_to(2);
		assert_ok!(reveal(1, 1, ok));
		assert_ok!(reveal(2, 1, too_much));
		go_to(4);
		let results: Vec<bool> = executed().into_iter().map(|(_, _, r)| r.is_ok()).collect();
		assert_eq!(results.iter().filter(|ok| **ok).count(), 1);
		assert_eq!(Balances::free_balance(1), 990);
		assert_eq!(Balances::free_balance(2), 1_000, "failed call; revealed, so deposit returned");
	});
}

#[test]
fn commitments_per_block_are_bounded() {
	new_test_ext().execute_with(|| {
		for i in 0..8u8 {
			assert_ok!(Sealed::commit(RuntimeOrigin::signed(RELAYER), [i; 32]));
		}
		assert_noop!(
			Sealed::commit(RuntimeOrigin::signed(RELAYER), [9; 32]),
			Error::<Test>::TooManyCommitments
		);
		assert_noop!(
			Sealed::commit(RuntimeOrigin::signed(1), [0; 32]),
			Error::<Test>::AlreadyCommitted
		);
	});
}
