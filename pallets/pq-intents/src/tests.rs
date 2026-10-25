use crate::{self as pallet_pq_intents, *};
use canggu_primitives::keyring::{self, MlDsa65Pair};
use frame_support::{assert_noop, assert_ok, derive_impl, traits::ConstU32, BoundedVec};
use sp_runtime::{traits::IdentityLookup, AccountId32, BuildStorage};

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Balances: pallet_balances,
		Intents: pallet_pq_intents,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type AccountId = AccountId32;
	type Lookup = IdentityLookup<AccountId32>;
	type AccountData = pallet_balances::AccountData<u64>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
	type AccountStore = System;
}

frame_support::parameter_types! {
	pub const BatchProgram: [u8; 32] = canggu_primitives::sp1::MLDSA_BATCH_VKEY_HASH;
}

impl Config for Test {
	type Currency = Balances;
	type MaxIntents = ConstU32<64>;
	type MaxCompressedIntents = ConstU32<64>;
	type MaxProofLen = ConstU32<{ 2 * 1024 * 1024 }>;
	type BatchProgram = BatchProgram;
}

fn alice() -> MlDsa65Pair {
	keyring::dev("Alice")
}
fn bob() -> MlDsa65Pair {
	keyring::dev("Bob")
}
fn relayer() -> AccountId32 {
	keyring::dev("Eve").account_id()
}

fn new_test_ext() -> sp_io::TestExternalities {
	let mut storage = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	pallet_balances::GenesisConfig::<Test> {
		balances: vec![
			(alice().account_id(), 1_000),
			(bob().account_id(), 1_000),
			(relayer(), 1_000),
		],
		..Default::default()
	}
	.assimilate_storage(&mut storage)
	.unwrap();
	let mut ext: sp_io::TestExternalities = storage.into();
	ext.execute_with(|| System::set_block_number(1));
	ext
}

fn sign(pair: &MlDsa65Pair, to: &MlDsa65Pair, amount: u64, nonce: u32) -> SignedIntentOf<Test> {
	let intent = Intent { to: to.account_id(), amount, nonce };
	let genesis = System::block_hash(0);
	SignedIntent {
		public: pair.public(),
		signature: pair.sign_raw(&signing_payload(&genesis, &intent)),
		intent,
	}
}

fn submit(intents: Vec<SignedIntentOf<Test>>) -> frame_support::dispatch::DispatchResult {
	Intents::submit_intents(
		RuntimeOrigin::signed(relayer()),
		BoundedVec::try_from(intents).unwrap(),
	)
}

#[test]
fn batch_of_valid_intents_executes() {
	new_test_ext().execute_with(|| {
		assert_ok!(submit(vec![
			sign(&alice(), &bob(), 100, 0),
			sign(&alice(), &bob(), 50, 1),
			sign(&bob(), &alice(), 10, 0),
		]));
		assert_eq!(Balances::free_balance(alice().account_id()), 1_000 - 150 + 10);
		assert_eq!(Balances::free_balance(bob().account_id()), 1_000 + 150 - 10);
		assert_eq!(Nonces::<Test>::get(alice().account_id()), 2);
		System::assert_last_event(
			Event::BatchExecuted { relayer: relayer(), executed: 3, rejected: 0 }.into(),
		);
	});
}

#[test]
fn bad_intents_are_rejected_individually() {
	new_test_ext().execute_with(|| {
		let mut forged = sign(&alice(), &bob(), 100, 0);
		forged.intent.amount = 900; // signature no longer matches
		let replay = sign(&bob(), &alice(), 10, 0);
		let too_much = sign(&bob(), &alice(), 5_000, 1);

		assert_ok!(submit(vec![forged, replay.clone(), replay, too_much]));
		System::assert_has_event(
			Event::IntentRejected { index: 0, reason: RejectReason::BadSignature }.into(),
		);
		System::assert_has_event(
			Event::IntentRejected { index: 2, reason: RejectReason::BadNonce }.into(),
		);
		System::assert_has_event(
			Event::IntentRejected { index: 3, reason: RejectReason::TransferFailed }.into(),
		);
		System::assert_last_event(
			Event::BatchExecuted { relayer: relayer(), executed: 1, rejected: 3 }.into(),
		);
		// The failed transfer did not consume Bob's nonce.
		assert_eq!(Nonces::<Test>::get(bob().account_id()), 1);
		assert_eq!(Balances::free_balance(alice().account_id()), 1_010);
	});
}

#[test]
fn intents_are_bound_to_the_chain() {
	new_test_ext().execute_with(|| {
		let intent = Intent { to: bob().account_id(), amount: 1, nonce: 0 };
		let other_chain = sp_core::H256::repeat_byte(7);
		let signed = SignedIntent {
			public: alice().public(),
			signature: alice().sign_raw(&signing_payload(&other_chain, &intent)),
			intent,
		};
		assert_ok!(submit(vec![signed]));
		System::assert_has_event(
			Event::IntentRejected { index: 0, reason: RejectReason::BadSignature }.into(),
		);
	});
}

#[test]
fn empty_batch_is_an_error() {
	new_test_ext().execute_with(|| {
		assert_noop!(submit(vec![]), Error::<Test>::NoIntents);
	});
}

// ---- Signature compression with SP1 ----------------------------------------------------------

type Batch = Vec<(AccountId32, IntentOf<Test>)>;

/// The batch proven in `fixtures/compressed-n4.proof`.
fn compressed_batch() -> Batch {
	vec![
		(alice().account_id(), Intent { to: bob().account_id(), amount: 100, nonce: 0 }),
		(alice().account_id(), Intent { to: bob().account_id(), amount: 50, nonce: 1 }),
		(bob().account_id(), Intent { to: alice().account_id(), amount: 10, nonce: 0 }),
		(bob().account_id(), Intent { to: relayer(), amount: 7, nonce: 1 }),
	]
}

const COMPRESSED_PROOF: &[u8] = include_bytes!("../fixtures/compressed-n4.proof");
const COMPRESSED_PV: &[u8] = include_bytes!("../fixtures/compressed-n4.pv");

fn submit_compressed(intents: Batch, proof: &[u8]) -> frame_support::dispatch::DispatchResult {
	Intents::submit_compressed(
		RuntimeOrigin::signed(relayer()),
		intents.try_into().unwrap(),
		proof.to_vec().try_into().unwrap(),
	)
}

/// Regenerate the fixture's prover input:
/// `cargo test --release -p pallet-pq-intents -- --ignored write_compressed_fixture_input`, then
/// `canggu-sp1 prove mldsa fixtures/compressed-n4.input fixtures/compressed-n4` (see sp1/).
#[test]
#[ignore]
fn write_compressed_fixture_input() {
	new_test_ext().execute_with(|| {
		let genesis = System::block_hash(0);
		let keys = |who: &AccountId32| if *who == alice().account_id() { alice() } else { bob() };
		let prefixed = |out: &mut Vec<u8>, bytes: &[u8]| {
			out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
			out.extend_from_slice(bytes);
		};
		let batch = compressed_batch();
		let mut input = vec![];
		prefixed(&mut input, canggu_primitives::ML_DSA_CONTEXT);
		input.extend_from_slice(&(batch.len() as u32).to_le_bytes());
		for (from, intent) in &batch {
			let message = signing_payload(&genesis, intent);
			let pair = keys(from);
			prefixed(&mut input, &pair.public().0);
			prefixed(&mut input, &message);
			prefixed(&mut input, &pair.sign_raw(&message).0);
		}
		std::fs::write(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/compressed-n4.input"), input)
			.unwrap();
	});
}

#[test]
fn runtime_recomputes_the_proven_public_values() {
	new_test_ext().execute_with(|| {
		assert_eq!(Intents::batch_public_values(&compressed_batch()), COMPRESSED_PV);
	});
}

#[test]
fn compressed_batch_executes_without_any_signature_on_chain() {
	new_test_ext().execute_with(|| {
		assert_ok!(submit_compressed(compressed_batch(), COMPRESSED_PROOF));
		assert_eq!(Balances::free_balance(alice().account_id()), 1_000 - 150 + 10);
		assert_eq!(Balances::free_balance(bob().account_id()), 1_000 + 150 - 10 - 7);
		assert_eq!(Nonces::<Test>::get(bob().account_id()), 2);
		System::assert_last_event(
			Event::BatchExecuted { relayer: relayer(), executed: 4, rejected: 0 }.into(),
		);
		// Replaying the same proven batch: the proof still verifies, the nonces do not.
		assert_ok!(submit_compressed(compressed_batch(), COMPRESSED_PROOF));
		System::assert_last_event(
			Event::BatchExecuted { relayer: relayer(), executed: 0, rejected: 4 }.into(),
		);
	});
}

#[test]
fn compressed_proof_is_bound_to_every_sender_and_intent() {
	new_test_ext().execute_with(|| {
		let tamper = |f: &dyn Fn(&mut Batch)| {
			let mut batch = compressed_batch();
			f(&mut batch);
			submit_compressed(batch, COMPRESSED_PROOF)
		};
		assert_noop!(tamper(&|b| b[0].1.amount = 999), Error::<Test>::InvalidBatchProof);
		assert_noop!(tamper(&|b| b[2].0 = relayer()), Error::<Test>::InvalidBatchProof);
		assert_noop!(
			tamper(&|b| b[3].1.to = alice().account_id()),
			Error::<Test>::InvalidBatchProof
		);
		assert_noop!(
			tamper(&|b| {
				b.pop();
			}),
			Error::<Test>::InvalidBatchProof
		);
		assert_noop!(tamper(&|b| b.swap(0, 1)), Error::<Test>::InvalidBatchProof);
		let mut padded = COMPRESSED_PROOF.to_vec();
		padded.push(0);
		assert_noop!(
			submit_compressed(compressed_batch(), &padded),
			Error::<Test>::InvalidBatchProof
		);
	});
}
