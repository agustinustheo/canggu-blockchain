use crate::{self as pallet_zk_verifier, *};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use canggu_zk::{PayrollCircuit, Scalar};
use frame_support::{assert_noop, assert_ok, derive_impl, traits::ConstU32, BoundedVec};
use sp_runtime::{BuildStorage, DispatchResult};

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		ZkVerifier: pallet_zk_verifier,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
}

impl Config for Test {
	type MaxVerifyingKeyLen = ConstU32<4096>;
	type MaxPublicInputs = ConstU32<16>;
	type MaxSp1ProofLen = ConstU32<{ 2 * 1024 * 1024 }>;
}

fn new_test_ext() -> sp_io::TestExternalities {
	let mut ext: sp_io::TestExternalities =
		frame_system::GenesisConfig::<Test>::default().build_storage().unwrap().into();
	ext.execute_with(|| System::set_block_number(1));
	ext
}

struct Fixture {
	vk: Vec<u8>,
	inputs: Vec<[u8; 32]>,
	proof: Vec<u8>,
}

fn fixture() -> Fixture {
	let mut rng = StdRng::seed_from_u64(1);
	let (pk, vk) = canggu_zk::setup(3, &mut rng).unwrap();
	let circuit = PayrollCircuit { salt: Scalar::from(99u64), amounts: vec![10, 20, 30] };
	let inputs = circuit.public_inputs().iter().map(canggu_zk::scalar_bytes).collect();
	let proof = canggu_zk::prove(&pk, circuit, &mut rng).unwrap();
	Fixture { vk: canggu_zk::encode(&vk), inputs, proof: canggu_zk::encode(&proof) }
}

fn register(vk: &[u8]) -> VkId {
	assert_ok!(ZkVerifier::register_verifying_key(
		RuntimeOrigin::signed(1),
		vk.to_vec().try_into().unwrap()
	));
	BlakeTwo256::hash(vk)
}

fn submit(vk: VkId, inputs: &[[u8; 32]], proof: &[u8]) -> frame_support::dispatch::DispatchResult {
	ZkVerifier::submit_proof(
		RuntimeOrigin::signed(2),
		vk,
		BoundedVec::try_from(inputs.to_vec()).unwrap(),
		BoundedVec::try_from(proof.to_vec()).unwrap(),
	)
}

#[test]
fn valid_proof_is_recorded() {
	let f = fixture();
	new_test_ext().execute_with(|| {
		let vk = register(&f.vk);
		assert!(!ZkVerifier::is_verified(&vk, &f.inputs));
		assert_ok!(submit(vk, &f.inputs, &f.proof));
		assert!(ZkVerifier::is_verified(&vk, &f.inputs));
		System::assert_last_event(
			Event::ProofVerified { vk, statement: statement_id(&vk, &f.inputs), who: 2 }.into(),
		);
		assert_noop!(submit(vk, &f.inputs, &f.proof), Error::<Test>::AlreadyVerified);
	});
}

#[test]
fn wrong_public_input_is_rejected() {
	let f = fixture();
	new_test_ext().execute_with(|| {
		let vk = register(&f.vk);
		let mut inputs = f.inputs.clone();
		// Claim a different payroll total.
		inputs[0] = canggu_zk::scalar_bytes(&Scalar::from(61u64));
		assert_noop!(submit(vk, &inputs, &f.proof), Error::<Test>::InvalidProof);
	});
}

#[test]
fn garbage_is_rejected_without_panicking() {
	let f = fixture();
	new_test_ext().execute_with(|| {
		let vk = register(&f.vk);
		assert_noop!(submit(vk, &f.inputs, &[0xff; 192]), Error::<Test>::InvalidProof);
		assert_noop!(submit(vk, &[[0xff; 32]; 2], &f.proof), Error::<Test>::InvalidProof);

		let junk_vk = register(&[1, 2, 3]);
		assert_noop!(submit(junk_vk, &f.inputs, &f.proof), Error::<Test>::InvalidProof);
	});
}

#[test]
fn unknown_and_duplicate_keys() {
	let f = fixture();
	new_test_ext().execute_with(|| {
		assert_noop!(
			submit(Default::default(), &f.inputs, &f.proof),
			Error::<Test>::UnknownVerifyingKey
		);
		register(&f.vk);
		assert_noop!(
			ZkVerifier::register_verifying_key(
				RuntimeOrigin::signed(1),
				f.vk.clone().try_into().unwrap()
			),
			Error::<Test>::VerifyingKeyExists
		);
	});
}

// A real SP1 v6.10 compressed proof of the payroll program (16 private amounts), produced by
// `sp1/scripts/bench-ladder.sh payroll 16`.
const SP1_PROOF: &[u8] = include_bytes!("../../../sp1/fixtures/payroll-n16.proof");
const SP1_PUBLIC_VALUES: &[u8] = include_bytes!("../../../sp1/fixtures/payroll-n16.pv");

fn submit_sp1(program: [u8; 32], public_values: &[u8], proof: &[u8]) -> DispatchResult {
	ZkVerifier::submit_sp1_proof(
		RuntimeOrigin::signed(2),
		program,
		public_values.to_vec().try_into().unwrap(),
		proof.to_vec().try_into().unwrap(),
	)
}

#[test]
fn post_quantum_sp1_proof_is_verified_and_recorded() {
	new_test_ext().execute_with(|| {
		let program = canggu_primitives::sp1::PAYROLL_VKEY_HASH;
		assert_eq!(SP1_PROOF.len(), 1_272_546);
		assert_ok!(submit_sp1(program, SP1_PUBLIC_VALUES, SP1_PROOF));
		let statement = sp1_statement_id(&program, SP1_PUBLIC_VALUES);
		assert!(VerifiedStatements::<Test>::contains_key(statement));
		assert_noop!(
			submit_sp1(program, SP1_PUBLIC_VALUES, SP1_PROOF),
			Error::<Test>::AlreadyVerified
		);
	});
}

#[test]
fn sp1_proof_is_bound_to_program_public_values_and_encoding() {
	new_test_ext().execute_with(|| {
		let program = canggu_primitives::sp1::PAYROLL_VKEY_HASH;
		// Claim a different payroll total (bytes 4..20 are the u128 total).
		let mut forged = SP1_PUBLIC_VALUES.to_vec();
		forged[4] ^= 1;
		assert_noop!(submit_sp1(program, &forged, SP1_PROOF), Error::<Test>::InvalidProof);
		// The proof is for the payroll program, not the ML-DSA batch program.
		let other = canggu_primitives::sp1::MLDSA_BATCH_VKEY_HASH;
		assert_noop!(submit_sp1(other, SP1_PUBLIC_VALUES, SP1_PROOF), Error::<Test>::InvalidProof);
		// A trailing byte would still verify with the raw sp1-verifier; ours rejects it.
		let mut padded = SP1_PROOF.to_vec();
		padded.push(0);
		assert_noop!(submit_sp1(program, SP1_PUBLIC_VALUES, &padded), Error::<Test>::InvalidProof);
		assert_noop!(
			submit_sp1(program, SP1_PUBLIC_VALUES, &[0u8; 64]),
			Error::<Test>::InvalidProof
		);
	});
}
