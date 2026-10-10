//! # Canggu primitives
//!
//! * [`CangguSignature`] / [`CangguSigner`]: the account signature scheme of the chain. The
//!   post-quantum variant is ML-DSA-65 (FIPS 204, a.k.a. CRYSTALS-Dilithium3, NIST level 3). The
//!   classical Substrate schemes are kept as a *transition-period* option, as proposed in the
//!   whitepaper, so existing wallets keep working while users migrate.
//! * [`canggu_crypto`]: host functions. Expensive cryptography (ML-DSA verification, Groth16
//!   pairing checks) runs natively in the node instead of inside the Wasm runtime, exactly like
//!   Substrate's own `sr25519_verify`. This is also the only sound place to add GPU acceleration:
//!   the host function has a fixed, deterministic input/output contract, and the node is free to
//!   compute it on CPU, GPU or FPGA as long as the answer is bit-identical.
//! * [`keyring`] (std only): deterministic development ML-DSA keys.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::{ecdsa, ed25519, sr25519};
use sp_runtime::{
	traits::{IdentifyAccount, Lazy, Verify},
	AccountId32,
};
use sp_runtime_interface::{pass_by::PassFatPointerAndRead, runtime_interface};

#[cfg(feature = "std")]
pub mod keyring;
#[cfg(feature = "std")]
pub mod zk;

/// Size in bytes of an encoded ML-DSA-65 verifying (public) key.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
/// Size in bytes of an encoded ML-DSA-65 signature.
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;
/// FIPS 204 context string used for every Canggu transaction signature (domain separation).
pub const ML_DSA_CONTEXT: &[u8] = b"canggu/tx/v1";

/// An ML-DSA-65 public key.
#[derive(
	Clone,
	Eq,
	PartialEq,
	Ord,
	PartialOrd,
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo,
)]
pub struct MlDsa65Public(pub [u8; ML_DSA_65_PUBLIC_KEY_LEN]);

/// An ML-DSA-65 signature.
#[derive(Clone, Eq, PartialEq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo)]
pub struct MlDsa65Signature(pub [u8; ML_DSA_65_SIGNATURE_LEN]);

impl MlDsa65Public {
	/// The account controlled by this key: `blake2_256(public_key)`.
	///
	/// The hash is 256 bits, which keeps 128-bit collision/preimage security against Grover.
	pub fn to_account_id(&self) -> AccountId32 {
		sp_io::hashing::blake2_256(&self.0).into()
	}
}

impl core::fmt::Debug for MlDsa65Public {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "MlDsa65Public({:02x?}..)", &self.0[..8])
	}
}

impl core::fmt::Debug for MlDsa65Signature {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "MlDsa65Signature({:02x?}..)", &self.0[..8])
	}
}

/// Signature over a Canggu transaction.
///
/// An `AccountId32` cannot be turned back into an ML-DSA public key (it is a hash of it), so the
/// post-quantum variant carries the public key next to the signature, the same trick Ethereum
/// account abstraction and Bitcoin P2PKH use. Variant indices 0..=2 are layout-compatible with
/// `sp_runtime::MultiSignature`, so existing tooling can still sign classical transactions.
#[derive(
	Clone, Eq, PartialEq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, Debug, TypeInfo,
)]
pub enum CangguSignature {
	/// Classical Ed25519 (transition period only).
	#[codec(index = 0)]
	Ed25519(ed25519::Signature),
	/// Classical Sr25519 (transition period only).
	#[codec(index = 1)]
	Sr25519(sr25519::Signature),
	/// Classical ECDSA/secp256k1 (transition period only).
	#[codec(index = 2)]
	Ecdsa(ecdsa::Signature),
	/// Post-quantum ML-DSA-65 (CRYSTALS-Dilithium3).
	#[codec(index = 3)]
	MlDsa65 { public: MlDsa65Public, signature: MlDsa65Signature },
}

/// Public key of any signature scheme accepted by Canggu.
#[derive(
	Clone, Eq, PartialEq, Ord, PartialOrd, Encode, Decode, DecodeWithMemTracking, Debug, TypeInfo,
)]
pub enum CangguSigner {
	#[codec(index = 0)]
	Ed25519(ed25519::Public),
	#[codec(index = 1)]
	Sr25519(sr25519::Public),
	#[codec(index = 2)]
	Ecdsa(ecdsa::Public),
	#[codec(index = 3)]
	MlDsa65(MlDsa65Public),
}

impl IdentifyAccount for CangguSigner {
	type AccountId = AccountId32;

	fn into_account(self) -> AccountId32 {
		match self {
			Self::Ed25519(who) => <[u8; 32]>::from(who).into(),
			Self::Sr25519(who) => <[u8; 32]>::from(who).into(),
			Self::Ecdsa(who) => sp_io::hashing::blake2_256(who.as_ref()).into(),
			Self::MlDsa65(who) => who.to_account_id(),
		}
	}
}

impl From<MlDsa65Public> for CangguSigner {
	fn from(public: MlDsa65Public) -> Self {
		Self::MlDsa65(public)
	}
}

impl From<sr25519::Public> for CangguSigner {
	fn from(public: sr25519::Public) -> Self {
		Self::Sr25519(public)
	}
}

impl From<sr25519::Signature> for CangguSignature {
	fn from(signature: sr25519::Signature) -> Self {
		Self::Sr25519(signature)
	}
}

impl Verify for CangguSignature {
	type Signer = CangguSigner;

	fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &AccountId32) -> bool {
		let who: [u8; 32] = *signer.as_ref();
		match self {
			Self::Ed25519(sig) => sig.verify(msg, &who.into()),
			Self::Sr25519(sig) => sig.verify(msg, &who.into()),
			Self::Ecdsa(sig) => {
				let m = sp_io::hashing::blake2_256(msg.get());
				sp_io::crypto::secp256k1_ecdsa_recover_compressed(sig.as_ref(), &m)
					.map_or(false, |pubkey| sp_io::hashing::blake2_256(&pubkey) == who)
			},
			// Bind the key to the account first: it is a cheap hash, the lattice check is not.
			Self::MlDsa65 { public, signature } => {
				public.to_account_id() == *signer &&
					canggu_crypto::ml_dsa_65_verify(&public.0, msg.get(), &signature.0)
			},
		}
	}
}

/// Native cryptography exposed to the runtime.
///
/// Consensus-critical contract: every implementation (CPU, GPU, FPGA...) must return exactly the
/// same boolean for the same bytes. The CPU code below is the reference implementation.
#[runtime_interface]
pub trait CangguCrypto {
	/// Verify an ML-DSA-65 signature over `msg` with context [`ML_DSA_CONTEXT`].
	fn ml_dsa_65_verify(
		public: PassFatPointerAndRead<&[u8]>,
		msg: PassFatPointerAndRead<&[u8]>,
		signature: PassFatPointerAndRead<&[u8]>,
	) -> bool {
		crate::keyring::verify(public, msg, signature)
	}

	/// Verify a Groth16 proof on BLS12-381.
	///
	/// * `vk`: arkworks compressed `VerifyingKey<Bls12_381>`.
	/// * `public_inputs`: concatenation of 32-byte little-endian scalar field elements.
	/// * `proof`: arkworks compressed `Proof<Bls12_381>` (192 bytes).
	fn groth16_bls12_381_verify(
		vk: PassFatPointerAndRead<&[u8]>,
		public_inputs: PassFatPointerAndRead<&[u8]>,
		proof: PassFatPointerAndRead<&[u8]>,
	) -> bool {
		crate::zk::verify(vk, public_inputs, proof)
	}
}

/// Host functions that a Canggu node must register next to `sp_io::SubstrateHostFunctions`.
#[cfg(feature = "std")]
pub type HostFunctions = canggu_crypto::HostFunctions;

/// Well-known development accounts (ML-DSA-65 keys derived from `//Name`, see [`keyring`]).
///
/// The runtime's genesis presets are compiled to Wasm, where we deliberately do not ship an ML-DSA
/// key generator, so the account ids are pinned here and checked by a test in [`keyring`].
pub mod dev_accounts {
	use sp_runtime::AccountId32;

	pub const ALICE: [u8; 32] = [
		28, 48, 16, 7, 249, 128, 235, 64, 242, 0, 6, 125, 195, 247, 3, 126, 194, 190, 198, 150, 27,
		32, 242, 47, 91, 92, 14, 108, 34, 108, 244, 69,
	];
	pub const BOB: [u8; 32] = [
		132, 5, 34, 224, 69, 2, 29, 104, 54, 56, 69, 232, 171, 122, 216, 20, 247, 143, 228, 237,
		204, 138, 152, 203, 171, 241, 7, 252, 135, 37, 56, 106,
	];
	pub const CHARLIE: [u8; 32] = [
		99, 148, 91, 101, 170, 255, 143, 172, 246, 81, 81, 59, 65, 226, 60, 51, 133, 126, 89, 110,
		122, 85, 141, 35, 212, 148, 225, 210, 83, 253, 92, 120,
	];
	pub const DAVE: [u8; 32] = [
		131, 221, 153, 232, 92, 168, 249, 160, 96, 115, 170, 154, 242, 115, 129, 186, 79, 51, 202,
		177, 116, 1, 108, 109, 32, 190, 70, 98, 70, 27, 4, 190,
	];
	pub const EVE: [u8; 32] = [
		167, 10, 105, 171, 64, 56, 147, 53, 33, 14, 180, 200, 174, 213, 42, 77, 219, 22, 99, 107,
		163, 109, 235, 29, 10, 183, 173, 167, 252, 237, 156, 53,
	];

	/// All dev accounts, in a stable order.
	pub fn all() -> [AccountId32; 5] {
		[ALICE.into(), BOB.into(), CHARLIE.into(), DAVE.into(), EVE.into()]
	}
}
