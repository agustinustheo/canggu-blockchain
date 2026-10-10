//! ML-DSA-65 key handling for the node, the CLI and tests (std only).

use crate::{
	CangguSignature, CangguSigner, MlDsa65Public, MlDsa65Signature, ML_DSA_65_PUBLIC_KEY_LEN,
	ML_DSA_65_SIGNATURE_LEN, ML_DSA_CONTEXT,
};
use ml_dsa::{
	signature::Keypair, EncodedVerifyingKey, MlDsa65, Seed, Signature, SigningKey, VerifyingKey,
};
use sp_runtime::AccountId32;

/// An ML-DSA-65 key pair.
pub struct MlDsa65Pair {
	signing_key: SigningKey<MlDsa65>,
	public: MlDsa65Public,
}

impl MlDsa65Pair {
	/// Key pair from a 32-byte FIPS 204 seed (`xi`).
	pub fn from_seed(seed: [u8; 32]) -> Self {
		let signing_key = SigningKey::<MlDsa65>::from_seed(&Seed::from(seed));
		let encoded = signing_key.verifying_key().encode();
		let mut public = [0u8; ML_DSA_65_PUBLIC_KEY_LEN];
		public.copy_from_slice(encoded.as_slice());
		Self { signing_key, public: MlDsa65Public(public) }
	}

	/// Key pair from a secret phrase, e.g. `//Alice`. The seed is `blake2_256(domain ++ phrase)`.
	///
	/// This is a development convenience, not a BIP-39 style derivation scheme.
	pub fn from_phrase(phrase: &str) -> Self {
		let mut input = b"canggu/ml-dsa-65/seed:".to_vec();
		input.extend_from_slice(phrase.as_bytes());
		Self::from_seed(sp_io::hashing::blake2_256(&input))
	}

	pub fn public(&self) -> MlDsa65Public {
		self.public.clone()
	}

	pub fn signer(&self) -> CangguSigner {
		CangguSigner::MlDsa65(self.public())
	}

	pub fn account_id(&self) -> AccountId32 {
		self.public.to_account_id()
	}

	/// Deterministic FIPS 204 signature with the Canggu context string.
	pub fn sign_raw(&self, msg: &[u8]) -> MlDsa65Signature {
		let signature = self
			.signing_key
			.expanded_key()
			.sign_deterministic(msg, ML_DSA_CONTEXT)
			.expect("context is shorter than 255 bytes; qed");
		let mut out = [0u8; ML_DSA_65_SIGNATURE_LEN];
		out.copy_from_slice(signature.encode().as_slice());
		MlDsa65Signature(out)
	}

	/// Sign and wrap into the runtime's transaction signature type.
	pub fn sign(&self, msg: &[u8]) -> CangguSignature {
		CangguSignature::MlDsa65 { public: self.public(), signature: self.sign_raw(msg) }
	}
}

/// Reference (CPU) ML-DSA-65 verification. Backs the `ml_dsa_65_verify` host function.
pub fn verify(public: &[u8], msg: &[u8], signature: &[u8]) -> bool {
	let Ok(public) = EncodedVerifyingKey::<MlDsa65>::try_from(public) else { return false };
	let Ok(signature) = Signature::<MlDsa65>::try_from(signature) else { return false };
	VerifyingKey::<MlDsa65>::decode(&public).verify_with_context(msg, ML_DSA_CONTEXT, &signature)
}

/// Development key pair for a well-known name (`Alice`, `Bob`...).
pub fn dev(name: &str) -> MlDsa65Pair {
	MlDsa65Pair::from_phrase(&format!("//{name}"))
}

/// Names of the pinned development accounts, matching [`crate::dev_accounts::all`].
pub const DEV_NAMES: [&str; 5] = ["Alice", "Bob", "Charlie", "Dave", "Eve"];

#[cfg(test)]
mod tests {
	use super::*;
	use sp_runtime::traits::{IdentifyAccount, Verify};

	#[test]
	fn sign_and_verify_roundtrip() {
		let pair = dev("Alice");
		let sig = pair.sign(b"hello canggu");
		assert!(sig.verify(&b"hello canggu"[..], &pair.account_id()));
		assert!(!sig.verify(&b"hello kuta"[..], &pair.account_id()));
		assert!(!sig.verify(&b"hello canggu"[..], &dev("Bob").account_id()));
		assert_eq!(pair.signer().into_account(), pair.account_id());
	}

	#[test]
	fn key_substitution_is_rejected() {
		// Bob signs, but claims to be Alice: the embedded key does not hash to Alice's account.
		let sig = dev("Bob").sign(b"payload");
		assert!(!sig.verify(&b"payload"[..], &dev("Alice").account_id()));
	}

	#[test]
	fn pinned_dev_accounts_match_keys() {
		let derived: Vec<AccountId32> = DEV_NAMES.iter().map(|n| dev(n).account_id()).collect();
		for (name, id) in DEV_NAMES.iter().zip(&derived) {
			println!(
				"pub const {}: [u8; 32] = {:?};",
				name.to_uppercase(),
				<[u8; 32]>::from(id.clone())
			);
		}
		assert_eq!(derived, crate::dev_accounts::all().to_vec());
	}
}
