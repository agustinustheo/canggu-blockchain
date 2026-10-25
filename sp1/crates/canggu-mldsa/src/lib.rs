//! Shared code of the canggu-sp1 guests and host.
//!
//! * [`verify`]: a self-contained ML-DSA-65 (FIPS 204) verifier, bit-exact with RustCrypto
//!   `ml-dsa` 0.1.1 `verify_with_context`; inside the SP1 zkVM its Keccak-f[1600] calls go to the
//!   SP1 precompile.
//! * [`batch`]: the `mldsa-batch` statement (input encoding and public values).
//! * [`payroll`]: the `payroll` statement (input encoding and public values).
//!
//! Everything here is `no_std` + `alloc` and has no SP1 dependency, so the same code runs in the
//! guest, on the host (to build inputs and expected public values) and could run in a runtime.

#![no_std]

extern crate alloc;

mod arith;
pub mod keccak;
pub mod params;
mod verify;

pub use keccak::keccak256;
pub use verify::verify;

/// Unkeyed BLAKE2b with 32-byte output (`sp_crypto_hashing::blake2_256`), the chain's account
/// derivation `AccountId = blake2_256(public_key)`.
pub fn blake2_256(data: &[u8]) -> [u8; 32] {
	use blake2::{digest::consts::U32, Blake2b, Digest};
	Blake2b::<U32>::digest(data).into()
}

/// A tiny cursor over an input blob; every read panics on truncated input, which inside the guest
/// aborts execution (and therefore makes proving impossible).
pub struct Reader<'a> {
	data: &'a [u8],
}

impl<'a> Reader<'a> {
	/// Read from `data`.
	pub fn new(data: &'a [u8]) -> Self {
		Self { data }
	}

	/// The next `len` bytes.
	pub fn bytes(&mut self, len: usize) -> &'a [u8] {
		assert!(len <= self.data.len(), "input truncated");
		let (head, tail) = self.data.split_at(len);
		self.data = tail;
		head
	}

	/// A little-endian `u32`.
	pub fn u32(&mut self) -> u32 {
		u32::from_le_bytes(self.bytes(4).try_into().expect("4 bytes"))
	}

	/// A `u32` length prefix followed by that many bytes.
	pub fn prefixed(&mut self) -> &'a [u8] {
		let len = self.u32() as usize;
		self.bytes(len)
	}

	/// Assert that the whole input was consumed.
	pub fn finish(self) {
		assert!(self.data.is_empty(), "trailing input");
	}
}

fn push_prefixed(out: &mut alloc::vec::Vec<u8>, bytes: &[u8]) {
	out.extend_from_slice(&u32::try_from(bytes.len()).expect("< 4 GiB").to_le_bytes());
	out.extend_from_slice(bytes);
}

/// The `mldsa-batch` statement.
///
/// Guest input (one `read_vec` blob, all integers little-endian):
///
/// ```text
/// ctx_len: u32 | ctx | n: u32 | n x ( pk_len: u32 | pk | msg_len: u32 | msg | sig_len: u32 | sig )
/// ```
///
/// Public values (68 bytes):
///
/// ```text
/// n: u32 LE | keccak256(ctx) | keccak256( concat_i( blake2_256(pk_i) | keccak256(msg_i) ) )
/// ```
pub mod batch {
	use super::*;
	use alloc::vec::Vec;

	/// Length of the public values.
	pub const PUBLIC_VALUES_BYTES: usize = 4 + 32 + 32;

	/// Encode the guest input.
	pub fn encode_input<P, M, S>(ctx: &[u8], items: &[(P, M, S)]) -> Vec<u8>
	where
		P: AsRef<[u8]>,
		M: AsRef<[u8]>,
		S: AsRef<[u8]>,
	{
		let mut out = Vec::with_capacity(
			8 + ctx.len()
				+ items
					.iter()
					.map(|(p, m, s)| 12 + p.as_ref().len() + m.as_ref().len() + s.as_ref().len())
					.sum::<usize>(),
		);
		push_prefixed(&mut out, ctx);
		out.extend_from_slice(&u32::try_from(items.len()).expect("< 2^32 items").to_le_bytes());
		for (pk, msg, sig) in items {
			push_prefixed(&mut out, pk.as_ref());
			push_prefixed(&mut out, msg.as_ref());
			push_prefixed(&mut out, sig.as_ref());
		}
		out
	}

	/// Incremental computation of the public values from `(account, keccak256(msg))` pairs.
	pub struct Digest {
		n: u32,
		ctx_hash: [u8; 32],
		sponge: crate::keccak::Sponge,
	}

	impl Digest {
		/// Start with the context string.
		pub fn new(ctx: &[u8]) -> Self {
			Self { n: 0, ctx_hash: keccak256(ctx), sponge: crate::keccak::Sponge::keccak256() }
		}

		/// Append one entry. `account = blake2_256(pk)`.
		pub fn push(&mut self, account: &[u8; 32], msg_hash: &[u8; 32]) {
			self.n = self.n.checked_add(1).expect("< 2^32 items");
			self.sponge.absorb(account).absorb(msg_hash);
		}

		/// The final public values.
		pub fn finish(self) -> [u8; PUBLIC_VALUES_BYTES] {
			let mut out = [0u8; PUBLIC_VALUES_BYTES];
			out[..4].copy_from_slice(&self.n.to_le_bytes());
			out[4..36].copy_from_slice(&self.ctx_hash);
			out[36..].copy_from_slice(&self.sponge.finish32());
			out
		}
	}

	/// The public values a runtime expects, from what it knows: the context, each signer's
	/// `AccountId` (`blake2_256(pk)`) and each message, in proof order.
	pub fn expected_public_values<M: AsRef<[u8]>>(
		ctx: &[u8],
		accounts: &[[u8; 32]],
		msgs: &[M],
	) -> [u8; PUBLIC_VALUES_BYTES] {
		assert_eq!(accounts.len(), msgs.len(), "one message per account");
		let mut d = Digest::new(ctx);
		for (account, msg) in accounts.iter().zip(msgs) {
			d.push(account, &keccak256(msg.as_ref()));
		}
		d.finish()
	}

	/// The guest: parse `input`, verify every signature (panicking on the first invalid one) and
	/// return the public values. Exposed so that the host can run the exact guest logic natively.
	pub fn run(input: &[u8]) -> [u8; PUBLIC_VALUES_BYTES] {
		let mut r = Reader::new(input);
		let ctx = r.prefixed();
		let n = r.u32();
		let mut d = Digest::new(ctx);
		for i in 0..n {
			let pk = r.prefixed();
			let msg = r.prefixed();
			let sig = r.prefixed();
			if !verify(pk, msg, sig, ctx) {
				panic!("invalid ML-DSA-65 signature at index {i}");
			}
			d.push(&blake2_256(pk), &keccak256(msg));
		}
		r.finish();
		d.finish()
	}
}

/// The `payroll` statement: "I know `salt` and `amounts` that sum to `total` and whose Keccak-256
/// commitment is `commitment`".
///
/// Guest input (one `read_vec` blob): `salt: [u8; 32] | n: u32 LE | n x amount: u64 LE`.
///
/// Public values (52 bytes): `n: u32 LE | total: u128 LE | commitment`, where
/// `commitment = keccak256(salt | amount_1 as u64 LE | .. | amount_n as u64 LE)`.
pub mod payroll {
	use super::*;
	use alloc::vec::Vec;

	/// Length of the public values.
	pub const PUBLIC_VALUES_BYTES: usize = 4 + 16 + 32;

	/// Encode the guest input.
	pub fn encode_input(salt: &[u8; 32], amounts: &[u64]) -> Vec<u8> {
		let mut out = Vec::with_capacity(36 + 8 * amounts.len());
		out.extend_from_slice(salt);
		out.extend_from_slice(&u32::try_from(amounts.len()).expect("< 2^32").to_le_bytes());
		for a in amounts {
			out.extend_from_slice(&a.to_le_bytes());
		}
		out
	}

	/// The public values for `(salt, amounts)`.
	pub fn public_values(salt: &[u8; 32], amounts: &[u64]) -> [u8; PUBLIC_VALUES_BYTES] {
		run(&encode_input(salt, amounts))
	}

	/// The guest: parse `input`, sum with overflow checks and commit.
	pub fn run(input: &[u8]) -> [u8; PUBLIC_VALUES_BYTES] {
		let mut r = Reader::new(input);
		let salt = r.bytes(32);
		let n = r.u32();
		let amounts = r.bytes(8 * n as usize);
		r.finish();

		let mut total: u128 = 0;
		for a in amounts.chunks_exact(8) {
			let a = u64::from_le_bytes(a.try_into().expect("8 bytes"));
			// Cannot overflow for n < 2^64, but the check is one branch and documents intent.
			total = total.checked_add(u128::from(a)).expect("total overflows u128");
		}
		// The amounts are already laid out as u64 LE, so the commitment hashes them in place.
		let mut h = crate::keccak::Sponge::keccak256();
		h.absorb(salt).absorb(amounts);

		let mut out = [0u8; PUBLIC_VALUES_BYTES];
		out[..4].copy_from_slice(&n.to_le_bytes());
		out[4..20].copy_from_slice(&total.to_le_bytes());
		out[20..].copy_from_slice(&h.finish32());
		out
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn blake2_256_known_vector() {
		// blake2_256(b"") as used by sp_crypto_hashing.
		let want = [
			0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2, 0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99,
			0xda, 0xa1, 0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87, 0xfa, 0xab, 0x45, 0xcd,
			0xf1, 0x2f, 0xe3, 0xa8,
		];
		assert_eq!(blake2_256(b""), want);
	}

	#[test]
	fn payroll_layout() {
		let salt = [9u8; 32];
		let amounts = [1u64, u64::MAX, 7];
		let pv = payroll::public_values(&salt, &amounts);
		assert_eq!(&pv[..4], &3u32.to_le_bytes());
		assert_eq!(&pv[4..20], &(u128::from(u64::MAX) + 8).to_le_bytes());
		let mut pre = salt.to_vec();
		for a in amounts {
			pre.extend_from_slice(&a.to_le_bytes());
		}
		assert_eq!(&pv[20..], &keccak256(&pre));
	}
}
