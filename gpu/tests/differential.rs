//! Differential tests: `MetalVerifier::verify_batch` vs `verify_batch_reference` vs RustCrypto
//! `ml-dsa` (`VerifyingKey::<MlDsa65>::verify_with_context`) on valid and malformed inputs.
//!
//! Run with `cargo test --release -- --nocapture` to see the per-category counts.

use canggu_gpu::{verify_batch_reference, Item, MetalVerifier};
use ml_dsa::{
	signature::Keypair, EncodedVerifyingKey, MlDsa65, Seed, Signature, SigningKey, VerifyingKey,
};
use std::{collections::BTreeMap, sync::OnceLock};

const CTX: &[u8] = b"canggu/tx/v1";
const PK_LEN: usize = 1952;
const SIG_LEN: usize = 3309;
const CTILDE: usize = 48;
const Z_LEN: usize = 3200;
const HINT: usize = CTILDE + Z_LEN;
const OMEGA: usize = 55;
const K: usize = 6;
const GAMMA1: u32 = 1 << 19;
const BETA: u32 = 196;

const NUM_KEYS: usize = 256;
const NUM_VALID: usize = 2304;

/// SplitMix64: tiny deterministic PRNG so the test corpus is reproducible without extra deps.
struct Rng(u64);

impl Rng {
	fn next(&mut self) -> u64 {
		self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
		let mut z = self.0;
		z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
		z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
		z ^ (z >> 31)
	}
	fn below(&mut self, n: usize) -> usize {
		(self.next() % n as u64) as usize
	}
	fn bytes(&mut self, len: usize) -> Vec<u8> {
		(0..len).map(|_| self.next() as u8).collect()
	}
}

/// An owned test vector.
#[derive(Clone)]
struct Case {
	category: &'static str,
	public: Vec<u8>,
	msg: Vec<u8>,
	signature: Vec<u8>,
	/// What a correct verifier must return.
	expect: bool,
}

impl Case {
	fn item(&self) -> Item<'_> {
		Item { public: &self.public, msg: &self.msg, signature: &self.signature }
	}
}

struct Key {
	sk: SigningKey<MlDsa65>,
	pk: Vec<u8>,
}

fn keys() -> &'static [Key] {
	static KEYS: OnceLock<Vec<Key>> = OnceLock::new();
	KEYS.get_or_init(|| {
		let mut rng = Rng(1);
		(0..NUM_KEYS)
			.map(|_| {
				let mut seed = [0u8; 32];
				seed.copy_from_slice(&rng.bytes(32));
				let sk = SigningKey::<MlDsa65>::from_seed(&Seed::from(seed));
				let pk = sk.verifying_key().encode().to_vec();
				Key { sk, pk }
			})
			.collect()
	})
}

fn sign(key: &Key, msg: &[u8], ctx: &[u8]) -> Vec<u8> {
	key.sk
		.expanded_key()
		.sign_deterministic(msg, ctx)
		.expect("ctx <= 255")
		.encode()
		.to_vec()
}

/// Valid signatures under `ctx` from many keys with message lengths spread over 0..1000.
fn valid_cases(n: usize, ctx: &[u8], seed: u64) -> Vec<Case> {
	let mut rng = Rng(seed);
	(0..n)
		.map(|i| {
			let key = &keys()[(i * 7 + seed as usize) % NUM_KEYS];
			let len = match i % 50 {
				0 => 0,
				1 => 999,
				_ => rng.below(1000),
			};
			let msg = rng.bytes(len);
			let signature = sign(key, &msg, ctx);
			Case { category: "valid", public: key.pk.clone(), msg, signature, expect: true }
		})
		.collect()
}

/// The hint section `y` (omega index bytes followed by k cut bytes) of a signature.
fn hint(sig: &mut [u8]) -> &mut [u8] {
	&mut sig[HINT..HINT + OMEGA + K]
}

/// Overwrite the 20-bit z field number `m` (0 .. 5 * 256) with `v`.
fn set_z_field(sig: &mut [u8], m: usize, v: u32) {
	let z = &mut sig[CTILDE..HINT];
	for b in 0..20 {
		let bit = m * 20 + b;
		let mask = 1u8 << (bit % 8);
		if (v >> b) & 1 == 1 {
			z[bit / 8] |= mask;
		} else {
			z[bit / 8] &= !mask;
		}
	}
}

fn flip_bit(bytes: &mut [u8], bit: usize) {
	bytes[bit / 8] ^= 1 << (bit % 8);
}

/// Malformed or forged variants of the valid cases (all signed under [`CTX`]).
fn invalid_cases(valid: &[Case], rng: &mut Rng) -> Vec<Case> {
	let mut out = Vec::new();
	let pick = |rng: &mut Rng| valid[rng.below(valid.len())].clone();
	let mut push = |mut c: Case, category: &'static str| {
		c.category = category;
		c.expect = false;
		out.push(c);
	};

	for _ in 0..150 {
		let mut c = pick(rng);
		flip_bit(&mut c.signature, rng.below(CTILDE * 8));
		push(c, "sig bit flip: c~");
	}
	for _ in 0..250 {
		let mut c = pick(rng);
		flip_bit(&mut c.signature, CTILDE * 8 + rng.below(Z_LEN * 8));
		push(c, "sig bit flip: z");
	}
	for _ in 0..150 {
		let mut c = pick(rng);
		flip_bit(&mut c.signature, HINT * 8 + rng.below((OMEGA + K) * 8));
		push(c, "sig bit flip: hint");
	}
	for _ in 0..100 {
		let mut c = pick(rng);
		flip_bit(&mut c.public, rng.below(32 * 8));
		push(c, "pk bit flip: rho");
	}
	for _ in 0..200 {
		let mut c = pick(rng);
		flip_bit(&mut c.public, 32 * 8 + rng.below((PK_LEN - 32) * 8));
		push(c, "pk bit flip: t1");
	}
	for _ in 0..200 {
		let mut c = pick(rng);
		if c.msg.is_empty() {
			c.msg.push(rng.next() as u8);
		} else {
			let bit = rng.below(c.msg.len() * 8);
			flip_bit(&mut c.msg, bit);
		}
		push(c, "msg bit flip");
	}
	for _ in 0..50 {
		let mut c = pick(rng);
		c.msg.push(0);
		push(c, "msg extended");
	}
	// Wrong lengths.
	for i in 0..250 {
		let mut c = pick(rng);
		match i % 7 {
			0 => c.signature.truncate(SIG_LEN - 1),
			1 => c.signature.push(0),
			2 => c.signature.truncate(rng.below(SIG_LEN)),
			3 => c.public.truncate(PK_LEN - 1),
			4 => c.public.push(0),
			5 => c.public.truncate(rng.below(PK_LEN)),
			_ => c.signature.clear(),
		}
		push(c, "wrong length");
	}
	// Hint encoding corruption (rejected by sigDecode) and re-encoded different hints (which
	// decode fine but must fail the final hash comparison).
	let mut produced = 0;
	while produced < 400 {
		let mut c = pick(rng);
		let variant = produced % 5;
		let y = hint(&mut c.signature);
		let cuts: Vec<usize> = y[OMEGA..].iter().map(|&b| b as usize).collect();
		let total = cuts[K - 1];
		let category = match variant {
			0 => {
				// Cut beyond omega.
				y[OMEGA + rng.below(K)] = (OMEGA + 1 + rng.below(200)) as u8;
				"hint: cut > omega"
			},
			1 => {
				// Non-monotonic cuts.
				let i = 1 + rng.below(K - 1);
				if cuts[i - 1] == 0 {
					y[OMEGA + i - 1] = 1;
				}
				y[OMEGA + i] = y[OMEGA + i - 1] - 1;
				"hint: decreasing cuts"
			},
			2 => {
				// Non-increasing indices within a polynomial.
				let Some(i) = (0..K).find(|&i| {
					let start = if i == 0 { 0 } else { cuts[i - 1] };
					cuts[i] - start >= 2
				}) else {
					continue;
				};
				let start = if i == 0 { 0 } else { cuts[i - 1] };
				y[start + 1] = y[start];
				"hint: repeated index"
			},
			3 => {
				// Non-zero padding after the last index.
				if total >= OMEGA {
					continue;
				}
				y[total + rng.below(OMEGA - total)] = 1 + rng.below(255) as u8;
				"hint: non-zero padding"
			},
			_ => {
				// Well-formed but different hint: drop the last hint bit of the last
				// non-empty polynomial.
				if total == 0 {
					continue;
				}
				y[total - 1] = 0;
				let i = (0..K).find(|&i| cuts[i] == total).expect("total is a cut");
				for cut in &mut y[OMEGA + i..] {
					*cut -= 1;
				}
				"hint: valid encoding, wrong hint"
			},
		};
		push(c, category);
		produced += 1;
	}
	// z coefficients out of range (rejected) and at the inclusive edge (decodes, but forged).
	for i in 0..300 {
		let mut c = pick(rng);
		let m = rng.below(5 * 256);
		let (v, category) = match i % 6 {
			0 => (0, "z: +gamma1"),
			1 => ((1 << 20) - 1, "z: -(gamma1 - 1)"),
			2 => (BETA, "z: +(gamma1 - beta)"),
			3 => (2 * GAMMA1 - BETA, "z: -(gamma1 - beta)"),
			4 => (BETA + 1, "z: +(gamma1 - beta - 1), forged"),
			_ => (rng.below(BETA as usize) as u32, "z: random out of range"),
		};
		set_z_field(&mut c.signature, m, v);
		push(c, category);
	}
	for _ in 0..100 {
		let mut c = pick(rng);
		c.signature = rng.bytes(SIG_LEN);
		push(c, "random signature bytes");
	}
	for _ in 0..100 {
		let a = pick(rng);
		let mut c = pick(rng);
		if a.msg == c.msg {
			c.msg.push(1);
		}
		c.signature = a.signature;
		push(c, "signature from other message");
	}
	for _ in 0..100 {
		let mut c = pick(rng);
		let other = &keys()[rng.below(NUM_KEYS)];
		if other.pk == c.public {
			continue;
		}
		c.public = other.pk.clone();
		push(c, "public key of other signer");
	}
	out
}

/// RustCrypto `ml-dsa` as the oracle.
fn ml_dsa_verify(item: &Item, ctx: &[u8]) -> bool {
	let Ok(enc) = EncodedVerifyingKey::<MlDsa65>::try_from(item.public) else {
		return false;
	};
	let vk = VerifyingKey::<MlDsa65>::decode(&enc);
	let Ok(sig) = Signature::<MlDsa65>::try_from(item.signature) else {
		return false;
	};
	vk.verify_with_context(item.msg, ctx, &sig)
}

fn metal() -> Option<&'static MetalVerifier> {
	static METAL: OnceLock<Option<MetalVerifier>> = OnceLock::new();
	METAL
		.get_or_init(|| match MetalVerifier::new() {
			Ok(m) => Some(m),
			Err(e) => {
				if cfg!(target_os = "macos") {
					panic!("Metal must be available on macOS: {e}");
				}
				eprintln!("Metal unavailable ({e}); comparing reference vs ml-dsa only");
				None
			},
		})
		.as_ref()
}

#[derive(Default)]
struct Tally {
	total: usize,
	accepted: usize,
}

/// Verify `cases` under `ctx` with all three implementations and assert full agreement.
/// The Metal verifier sees the cases both as one batch and split into irregular sub-batches.
fn check(cases: &[Case], ctx: &[u8], tallies: &mut BTreeMap<String, Tally>) {
	let items: Vec<Item> = cases.iter().map(Case::item).collect();
	let oracle: Vec<bool> = items.iter().map(|i| ml_dsa_verify(i, ctx)).collect();
	let reference = verify_batch_reference(&items, ctx);
	let gpu = metal().map(|m| {
		let (whole, stats) = m.verify_batch_with_stats(&items, ctx);
		// The results must come from the GPU, not from the CPU fallback path.
		assert_eq!(stats.cpu_fallback_jobs, 0);
		assert!(stats.command_buffers >= 1 || whole.iter().all(|v| !v));
		let mut split = Vec::new();
		let mut rest = &items[..];
		let mut rng = Rng(items.len() as u64);
		while !rest.is_empty() {
			let take = (1 + rng.below(300)).min(rest.len());
			split.extend(m.verify_batch(&rest[..take], ctx));
			rest = &rest[take..];
		}
		assert_eq!(whole, split, "Metal result depends on batch composition");
		whole
	});

	for (k, case) in cases.iter().enumerate() {
		let what = format!("case {k} ({}, ctx len {})", case.category, ctx.len());
		assert_eq!(reference[k], oracle[k], "reference vs ml-dsa: {what}");
		if let Some(gpu) = &gpu {
			assert_eq!(gpu[k], oracle[k], "Metal vs ml-dsa: {what}");
		}
		let expect = case.expect && ctx.len() <= 255;
		assert_eq!(oracle[k], expect, "unexpected verdict: {what}");
		let t = tallies.entry(format!("{:<5} {}", oracle[k], case.category)).or_default();
		t.total += 1;
		t.accepted += usize::from(oracle[k]);
	}
}

#[test]
fn differential_valid_and_invalid() {
	let mut tallies = BTreeMap::new();
	let valid = valid_cases(NUM_VALID, CTX, 42);
	let mut rng = Rng(7);
	let invalid = invalid_cases(&valid, &mut rng);

	// The production context: valid and invalid cases mixed in one batch (> 4096 items, so the
	// Metal verifier needs more than one command buffer).
	let mut mixed: Vec<Case> = valid.iter().chain(&invalid).cloned().collect();
	for i in (1..mixed.len()).rev() {
		mixed.swap(i, rng.below(i + 1));
	}
	check(&mixed, CTX, &mut tallies);

	// Wrong contexts for correct signatures.
	let mut wrong: Vec<Case> = valid[..300].to_vec();
	for c in &mut wrong {
		c.category = "wrong ctx";
		c.expect = false;
	}
	check(&wrong, b"canggu/tx/v2", &mut tallies);
	check(&wrong[..100], b"", &mut tallies);
	for c in &mut wrong {
		c.category = "ctx > 255 bytes";
	}
	check(&wrong[..100], &[b'x'; 256], &mut tallies);
	check(&wrong[100..200], &[0u8; 1000], &mut tallies);

	// Other valid contexts: empty and the maximum length.
	let ctx255 = [0xA5u8; 255];
	let mut other_ctx = valid_cases(100, b"", 1001);
	check(&other_ctx, b"", &mut tallies);
	other_ctx = valid_cases(100, &ctx255, 1002);
	check(&other_ctx, &ctx255, &mut tallies);

	let (mut n_valid, mut n_invalid) = (0, 0);
	eprintln!("\n{:<7}{:<46}{:>7}", "result", "category", "count");
	for (k, t) in &tallies {
		eprintln!("{k:<53}{:>7}", t.total);
		if k.starts_with("true") {
			n_valid += t.total;
		} else {
			n_invalid += t.total;
		}
	}
	eprintln!(
		"three-way agreement on {} items: {n_valid} valid (all accepted), {n_invalid} invalid \
		 (all rejected); Metal compared: {}",
		n_valid + n_invalid,
		metal().is_some()
	);
	assert!(n_valid >= 2000 && n_invalid >= 2000);
}

/// Exhaustive / randomised comparison of the GPU building blocks with their Rust twins,
/// including edge cases (e.g. `UseHint` with `r0 = 0`) that real signatures never reach.
#[test]
fn gpu_self_test() {
	let Some(m) = metal() else { return };
	let t = std::time::Instant::now();
	m.self_test().expect("GPU self-test");
	eprintln!("GPU self-test passed in {:?}", t.elapsed());
}

#[test]
fn concurrent_use_from_many_threads() {
	let Some(m) = metal() else { return };
	let cases = valid_cases(256, CTX, 99);
	let mut rng = Rng(3);
	let mut all = cases.clone();
	all.extend(invalid_cases(&cases, &mut rng).into_iter().take(256));
	let items: Vec<Item> = all.iter().map(Case::item).collect();
	let want = verify_batch_reference(&items, CTX);
	std::thread::scope(|s| {
		for t in 0..8 {
			let (items, want) = (&items, &want);
			s.spawn(move || {
				for round in 0..4 {
					let lo = (t * 37 + round * 101) % items.len();
					let hi = (lo + 64 + t * 13).min(items.len());
					assert_eq!(m.verify_batch(&items[lo..hi], CTX), want[lo..hi]);
				}
			});
		}
	});
}

#[test]
fn empty_and_single_item_batches() {
	let cases = valid_cases(1, CTX, 5);
	let items: Vec<Item> = cases.iter().map(Case::item).collect();
	assert_eq!(verify_batch_reference(&[], CTX), Vec::<bool>::new());
	assert_eq!(verify_batch_reference(&items, CTX), vec![true]);
	if let Some(m) = metal() {
		assert!(m.verify_batch(&[], CTX).is_empty());
		assert_eq!(m.verify_batch(&items, CTX), vec![true]);
		assert_eq!(m.verify_batch(&items, b"other"), vec![false]);
		assert!(!m.device_name().is_empty());
	}
}
