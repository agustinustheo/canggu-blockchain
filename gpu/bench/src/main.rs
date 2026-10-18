//! Throughput comparison: RustCrypto `ml-dsa` (one thread / all cores) vs `MetalVerifier`.
//!
//! Every verifier starts from raw bytes (public key, message, signature), which is what a
//! runtime host function receives: for `ml-dsa` that includes `VerifyingKey::decode` (which
//! expands A) and `Signature::try_from`; for Metal it includes CPU pre-processing, upload,
//! GPU execution and read-back.
//!
//! Run with `cargo run --release --bin bench`.

use canggu_gpu::{BatchStats, Item, MetalVerifier};
use ml_dsa::{
	signature::Keypair, EncodedVerifyingKey, MlDsa65, Seed, Signature, SigningKey, VerifyingKey,
};
use rayon::prelude::*;
use std::time::{Duration, Instant};

const CTX: &[u8] = b"canggu/tx/v1";
const BATCH_SIZES: [usize; 6] = [1, 16, 64, 256, 1024, 4096];
const NUM_KEYS: usize = 512;
/// Minimum measured wall time per (verifier, batch size) cell.
const MIN_MEASURE: Duration = Duration::from_millis(500);
const MIN_RUNS: usize = 5;

fn ml_dsa_verify(item: &Item) -> bool {
	let Ok(enc) = EncodedVerifyingKey::<MlDsa65>::try_from(item.public) else {
		return false;
	};
	let vk = VerifyingKey::<MlDsa65>::decode(&enc);
	let Ok(sig) = Signature::<MlDsa65>::try_from(item.signature) else {
		return false;
	};
	vk.verify_with_context(item.msg, CTX, &sig)
}

/// Run `f` repeatedly; return the median duration and the output of the median run.
fn measure<T>(mut f: impl FnMut() -> T) -> (Duration, T) {
	let _ = f(); // warm-up
	let mut runs = Vec::new();
	let start = Instant::now();
	while runs.len() < MIN_RUNS || start.elapsed() < MIN_MEASURE {
		let t = Instant::now();
		let out = f();
		runs.push((t.elapsed(), out));
	}
	runs.sort_by_key(|r| r.0);
	let mid = runs.len() / 2;
	runs.swap_remove(mid)
}

fn per_sec(n: usize, d: Duration) -> f64 {
	n as f64 / d.as_secs_f64()
}

fn ms(d: Duration) -> f64 {
	d.as_secs_f64() * 1e3
}

fn main() {
	let max = *BATCH_SIZES.iter().max().expect("non-empty");
	eprintln!("generating {max} signatures from {NUM_KEYS} keys ...");
	let keys: Vec<_> = (0..NUM_KEYS as u64)
		.map(|i| {
			let mut seed = [0u8; 32];
			seed[..8].copy_from_slice(&i.to_le_bytes());
			seed[8] = 0xB3;
			let sk = SigningKey::<MlDsa65>::from_seed(&Seed::from(seed));
			let pk = sk.verifying_key().encode().to_vec();
			(sk, pk)
		})
		.collect();
	let data: Vec<(usize, Vec<u8>, Vec<u8>)> = (0..max)
		.into_par_iter()
		.map(|i| {
			let k = i % NUM_KEYS;
			let len = (i * 7919) % 1000;
			let msg: Vec<u8> = (0..len).map(|j| (i * 31 + j * 17) as u8).collect();
			let sig = keys[k].0.expanded_key().sign_deterministic(&msg, CTX).expect("ctx ok");
			(k, msg, sig.encode().to_vec())
		})
		.collect();
	let items: Vec<Item> = data
		.iter()
		.map(|(k, msg, sig)| Item { public: &keys[*k].1, msg, signature: sig })
		.collect();

	let metal = match MetalVerifier::new() {
		Ok(m) => Some(m),
		Err(e) => {
			eprintln!("Metal unavailable: {e}");
			None
		},
	};
	let threads = rayon::current_num_threads();
	println!(
		"ML-DSA-65 batch verification, ctx = {:?}, {threads} rayon threads",
		String::from_utf8_lossy(CTX)
	);
	println!("Metal device: {}", metal.as_ref().map_or("<none>".into(), |m| m.device_name()));
	println!("All timings are medians of >= {MIN_RUNS} runs (>= {MIN_MEASURE:?} per cell).\n");
	println!(
		"{:>6} | {:>18} | {:>18} | {:>18} | {:>9} | {:>9} | {:>5} | {:>7}",
		"batch",
		"ml-dsa 1 thread",
		format!("ml-dsa {threads} threads"),
		"Metal (wall)",
		"Metal prep",
		"GPU time",
		"cmdbf",
		"vs best"
	);
	println!(
		"{:>6} | {:>18} | {:>18} | {:>18} | {:>9} | {:>9} | {:>5} | {:>7}",
		"", "ms  (sig/s)", "ms  (sig/s)", "ms  (sig/s)", "ms", "ms", "", "CPU"
	);
	println!("{}", "-".repeat(113));

	let mut gpu_evidence: Vec<(usize, BatchStats)> = Vec::new();
	for &n in &BATCH_SIZES {
		let batch = &items[..n];
		let (st, r1) = measure(|| batch.iter().map(ml_dsa_verify).collect::<Vec<_>>());
		let (mt, r2) = measure(|| batch.par_iter().map(ml_dsa_verify).collect::<Vec<_>>());
		assert!(r1.iter().all(|v| *v) && r2.iter().all(|v| *v), "ml-dsa rejected a signature");
		let cell = |d: Duration| format!("{:>8.3} ({:>7.0})", ms(d), per_sec(n, d));
		let metal_cols = match &metal {
			Some(m) => {
				let (wall, (r3, stats)) = measure(|| m.verify_batch_with_stats(batch, CTX));
				assert!(r3.iter().all(|v| *v), "Metal rejected a valid signature");
				assert_eq!(stats.cpu_fallback_jobs, 0, "Metal fell back to the CPU");
				gpu_evidence.push((n, stats));
				let speedup = st.min(mt).as_secs_f64() / wall.as_secs_f64();
				format!(
					"{} | {:>9.3} | {:>9.3} | {:>5} | {:>6.2}x",
					cell(wall),
					ms(stats.prepare),
					ms(stats.gpu),
					stats.command_buffers,
					speedup
				)
			},
			None => "n/a".into(),
		};
		println!("{n:>6} | {} | {} | {metal_cols}", cell(st), cell(mt));
	}

	// Context: what ml-dsa achieves if the node caches decoded (A-expanded) verifying keys.
	let n = max;
	let decoded: Vec<_> = keys
		.iter()
		.map(|(_, pk)| {
			let enc = EncodedVerifyingKey::<MlDsa65>::try_from(pk.as_slice()).expect("1952");
			VerifyingKey::<MlDsa65>::decode(&enc)
		})
		.collect();
	let (cached, _) = measure(|| {
		data.par_iter()
			.map(|(k, msg, sig)| {
				let sig = Signature::<MlDsa65>::try_from(sig.as_slice()).expect("valid");
				decoded[*k].verify_with_context(msg, CTX, &sig)
			})
			.collect::<Vec<_>>()
	});
	println!(
		"\nFor reference: ml-dsa on {threads} threads with pre-decoded verifying keys (no ExpandA \
		 per item): {n} sigs in {:.3} ms = {:.0} sig/s",
		ms(cached),
		per_sec(n, cached)
	);

	if let Some(m) = &metal {
		println!(
			"\nGPU execution evidence ({}), from MTLCommandBuffer GPUStartTime/GPUEndTime:",
			m.device_name()
		);
		for (n, s) in &gpu_evidence {
			println!(
				"  batch {n:>5}: {} command buffer(s), {} jobs on GPU, GPU busy {:.3} ms \
				 ({:.2} us/sig), CPU prep {:.3} ms, total wall {:.3} ms",
				s.command_buffers,
				s.gpu_jobs,
				ms(s.gpu),
				ms(s.gpu) * 1e3 / *n as f64,
				ms(s.prepare),
				ms(s.total)
			);
		}
		println!("\nPer-kernel GPU time (one command buffer per kernel, diagnostics only):");
		for &n in &[1, 256, 4096] {
			// Median of several profiled runs.
			let mut runs: Vec<Vec<(&str, Duration)>> =
				(0..7).filter_map(|_| m.profile_kernels(&items[..n], CTX)).collect();
			runs.sort_by_key(|r| r.iter().map(|k| k.1).sum::<Duration>());
			let Some(run) = runs.get(runs.len() / 2) else {
				continue;
			};
			let cols: Vec<String> =
				run.iter().map(|(name, d)| format!("{name} {:.3} ms", ms(*d))).collect();
			println!("  batch {n:>5}: {}", cols.join(", "));
		}
	}
}
