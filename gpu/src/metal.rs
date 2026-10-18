//! Metal host code: device setup, buffer management and command encoding.

use crate::{
	arith,
	params::{K, L, N, Q, W1_BYTES},
	prepare::JOB_BYTES,
	prepare_jobs, reference, shader, BatchStats, Error, Item,
};
use objc2::{rc::Retained, runtime::ProtocolObject};
use objc2_foundation::NSString;
use objc2_metal::{
	MTLBuffer, MTLCommandBuffer, MTLCommandBufferStatus, MTLCommandEncoder, MTLCommandQueue,
	MTLComputeCommandEncoder, MTLComputePipelineState, MTLCreateSystemDefaultDevice, MTLDevice,
	MTLLibrary, MTLResourceOptions, MTLSize,
};
use std::{
	ops::Range,
	ptr::NonNull,
	sync::Mutex,
	time::{Duration, Instant},
};

/// Maximum number of jobs resident on the GPU at once. Larger batches are processed in chunks
/// that reuse the same scratch buffers; this bounds GPU memory to roughly
/// `MAX_JOBS_PER_SUBMISSION * 52 KiB` (about 210 MiB).
pub const MAX_JOBS_PER_SUBMISSION: usize = 4096;

/// A chunk is split into at most this many sub-batches, each with its own command buffer, so
/// that CPU pre-processing of sub-batch `k + 1` overlaps GPU execution of sub-batch `k`.
const PIPELINE_DEPTH: usize = 4;
/// Do not split below this many jobs per sub-batch: each command buffer has a fixed latency of
/// roughly 0.2 ms (the sequential SHAKE chains of a single job), which must be amortised.
const MIN_SUB_BATCH: usize = 512;

/// Threads per threadgroup for the cooperative NTT kernels (one butterfly per thread).
const NTT_THREADS: usize = N / 2;
/// Preferred threads per threadgroup for the one-thread-per-item kernels.
const FLAT_THREADS: usize = 64;

type Buffer = Retained<ProtocolObject<dyn MTLBuffer>>;
type Pipeline = Retained<ProtocolObject<dyn MTLComputePipelineState>>;
type CommandBuffer = Retained<ProtocolObject<dyn MTLCommandBuffer>>;

/// Shared-storage buffers sized for `capacity` jobs. Job `i` of a buffer with per-job size
/// `stride` lives at byte offset `i * stride`.
struct Scratch {
	capacity: usize,
	/// Job records written by the CPU (stage 1).
	jobs: Buffer,
	/// `NTT(z)` in Montgomery form, `L` polynomials per job.
	z_hat: Buffer,
	/// `NTT(t1 * 2^d)`, `K` polynomials per job.
	t1_hat: Buffer,
	/// `NTT(c)` in Montgomery form, one polynomial per job.
	c_hat: Buffer,
	/// `A_hat[i][j] o z_hat[j]`, `K * L` polynomials per job.
	prod: Buffer,
	/// `w1Encode(w1')`, `W1_BYTES` per job.
	w1: Buffer,
	/// One `u32` verdict per job.
	results: Buffer,
}

const U32: usize = std::mem::size_of::<u32>();
const Z_HAT_STRIDE: usize = L * N * U32;
const T1_HAT_STRIDE: usize = K * N * U32;
const C_HAT_STRIDE: usize = N * U32;
const PROD_STRIDE: usize = K * L * N * U32;

// SAFETY: Metal buffers are reference-counted Objective-C objects that may be used from any
// thread. `Scratch` is only ever accessed while holding `MetalVerifier::scratch`'s mutex.
unsafe impl Send for Scratch {}

impl Scratch {
	/// The job records `range` as a mutable byte slice.
	///
	/// # Safety
	///
	/// `range.end <= self.capacity`, no command buffer that may read these records is in
	/// flight, and no other live slice overlaps `range`.
	// The buffer contents are not owned by `self` in the Rust sense (they are GPU-shared
	// memory behind an Objective-C object); exclusivity is part of the safety contract.
	#[allow(clippy::mut_from_ref)]
	unsafe fn jobs_mut(&self, range: Range<usize>) -> &mut [u8] {
		let base = self.jobs.contents().as_ptr().cast::<u8>();
		// SAFETY: guaranteed by the caller; the buffer holds `capacity * JOB_BYTES` bytes.
		unsafe {
			std::slice::from_raw_parts_mut(
				base.add(range.start * JOB_BYTES),
				range.len() * JOB_BYTES,
			)
		}
	}

	/// The verdicts of jobs `range`.
	///
	/// # Safety
	///
	/// `range.end <= self.capacity` and the command buffer that wrote them has completed.
	unsafe fn results(&self, range: Range<usize>) -> &[u32] {
		let base = self.results.contents().as_ptr().cast::<u32>();
		// SAFETY: guaranteed by the caller; the buffer holds `capacity` u32 values.
		unsafe { std::slice::from_raw_parts(base.add(range.start), range.len()) }
	}
}

/// A sub-batch whose command buffer may still be running.
struct InFlight {
	range: Range<usize>,
	valid: Vec<bool>,
	/// `None` if nothing needed the GPU (all items rejected by the CPU checks) or encoding
	/// failed (handled by the CPU fallback).
	cmd: Option<CommandBuffer>,
}

/// Batch ML-DSA-65 verifier running the lattice stage on the system default Metal device.
///
/// Thread-safe: GPU submissions are serialised internally, so a single instance can be stored
/// in a global and shared by many threads.
pub struct MetalVerifier {
	device: Retained<ProtocolObject<dyn MTLDevice>>,
	queue: Retained<ProtocolObject<dyn MTLCommandQueue>>,
	pipelines: [Pipeline; 4],
	selftest: [Pipeline; 3],
	scratch: Mutex<Option<Scratch>>,
}

impl MetalVerifier {
	/// Pick the system default Metal device and compile the kernels.
	pub fn new() -> Result<Self, Error> {
		let device = MTLCreateSystemDefaultDevice().ok_or(Error::NoDevice)?;
		let source = NSString::from_str(&shader::source());
		let library = device
			.newLibraryWithSource_options_error(&source, None)
			.map_err(|e| Error::ShaderCompile(e.localizedDescription().to_string()))?;
		let pipeline = |name: &str| -> Result<Pipeline, Error> {
			let function = library
				.newFunctionWithName(&NSString::from_str(name))
				.ok_or_else(|| Error::Pipeline(format!("missing kernel {name}")))?;
			device
				.newComputePipelineStateWithFunction_error(&function)
				.map_err(|e| Error::Pipeline(e.localizedDescription().to_string()))
		};
		let [a, b, c, d] = shader::KERNEL_NAMES;
		let pipelines = [pipeline(a)?, pipeline(b)?, pipeline(c)?, pipeline(d)?];
		for (p, name) in pipelines.iter().zip(shader::KERNEL_NAMES) {
			if p.maxTotalThreadsPerThreadgroup() < NTT_THREADS {
				return Err(Error::Pipeline(format!("{name}: threadgroup too small")));
			}
		}
		let [a, b, c] = shader::SELFTEST_NAMES;
		let selftest = [pipeline(a)?, pipeline(b)?, pipeline(c)?];
		let queue = device.newCommandQueue().ok_or(Error::NoDevice)?;
		Ok(Self { device, queue, pipelines, selftest, scratch: Mutex::new(None) })
	}

	/// Name of the Metal device, e.g. "Apple M4 Pro".
	pub fn device_name(&self) -> String {
		self.device.name().to_string()
	}

	/// Verify a batch. Returns, for every item, exactly what `ml-dsa`'s
	/// `VerifyingKey::<MlDsa65>::verify_with_context(msg, ctx, sig)` returns (with `false` for
	/// undecodable keys or signatures and for `ctx` longer than 255 bytes).
	pub fn verify_batch(&self, items: &[Item], ctx: &[u8]) -> Vec<bool> {
		self.verify_batch_with_stats(items, ctx).0
	}

	/// [`Self::verify_batch`], additionally returning timing information.
	pub fn verify_batch_with_stats(&self, items: &[Item], ctx: &[u8]) -> (Vec<bool>, BatchStats) {
		let start = Instant::now();
		let mut stats = BatchStats::default();
		let mut out = Vec::with_capacity(items.len());
		// Never panic: a poisoned lock only means another thread panicked mid-batch, and every
		// batch fully rewrites the scratch contents it reads.
		let mut guard = self.scratch.lock().unwrap_or_else(|e| e.into_inner());
		for chunk in items.chunks(MAX_JOBS_PER_SUBMISSION) {
			match self.scratch_for(&mut guard, chunk.len()) {
				Some(scratch) => self.run_chunk(scratch, chunk, ctx, &mut out, &mut stats),
				None => {
					// Allocation failure: fall back to the bit-identical CPU pipeline.
					stats.cpu_fallback_jobs += chunk.len();
					out.extend(crate::verify_batch_reference(chunk, ctx));
				},
			}
		}
		stats.total = start.elapsed();
		(out, stats)
	}

	/// Verify one chunk of at most `scratch.capacity` items, appending verdicts to `out`.
	fn run_chunk(
		&self,
		scratch: &Scratch,
		chunk: &[Item],
		ctx: &[u8],
		out: &mut Vec<bool>,
		stats: &mut BatchStats,
	) {
		let n = chunk.len();
		let parts = (n / MIN_SUB_BATCH).clamp(1, PIPELINE_DEPTH);
		let per_part = n.div_ceil(parts);

		// Prepare and commit sub-batches back to back; the GPU starts on the first while the
		// CPU prepares the next.
		let mut in_flight = Vec::with_capacity(parts);
		for first in (0..n).step_by(per_part) {
			let range = first..(first + per_part).min(n);
			let t = Instant::now();
			// SAFETY: `range` is within the chunk (<= capacity), disjoint from the ranges of
			// all previous sub-batches, and no command buffer reading it has been committed.
			let jobs = unsafe { scratch.jobs_mut(range.clone()) };
			let valid = prepare_jobs(&chunk[range.clone()], ctx, jobs);
			stats.prepare += t.elapsed();
			let cmd = if valid.contains(&true) {
				stats.gpu_jobs += range.len();
				self.commit(scratch, range.clone(), &[&[0, 1, 2, 3]]).and_then(|mut c| c.pop())
			} else {
				None
			};
			in_flight.push(InFlight { range, valid, cmd });
		}

		for InFlight { range, valid, cmd } in in_flight {
			let gpu_ok = match &cmd {
				Some(cmd) => wait(cmd).map(|t| {
					stats.gpu += t;
					stats.command_buffers += 1;
				}),
				None => None,
			};
			if gpu_ok.is_some() {
				// SAFETY: in range, and the command buffer writing these verdicts completed.
				let results = unsafe { scratch.results(range) };
				out.extend(valid.iter().zip(results).map(|(v, r)| *v && *r == 1));
			} else if valid.contains(&true) {
				// Metal error: recompute this sub-batch on the CPU from the prepared records.
				stats.cpu_fallback_jobs += range.len();
				// SAFETY: in range; the command buffer (if any) has finished, so nothing else
				// accesses these records.
				let jobs = unsafe { scratch.jobs_mut(range) };
				let mut s = reference::Scratch::new();
				out.extend(jobs.chunks(JOB_BYTES).map(|job| reference::run_job(job, &mut s)));
			} else {
				out.extend(valid);
			}
		}
	}

	/// Get scratch buffers able to hold `n` jobs, (re)allocating if needed.
	fn scratch_for<'a>(&self, slot: &'a mut Option<Scratch>, n: usize) -> Option<&'a Scratch> {
		if slot.as_ref().is_none_or(|s| s.capacity < n) {
			*slot = None;
			// Grow geometrically to avoid reallocating for every slightly larger batch.
			let capacity = n.next_power_of_two().clamp(64, MAX_JOBS_PER_SUBMISSION).max(n);
			let buf = |bytes: usize| {
				self.device
					.newBufferWithLength_options(bytes, MTLResourceOptions::StorageModeShared)
			};
			*slot = Some(Scratch {
				capacity,
				jobs: buf(capacity * JOB_BYTES)?,
				z_hat: buf(capacity * Z_HAT_STRIDE)?,
				t1_hat: buf(capacity * T1_HAT_STRIDE)?,
				c_hat: buf(capacity * C_HAT_STRIDE)?,
				prod: buf(capacity * PROD_STRIDE)?,
				w1: buf(capacity * W1_BYTES)?,
				results: buf(capacity * U32)?,
			});
		}
		slot.as_ref()
	}

	/// Encode the kernels for the prepared jobs `range` and commit, one command buffer per
	/// entry of `groups` (each entry lists kernel indices into [`shader::KERNEL_NAMES`]).
	/// Returns the committed command buffers, or `None` if Metal could not create one.
	fn commit(
		&self,
		s: &Scratch,
		range: Range<usize>,
		groups: &[&[usize]],
	) -> Option<Vec<CommandBuffer>> {
		let n = u32::try_from(range.len()).ok()?;
		let mut cmds = Vec::with_capacity(groups.len());
		for kernels in groups {
			let cmd = self.queue.commandBuffer()?;
			let enc = cmd.computeCommandEncoder()?;
			for &kernel in *kernels {
				self.encode_kernel(&enc, s, range.clone(), n, kernel);
			}
			enc.endEncoding();
			cmd.commit();
			cmds.push(cmd);
		}
		Some(cmds)
	}

	/// Encode kernel number `kernel` for jobs `range` (`n` of them). Dispatches in one compute
	/// encoder execute serially, so each kernel sees the previous kernel's output.
	fn encode_kernel(
		&self,
		enc: &ProtocolObject<dyn MTLComputeCommandEncoder>,
		s: &Scratch,
		range: Range<usize>,
		n: u32,
		kernel: usize,
	) {
		let pipeline = &self.pipelines[kernel];
		let jobs = range.len();
		let flat = |threads: usize| {
			let per_group = FLAT_THREADS.min(pipeline.maxTotalThreadsPerThreadgroup());
			(size(threads.div_ceil(per_group)), size(per_group))
		};
		// Buffer arguments in kernel signature order, with their per-job strides.
		let (buffers, (groups, threads)): (&[(&Buffer, usize)], _) = match kernel {
			0 => (
				&[
					(&s.jobs, JOB_BYTES),
					(&s.z_hat, Z_HAT_STRIDE),
					(&s.t1_hat, T1_HAT_STRIDE),
					(&s.c_hat, C_HAT_STRIDE),
				],
				(size(jobs * (L + K + 1)), size(NTT_THREADS)),
			),
			1 => (
				&[(&s.jobs, JOB_BYTES), (&s.z_hat, Z_HAT_STRIDE), (&s.prod, PROD_STRIDE)],
				flat(jobs * K * L),
			),
			2 => (
				&[
					(&s.jobs, JOB_BYTES),
					(&s.prod, PROD_STRIDE),
					(&s.t1_hat, T1_HAT_STRIDE),
					(&s.c_hat, C_HAT_STRIDE),
					(&s.w1, W1_BYTES),
				],
				(size(jobs * K), size(NTT_THREADS)),
			),
			_ => (&[(&s.jobs, JOB_BYTES), (&s.w1, W1_BYTES), (&s.results, U32)], flat(jobs)),
		};
		enc.setComputePipelineState(pipeline);
		// SAFETY: every buffer holds `capacity >= range.end` jobs (ensured by `scratch_for`)
		// at the given strides, so the offset views hold `n` jobs; the argument indices match
		// the kernel signatures in `shaders/verify.metal` (buffers in order, then the job
		// count); and `setBytes` copies `n` immediately.
		unsafe {
			for (i, (buffer, stride)) in buffers.iter().enumerate() {
				enc.setBuffer_offset_atIndex(Some(buffer), range.start * stride, i);
			}
			enc.setBytes_length_atIndex(NonNull::from(&n).cast(), U32, buffers.len());
		}
		enc.dispatchThreadgroups_threadsPerThreadgroup(groups, threads);
	}

	/// Diagnostics for benchmarking: run the lattice stage for (at most
	/// [`MAX_JOBS_PER_SUBMISSION`] of) `items` with one command buffer per kernel and return the
	/// GPU time of each kernel by name. Returns `None` if no item passes the CPU checks or Metal
	/// reports an error. Verification results are discarded.
	pub fn profile_kernels(
		&self,
		items: &[Item],
		ctx: &[u8],
	) -> Option<Vec<(&'static str, Duration)>> {
		let items = &items[..items.len().min(MAX_JOBS_PER_SUBMISSION)];
		let n = items.len();
		let mut guard = self.scratch.lock().unwrap_or_else(|e| e.into_inner());
		let scratch = self.scratch_for(&mut guard, n)?;
		// SAFETY: in range, nothing in flight (we hold the lock), no other slice.
		let jobs = unsafe { scratch.jobs_mut(0..n) };
		if !prepare_jobs(items, ctx, jobs).contains(&true) {
			return None;
		}
		let cmds = self.commit(scratch, 0..n, &[&[0], &[1], &[2], &[3]])?;
		let times = cmds.iter().map(wait).collect::<Option<Vec<_>>>()?;
		Some(shader::KERNEL_NAMES.into_iter().zip(times).collect())
	}
}

impl MetalVerifier {
	/// Check the GPU building blocks against their Rust twins used by
	/// [`crate::verify_batch_reference`]:
	///
	/// - `UseHint`/`Decompose` for **every** `r` in `[0, q)` and both hint values;
	/// - `mont_mul`, `add_mod`, `sub_mod`, `to_mont` on all pairs of edge values and 2^20
	///   pseudo-random pairs;
	/// - `Keccak-f[1600]` on 1024 pseudo-random states.
	///
	/// These cover edge cases that honest or randomly corrupted signatures practically never
	/// reach. Takes a few tens of milliseconds; a node can run it once at start-up before
	/// trusting the device.
	pub fn self_test(&self) -> Result<(), Error> {
		let _guard = self.scratch.lock().unwrap_or_else(|e| e.into_inner());
		let fail = |what: String| Err(Error::SelfTest(what));
		let gpu_err = || Error::SelfTest("Metal error while running a self-test kernel".into());

		// UseHint, exhaustively.
		let out = self.new_buffer::<u8>(&[], Q as usize).ok_or_else(gpu_err)?;
		self.run_selftest(0, &[&out], None, Q as usize).ok_or_else(gpu_err)?;
		// SAFETY: `out` holds `Q` bytes and the kernel has completed.
		let got = unsafe { buffer_slice::<u8>(&out, Q as usize) };
		for (r, &g) in got.iter().enumerate() {
			let r = r as u32;
			let want =
				crate::reference::use_hint(false, r) | crate::reference::use_hint(true, r) << 4;
			if u32::from(g) != want {
				return fail(format!("use_hint mismatch at r = {r}: gpu {g:#x}, cpu {want:#x}"));
			}
		}

		// Z_q arithmetic.
		let edges = [0, 1, 2, 3, 4095, 4096, Q / 2, Q / 2 + 1, Q - 3, Q - 2, Q - 1, arith::R2];
		let mut pairs: Vec<[u32; 2]> =
			edges.iter().flat_map(|&a| edges.iter().map(move |&b| [a, b])).collect();
		let mut x = 0x243F_6A88_85A3_08D3u64;
		for _ in 0..1 << 20 {
			x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
			pairs.push([((x >> 8) % u64::from(Q)) as u32, ((x >> 36) % u64::from(Q)) as u32]);
		}
		let input = self.new_buffer(&pairs, pairs.len()).ok_or_else(gpu_err)?;
		let output = self.new_buffer::<[u32; 4]>(&[], pairs.len()).ok_or_else(gpu_err)?;
		let n = pairs.len();
		self.run_selftest(1, &[&input, &output], Some(n), n).ok_or_else(gpu_err)?;
		// SAFETY: `output` holds `n` `[u32; 4]` values and the kernel has completed.
		let got = unsafe { buffer_slice::<[u32; 4]>(&output, n) };
		for (&[a, b], g) in pairs.iter().zip(got) {
			let want = [
				arith::mont_mul(a, b),
				arith::add_mod(a, b),
				arith::sub_mod(a, b),
				arith::to_mont(a),
			];
			if *g != want {
				return fail(format!(
					"arithmetic mismatch for ({a}, {b}): gpu {g:?}, cpu {want:?}"
				));
			}
		}

		// Keccak-f[1600].
		let mut states = vec![[0u64; 25]; 1024];
		for st in states.iter_mut().skip(1) {
			for w in st.iter_mut() {
				x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
				*w = x;
			}
		}
		let buf = self.new_buffer(&states, states.len()).ok_or_else(gpu_err)?;
		let n = states.len();
		self.run_selftest(2, &[&buf], Some(n), n).ok_or_else(gpu_err)?;
		// SAFETY: `buf` holds `n` states and the kernel has completed.
		let got = unsafe { buffer_slice::<[u64; 25]>(&buf, n) };
		for (i, (st, g)) in states.iter_mut().zip(got).enumerate() {
			crate::keccak::keccak_f1600(st);
			if st != g {
				return fail(format!("keccak_f1600 mismatch for state {i}"));
			}
		}
		Ok(())
	}

	/// A shared buffer with room for `len` values of `T`, initialised from `init` (which may
	/// be shorter; the rest is zero).
	fn new_buffer<T: Copy>(&self, init: &[T], len: usize) -> Option<Buffer> {
		let bytes = std::mem::size_of::<T>() * len.max(init.len());
		let buf = self
			.device
			.newBufferWithLength_options(bytes, MTLResourceOptions::StorageModeShared)?;
		// SAFETY: the buffer holds at least `init.len()` values of `T` (new buffers are
		// zero-filled and suitably aligned) and is not in use by the GPU.
		unsafe {
			std::ptr::copy_nonoverlapping(
				init.as_ptr(),
				buf.contents().as_ptr().cast::<T>(),
				init.len(),
			);
		}
		Some(buf)
	}

	/// Run self-test kernel `k` over `threads` threads and wait for it.
	fn run_selftest(
		&self,
		k: usize,
		buffers: &[&Buffer],
		n: Option<usize>,
		threads: usize,
	) -> Option<()> {
		let pipeline = &self.selftest[k];
		let cmd = self.queue.commandBuffer()?;
		let enc = cmd.computeCommandEncoder()?;
		enc.setComputePipelineState(pipeline);
		let n = n.map(u32::try_from).transpose().ok()?;
		// SAFETY: buffer sizes and argument indices match the self-test kernel signatures;
		// `setBytes` copies `n` immediately.
		unsafe {
			for (i, b) in buffers.iter().enumerate() {
				enc.setBuffer_offset_atIndex(Some(b), 0, i);
			}
			if let Some(n) = &n {
				enc.setBytes_length_atIndex(NonNull::from(n).cast(), U32, buffers.len());
			}
		}
		let per_group = FLAT_THREADS.min(pipeline.maxTotalThreadsPerThreadgroup());
		enc.dispatchThreadgroups_threadsPerThreadgroup(
			size(threads.div_ceil(per_group)),
			size(per_group),
		);
		enc.endEncoding();
		cmd.commit();
		wait(&cmd).map(|_| ())
	}
}

/// View the first `len` values of type `T` in a shared buffer.
///
/// # Safety
///
/// The buffer must hold at least `len` initialised values of `T` and must not be written by
/// the GPU while the slice is alive.
unsafe fn buffer_slice<T>(buf: &Buffer, len: usize) -> &[T] {
	// SAFETY: guaranteed by the caller.
	unsafe { std::slice::from_raw_parts(buf.contents().as_ptr().cast::<T>(), len) }
}

/// Wait for `cmd`; return its GPU execution time (`GPUEndTime - GPUStartTime`), or `None` if
/// it did not complete successfully.
fn wait(cmd: &CommandBuffer) -> Option<Duration> {
	cmd.waitUntilCompleted();
	if cmd.status() != MTLCommandBufferStatus::Completed {
		return None;
	}
	Some(Duration::from_secs_f64((cmd.GPUEndTime() - cmd.GPUStartTime()).max(0.0)))
}

fn size(width: usize) -> MTLSize {
	MTLSize { width, height: 1, depth: 1 }
}
