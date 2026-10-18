// ML-DSA-65 (FIPS 204) batch verification: lattice stage.
//
// This file is prefixed at runtime by a generated prelude (see `src/shader.rs`) defining the
// parameters (`Q`, `K`, `L`, ...), the job record offsets (`JOB_*`), the Montgomery constants
// and the tables `ZETAS_MONT`, `KECCAK_RC`, `KECCAK_RHO_PI_DST` and `KECCAK_RHO_PI_ROT`. All of
// them come from the same Rust constants that the reference pipeline (`src/reference.rs`) uses.
//
// Every kernel has a twin `kernel_*` function in `src/reference.rs`. Only integer arithmetic
// is used; all values handed between functions are fully reduced to [0, q), so the result is
// independent of scheduling and bit-identical to the reference.
//
// Pipeline (serial dispatches in one compute encoder per sub-batch):
//   1. ntt_inputs  threadgroup per (job, poly): NTT(z_j), NTT(t1_i * 2^d), NTT(c)
//   2. expand_a    thread per (job, i, j):     A_hat[i][j] = RejNTTPoly(rho||j||i) o z_hat[j]
//   3. rows        threadgroup per (job, i):   UseHint(h_i, NTT^-1(sum_j - c_hat o t1_hat_i))
//                                              and w1Encode
//   4. challenge   thread per job:             H(mu || w1, 48) == c~

// ---------------------------------------------------------------------------------------------
// Z_q arithmetic (twins of `src/arith.rs`).
// ---------------------------------------------------------------------------------------------

// a * b * 2^-32 mod q in [0, q), for a, b < q.
static inline uint mont_mul(uint a, uint b) {
	uint lo = a * b;
	uint hi = mulhi(a, b);
	uint m = lo * NEG_QINV;
	uint t = hi + mulhi(m, Q) + (lo != 0u ? 1u : 0u);
	return t >= Q ? t - Q : t;
}

static inline uint add_mod(uint a, uint b) {
	uint t = a + b;
	return t >= Q ? t - Q : t;
}

static inline uint sub_mod(uint a, uint b) {
	return add_mod(a, Q - b);
}

static inline uint to_mont(uint a) {
	return mont_mul(a, R2);
}

// Forward NTT on a threadgroup-resident polynomial; thread `t` in [0, 128) performs butterfly
// `t` of every layer.
static void ntt_tg(threadgroup uint *a, uint t) {
	for (uint len = 128; len > 0; len >>= 1) {
		uint group = t / len;
		uint j = 2 * len * group + t % len;
		uint zeta = ZETAS_MONT[N / (2 * len) + group];
		uint u = a[j];
		uint v = mont_mul(zeta, a[j + len]);
		a[j] = add_mod(u, v);
		a[j + len] = sub_mod(u, v);
		threadgroup_barrier(mem_flags::mem_threadgroup);
	}
}

// Inverse NTT including the final scaling by 1/256.
static void inv_ntt_tg(threadgroup uint *a, uint t) {
	for (uint len = 1; len < N; len <<= 1) {
		uint group = t / len;
		uint j = 2 * len * group + t % len;
		uint zeta = Q - ZETAS_MONT[N / len - 1 - group];
		uint u = a[j];
		uint v = a[j + len];
		a[j] = add_mod(u, v);
		a[j + len] = mont_mul(zeta, sub_mod(u, v));
		threadgroup_barrier(mem_flags::mem_threadgroup);
	}
	for (uint m = t; m < N; m += N / 2) {
		a[m] = mont_mul(a[m], INV_N_MONT);
	}
	threadgroup_barrier(mem_flags::mem_threadgroup);
}

// ---------------------------------------------------------------------------------------------
// Keccak-f[1600] (twin of `src/keccak.rs`).
// ---------------------------------------------------------------------------------------------

static inline ulong rotl64(ulong x, uint n) {
	return (x << n) | (x >> (64u - n));
}

static void keccak_f1600(thread ulong *st) {
	for (uint round = 0; round < 24; ++round) {
		ulong c[5];
#pragma unroll
		for (uint x = 0; x < 5; ++x) {
			c[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
		}
#pragma unroll
		for (uint x = 0; x < 5; ++x) {
			ulong d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
#pragma unroll
			for (uint y = 0; y < 5; ++y) {
				st[x + 5 * y] ^= d;
			}
		}
		// Rho and pi as one lane permutation; lane 0 is neither moved nor rotated.
		ulong b[25];
		b[0] = st[0];
#pragma unroll
		for (uint i = 1; i < 25; ++i) {
			b[KECCAK_RHO_PI_DST[i]] = rotl64(st[i], KECCAK_RHO_PI_ROT[i]);
		}
		// Chi.
#pragma unroll
		for (uint y = 0; y < 5; ++y) {
			ulong r0 = b[5 * y], r1 = b[5 * y + 1], r2 = b[5 * y + 2];
			ulong r3 = b[5 * y + 3], r4 = b[5 * y + 4];
			st[5 * y] = r0 ^ (~r1 & r2);
			st[5 * y + 1] = r1 ^ (~r2 & r3);
			st[5 * y + 2] = r2 ^ (~r3 & r4);
			st[5 * y + 3] = r3 ^ (~r4 & r0);
			st[5 * y + 4] = r4 ^ (~r0 & r1);
		}
		st[0] ^= KECCAK_RC[round];
	}
}

static inline ulong load_le64(device const uchar *p) {
	ulong v = 0;
#pragma unroll
	for (uint k = 0; k < 8; ++k) {
		v |= ((ulong)p[k]) << (8 * k);
	}
	return v;
}

// Byte `k` of the Keccak state, for a compile-time constant `k` after unrolling.
static inline uint state_byte(thread const ulong *st, uint k) {
	return (uint)(st[k / 8] >> (8 * (k % 8))) & 0xFFu;
}

// ---------------------------------------------------------------------------------------------
// Kernel 1: NTT of z, t1 * 2^d and c.
// ---------------------------------------------------------------------------------------------

// Coefficient `m` of input polynomial `p` (twin of the loop body in `kernel_ntt_inputs`).
static inline uint load_input(device const uchar *job, uint p, uint m) {
	if (p < L) {
		// z: 20-bit fields, gamma1 - v mod q.
		device const uchar *zp = job + JOB_Z + p * Z_POLY_BYTES;
		uint bit = m * 20;
		device const uchar *b = zp + bit / 8;
		uint v = ((uint)b[0] | ((uint)b[1] << 8) | ((uint)b[2] << 16)) >> (bit % 8);
		v &= 0xFFFFFu;
		uint z = GAMMA1 + Q - v;
		return z >= Q ? z - Q : z;
	} else if (p < L + K) {
		// t1: 10-bit fields, times 2^d (already < q).
		device const uchar *t1 = job + JOB_PK + 32 + (p - L) * T1_POLY_BYTES;
		uint bit = m * 10;
		device const uchar *b = t1 + bit / 8;
		uint v = (((uint)b[0] | ((uint)b[1] << 8)) >> (bit % 8)) & 0x3FFu;
		return v << D;
	} else {
		uchar c = job[JOB_C + m];
		return c == 0 ? 0u : (c == 1 ? 1u : Q - 1u);
	}
}

kernel void ntt_inputs(
	device const uchar *jobs [[buffer(0)]],
	device uint *z_hat [[buffer(1)]],
	device uint *t1_hat [[buffer(2)]],
	device uint *c_hat [[buffer(3)]],
	constant uint &n_jobs [[buffer(4)]],
	uint tg [[threadgroup_position_in_grid]],
	uint t [[thread_position_in_threadgroup]])
{
	threadgroup uint a[N];
	uint job_idx = tg / (L + K + 1);
	uint p = tg % (L + K + 1);
	if (job_idx >= n_jobs) {
		return;
	}
	device const uchar *job = jobs + (ulong)job_idx * JOB_BYTES;
	// Uniform across the threadgroup, so returning before the barriers is safe.
	if (job[JOB_VALID] == 0) {
		return;
	}
	for (uint m = t; m < N; m += N / 2) {
		a[m] = load_input(job, p, m);
	}
	threadgroup_barrier(mem_flags::mem_threadgroup);
	ntt_tg(a, t);
	for (uint m = t; m < N; m += N / 2) {
		if (p < L) {
			z_hat[((ulong)job_idx * L + p) * N + m] = to_mont(a[m]);
		} else if (p < L + K) {
			t1_hat[((ulong)job_idx * K + (p - L)) * N + m] = a[m];
		} else {
			c_hat[(ulong)job_idx * N + m] = to_mont(a[m]);
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Kernel 2: ExpandA (RejNTTPoly) fused with the pointwise product A_hat[i][j] o z_hat[j].
// ---------------------------------------------------------------------------------------------

kernel void expand_a(
	device const uchar *jobs [[buffer(0)]],
	device const uint *z_hat [[buffer(1)]],
	device uint *prod [[buffer(2)]],
	constant uint &n_jobs [[buffer(3)]],
	uint gid [[thread_position_in_grid]])
{
	uint job_idx = gid / (K * L);
	uint r = gid % (K * L);
	uint i = r / L;
	uint j = r % L;
	if (job_idx >= n_jobs) {
		return;
	}
	device const uchar *job = jobs + (ulong)job_idx * JOB_BYTES;
	if (job[JOB_VALID] == 0) {
		return;
	}

	// SHAKE128 absorb of rho || j || i (34 bytes) plus padding, directly into the state.
	ulong st[25];
#pragma unroll
	for (uint w = 0; w < 25; ++w) {
		st[w] = 0;
	}
#pragma unroll
	for (uint w = 0; w < 4; ++w) {
		st[w] = load_le64(job + JOB_PK + 8 * w);
	}
	st[4] = (ulong)j | ((ulong)i << 8) | (0x1Ful << 16);
	st[SHAKE128_RATE / 8 - 1] ^= 0x80ul << 56;

	device const uint *zj = z_hat + ((ulong)job_idx * L + j) * N;
	device uint *out = prod + (((ulong)job_idx * K + i) * L + j) * N;
	uint m = 0;
	while (m < N) {
		keccak_f1600(st);
		// 168-byte block = 56 candidate coefficients of three bytes each.
#pragma unroll
		for (uint k = 0; k < SHAKE128_RATE; k += 3) {
			uint a = state_byte(st, k) | (state_byte(st, k + 1) << 8) |
				((state_byte(st, k + 2) & 0x7Fu) << 16);
			if (a < Q && m < N) {
				out[m] = mont_mul(a, zj[m]);
				m += 1;
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Kernel 3: w'_approx row, inverse NTT, UseHint, w1Encode.
// ---------------------------------------------------------------------------------------------

// UseHint with Decompose for 2 * gamma2 = (q - 1) / 16 (twin of `reference::use_hint`).
static inline uint use_hint(bool h, uint r) {
	const uint two_gamma2 = 2 * GAMMA2;
	int r0 = (int)(r % two_gamma2);
	if (r0 > (int)GAMMA2) {
		r0 -= (int)two_gamma2;
	}
	int diff = (int)r - r0;
	uint r1;
	if (diff == (int)(Q - 1)) {
		r0 -= 1;
		r1 = 0;
	} else {
		r1 = (uint)diff / two_gamma2;
	}
	if (!h) {
		return r1;
	}
	return r0 > 0 ? ((r1 + 1) & 15u) : ((r1 + 15) & 15u);
}

kernel void rows(
	device const uchar *jobs [[buffer(0)]],
	device const uint *prod [[buffer(1)]],
	device const uint *t1_hat [[buffer(2)]],
	device const uint *c_hat [[buffer(3)]],
	device uchar *w1 [[buffer(4)]],
	constant uint &n_jobs [[buffer(5)]],
	uint tg [[threadgroup_position_in_grid]],
	uint t [[thread_position_in_threadgroup]])
{
	threadgroup uint w[N];
	uint job_idx = tg / K;
	uint i = tg % K;
	if (job_idx >= n_jobs) {
		return;
	}
	device const uchar *job = jobs + (ulong)job_idx * JOB_BYTES;
	if (job[JOB_VALID] == 0) {
		return;
	}
	device const uint *row = prod + ((ulong)job_idx * K + i) * L * N;
	device const uint *t1 = t1_hat + ((ulong)job_idx * K + i) * N;
	device const uint *c = c_hat + (ulong)job_idx * N;
	for (uint m = t; m < N; m += N / 2) {
		uint acc = 0;
		for (uint j = 0; j < L; ++j) {
			acc = add_mod(acc, row[j * N + m]);
		}
		w[m] = sub_mod(acc, mont_mul(c[m], t1[m]));
	}
	threadgroup_barrier(mem_flags::mem_threadgroup);
	inv_ntt_tg(w, t);

	// Thread t packs coefficients 2t and 2t + 1 into byte t of w1Encode(w1_i).
	device const uchar *hint = job + JOB_HINT + i * (N / 8);
	uint m0 = 2 * t;
	uint m1 = 2 * t + 1;
	bool h0 = ((hint[m0 / 8] >> (m0 % 8)) & 1u) != 0;
	bool h1 = ((hint[m1 / 8] >> (m1 % 8)) & 1u) != 0;
	uint lo = use_hint(h0, w[m0]);
	uint hi = use_hint(h1, w[m1]);
	w1[(ulong)job_idx * W1_BYTES + i * W1_POLY_BYTES + t] = (uchar)(lo | (hi << 4));
}

// ---------------------------------------------------------------------------------------------
// Kernel 4: c~' = SHAKE256(mu || w1Encode(w1'), 48) and comparison with c~.
// ---------------------------------------------------------------------------------------------

// Lane `off / 8` of the message mu || w1 (both parts are multiples of 8 bytes).
static inline ulong hash_input_lane(device const uchar *job, device const uchar *w1, uint off) {
	return off < 64 ? load_le64(job + JOB_MU + off) : load_le64(w1 + (off - 64));
}

kernel void challenge(
	device const uchar *jobs [[buffer(0)]],
	device const uchar *w1_all [[buffer(1)]],
	device uint *results [[buffer(2)]],
	constant uint &n_jobs [[buffer(3)]],
	uint gid [[thread_position_in_grid]])
{
	if (gid >= n_jobs) {
		return;
	}
	device const uchar *job = jobs + (ulong)gid * JOB_BYTES;
	if (job[JOB_VALID] == 0) {
		results[gid] = 0;
		return;
	}
	device const uchar *w1 = w1_all + (ulong)gid * W1_BYTES;

	ulong st[25];
#pragma unroll
	for (uint w = 0; w < 25; ++w) {
		st[w] = 0;
	}
	// HASH_IN_BYTES = 64 + 768 = 832 = 6 full 136-byte blocks + 16 bytes.
	for (uint blk = 0; blk * SHAKE256_RATE <= HASH_IN_BYTES; ++blk) {
#pragma unroll
		for (uint l = 0; l < SHAKE256_RATE / 8; ++l) {
			uint off = blk * SHAKE256_RATE + 8 * l;
			if (off < HASH_IN_BYTES) {
				st[l] ^= hash_input_lane(job, w1, off);
			}
		}
		if ((blk + 1) * SHAKE256_RATE > HASH_IN_BYTES) {
			// Final block: SHAKE padding right after the message, 0x80 at the end of the rate.
			const uint pad = HASH_IN_BYTES % SHAKE256_RATE;
			st[pad / 8] ^= 0x1Ful << (8 * (pad % 8));
			st[SHAKE256_RATE / 8 - 1] ^= 0x80ul << 56;
		}
		keccak_f1600(st);
	}

	// Compare the first 48 squeezed bytes (6 lanes) with c~.
	uint diff = 0;
#pragma unroll
	for (uint l = 0; l < CTILDE_BYTES / 8; ++l) {
		diff |= (st[l] != load_le64(job + JOB_CTILDE + 8 * l)) ? 1u : 0u;
	}
	results[gid] = diff == 0 ? 1u : 0u;
}

// ---------------------------------------------------------------------------------------------
// Self-test kernels (`MetalVerifier::self_test`): expose the building blocks so the host can
// compare them with their Rust twins, exhaustively where the domain allows.
// ---------------------------------------------------------------------------------------------

// For every r in [0, q): out[r] = use_hint(false, r) | use_hint(true, r) << 4.
kernel void selftest_use_hint(
	device uchar *out [[buffer(0)]],
	uint r [[thread_position_in_grid]])
{
	if (r < Q) {
		out[r] = (uchar)(use_hint(false, r) | (use_hint(true, r) << 4));
	}
}

// For input pairs (a, b) with a, b < q: mont_mul, add_mod, sub_mod and to_mont.
kernel void selftest_arith(
	device const uint2 *in [[buffer(0)]],
	device uint4 *out [[buffer(1)]],
	constant uint &n [[buffer(2)]],
	uint gid [[thread_position_in_grid]])
{
	if (gid < n) {
		uint a = in[gid].x;
		uint b = in[gid].y;
		out[gid] = uint4(mont_mul(a, b), add_mod(a, b), sub_mod(a, b), to_mont(a));
	}
}

// Keccak-f[1600] applied to each of `n` states in place.
kernel void selftest_keccak(
	device ulong *states [[buffer(0)]],
	constant uint &n [[buffer(1)]],
	uint gid [[thread_position_in_grid]])
{
	if (gid < n) {
		ulong st[25];
		for (uint w = 0; w < 25; ++w) {
			st[w] = states[gid * 25 + w];
		}
		keccak_f1600(st);
		for (uint w = 0; w < 25; ++w) {
			states[gid * 25 + w] = st[w];
		}
	}
}
