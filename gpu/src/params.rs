//! ML-DSA-65 parameters (FIPS 204, Table 1) and derived encoding sizes.

/// The prime modulus q = 2^23 - 2^13 + 1.
pub const Q: u32 = 8_380_417;
/// Number of dropped bits from t.
pub const D: u32 = 13;
/// Number of +/-1 coefficients in the challenge polynomial.
pub const TAU: usize = 49;
/// Coefficient range of the mask y (and hence the bound on z).
pub const GAMMA1: u32 = 1 << 19;
/// Low-order rounding range.
pub const GAMMA2: u32 = (Q - 1) / 32;
/// Rows of A.
pub const K: usize = 6;
/// Columns of A.
pub const L: usize = 5;
/// beta = tau * eta.
pub const BETA: u32 = 196;
/// Maximum number of ones in the hint.
pub const OMEGA: usize = 55;
/// Polynomial degree.
pub const N: usize = 256;

/// Length of the commitment hash c~ in bytes (lambda / 4 with lambda = 192).
pub const CTILDE_BYTES: usize = 48;
/// Bytes per packed t1 polynomial (10 bits per coefficient).
pub const T1_POLY_BYTES: usize = 320;
/// Bytes per packed z polynomial (20 bits per coefficient).
pub const Z_POLY_BYTES: usize = 640;
/// Bytes per packed w1 polynomial (4 bits per coefficient).
pub const W1_POLY_BYTES: usize = 128;
/// Length of w1Encode(w1).
pub const W1_BYTES: usize = K * W1_POLY_BYTES;

/// Encoded public key length: rho || t1.
pub const PUBLIC_KEY_BYTES: usize = 32 + K * T1_POLY_BYTES;
/// Encoded signature length: c~ || z || h.
pub const SIGNATURE_BYTES: usize = CTILDE_BYTES + L * Z_POLY_BYTES + OMEGA + K;

const _: () = assert!(PUBLIC_KEY_BYTES == 1952);
const _: () = assert!(SIGNATURE_BYTES == 3309);
