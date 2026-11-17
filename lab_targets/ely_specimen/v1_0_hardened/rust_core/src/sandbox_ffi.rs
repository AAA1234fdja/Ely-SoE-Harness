//! Ely-Cowork v1.0-rc1 Hardened Rust Core FFI Sandbox Bridge.

use std::slice;

pub const MAX_POLICY_BYTES: usize = 65_536;

pub fn validate_ffi_bounds(ptr: *const u8, len: usize) -> Result<(), i32> {
    if ptr.is_null() || len == 0 || len > MAX_POLICY_BYTES {
        return Err(-1);
    }
    Ok(())
}

pub unsafe extern "C" fn parse_sandbox_policy(ptr: *const u8, len: usize) -> i64 {
    if validate_ffi_bounds(ptr, len).is_err() {
        return -1;
    }
    // SAFETY: ptr is verified non-null and len is strictly bounded by MAX_POLICY_BYTES.
    let data = slice::from_raw_parts(ptr, len);
    let mut header = [0u8; 8];
    let copy_n = data.len().min(8);
    header[..copy_n].copy_from_slice(&data[..copy_n]);
    u64::from_le_bytes(header) as i64
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn verify_core_token(provided: &str, expected: &str) -> bool {
    constant_time_eq(provided.as_bytes(), expected.as_bytes())
}

pub fn parse_agent_budget(raw: &str) -> Result<u64, std::num::ParseIntError> {
    raw.trim().parse::<u64>()
}
