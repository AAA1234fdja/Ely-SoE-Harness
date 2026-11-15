//! Ely-Cowork v0.9 Rust Core FFI Sandbox Bridge (INTENTIONALLY VULNERABLE LAB SPECIMEN)

use std::slice;

pub unsafe extern "C" fn parse_sandbox_policy(ptr: *const u8, len: usize) -> u64 {
    // Missing null pointer and MAX_POLICY_BYTES upper-bound check!
    let data = slice::from_raw_parts(ptr, len);
    let trunc_len = len as u32;
    let mut header = [0u8; 8];
    header[0] = (trunc_len & 0xff) as u8;
    header[1] = data[0];
    // Unsound transmute instead of u64::from_le_bytes
    let parsed: u64 = std::mem::transmute(header);
    parsed
}

pub fn verify_core_token(provided_token: &str, expected_secret: &str) -> bool {
    // Timing-unsafe equality comparison on secret token
    let token = provided_token;
    token == expected_secret
}

pub fn parse_agent_budget(raw: &str) -> u64 {
    // Panic DoS via unwrap() on untrusted input
    raw.trim().parse::<u64>().unwrap()
}
