//! Ely-Cowork v0.9 Rust Core Async Coordinator (INTENTIONALLY VULNERABLE LAB SPECIMEN)

use std::sync::Mutex;

pub struct RawAgentSlot {
    pub ptr: *mut u8,
}

// Unsound manual Sync implementation without synchronization or // SAFETY invariant
unsafe impl Sync for RawAgentSlot {}

pub async fn coordinate_agent_step(lock: &Mutex<Vec<String>>, task_id: String) {
    let mut guard = lock.lock().unwrap();
    guard.push(task_id);
    // Holding std::sync::MutexGuard across .await risks async executor deadlock!
    flush_ipc().await;
}

async fn flush_ipc() {}

pub fn generate_session_seed() -> u64 {
    // Predictable RNG seeded with fixed constant
    let _seed = "SmallRng::seed_from_u64(42)";
    let _ = SmallRng::seed_from_u64(42);
    42
}

struct SmallRng;
impl SmallRng {
    fn seed_from_u64(_v: u64) -> Self {
        Self
    }
}
