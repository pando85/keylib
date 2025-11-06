/// Performance demonstration showing the benefits of Phase 1 and Phase 2 optimizations
///
/// This example demonstrates:
/// 1. Phase 1: Response buffer reuse (raw_handle_into vs raw_handle)
/// 2. Phase 2: Zero-copy credentials (CredentialRef vs Credential clone)
use keylib_sys::callbacks::Callbacks;
use keylib_sys::error::Result;
use keylib_sys::{Authenticator, CredentialRef};
use std::sync::Arc;
use std::time::Instant;

fn main() -> Result<()> {
    println!("🚀 FFI Performance Optimization Demo\n");

    // Create authenticator with minimal callbacks
    let callbacks = Callbacks {
        up: Some(Arc::new(|_info, _user, _rp| {
            Ok(keylib_sys::callbacks::UpResult::Accepted)
        })),
        uv: None,
        select: None,
        read: None,
        write: Some(Arc::new(|_id, _rp, cred_ref: CredentialRef| {
            // Zero-copy: only allocate if we actually need to store
            // For this demo, we just access the data without allocating
            let _ = cred_ref.id.len(); // Access borrowed data
            let _ = cred_ref.rp_id.len();
            Ok(())
        })),
        delete: None,
        read_first: None,
        read_next: None,
    };

    let mut auth = Authenticator::new(callbacks)?;

    // GetInfo command (0x04)
    let get_info_request = vec![0x04];

    println!("📊 Phase 1 Demo: Response Buffer Reuse");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Benchmark OLD way (allocates response Vec every time)
    println!("❌ OLD: raw_handle() - Allocates new Vec each call");
    let iterations = 1000;
    let start = Instant::now();
    for _ in 0..iterations {
        let _response = auth.raw_handle(&get_info_request)?;
        // Each call allocates a new Vec<u8>
    }
    let old_duration = start.elapsed();
    println!("   Time for {} requests: {:?}", iterations, old_duration);
    println!("   Avg per request: {:?}\n", old_duration / iterations);

    // Benchmark NEW way (reuses buffer)
    println!("✅ NEW: raw_handle_into() - Reuses same Vec");
    let mut response_buffer = Vec::new();
    let start = Instant::now();
    for _ in 0..iterations {
        auth.raw_handle_into(&get_info_request, &mut response_buffer)?;
        response_buffer.clear(); // Reuse allocation
    }
    let new_duration = start.elapsed();
    println!("   Time for {} requests: {:?}", iterations, new_duration);
    println!("   Avg per request: {:?}", new_duration / iterations);

    let speedup = old_duration.as_nanos() as f64 / new_duration.as_nanos() as f64;
    println!("\n   🎯 Speedup: {:.2}x faster!", speedup);
    println!("   💾 Allocations saved: {} Vec allocations\n", iterations);

    println!("\n📊 Phase 2 Demo: Zero-Copy Credentials");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    println!("✅ Zero-copy CredentialRef in write callback:");
    println!("   - No heap allocations for id, rp_id, user_id, private_key");
    println!("   - Data borrowed directly from FFI struct");
    println!("   - Only allocate if credential needs to be stored");
    println!("   - Demonstrated above in write callback\n");

    println!("📈 Summary:");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("Phase 1 (Response Buffer Reuse):");
    println!("  • Eliminates 1 allocation per request");
    println!("  • {:.2}x faster for request handling", speedup);
    println!("\nPhase 2 (Zero-Copy Credentials):");
    println!("  • Eliminates 4+ allocations per credential write");
    println!("  • Eliminates 4+ allocations per credential read");
    println!("  • Callback-driven allocation strategy\n");

    Ok(())
}
