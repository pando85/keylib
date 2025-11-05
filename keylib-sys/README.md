# keylib-sys

Rust FFI bindings for the keylib C API.

## Prerequisites

Before building this crate, you need to build the keylib Zig library:

```bash
# From the project root
zig build
```

This will generate the necessary static libraries and C headers in `zig-out/`.

## Building

```bash
cargo build
```

## Running the Examples

```bash
cargo run --example basic        # Simple authenticator initialization
cargo run --example client       # Client that sends CTAP commands
cargo run --example authenticator # Authenticator with callbacks, base64 credentials, and PEM certificates
```

## API

This crate provides safe Rust abstractions over the unsafe FFI bindings.

### Key Types

- `Authenticator`: Safe wrapper for authenticator instances with callback support
- `Callbacks`: Configuration for user interaction callbacks (UP/UV/Select/Read/Write/Delete)
- `Error`: Error types that can occur during operations

### Basic Usage

```rust
use keylib_sys::*;
use keylib_sys::callbacks::{UpResult, UvResult};
use std::sync::Arc;

// Create callbacks
let up_callback = Arc::new(|_info: &str, _user: Option<&str>, _rp: Option<&str>| -> Result<UpResult> {
    Ok(UpResult::Accepted)
});

let uv_callback = Arc::new(|_info: &str, _user: Option<&str>, _rp: Option<&str>| -> Result<UvResult> {
    Ok(UvResult::Accepted)
});

// Optional credential management callbacks
let select_callback = Arc::new(|_rp_id: &str| -> Result<Vec<String>> {
    Ok(vec!["user1".to_string(), "user2".to_string()])
});

let read_callback = Arc::new(|_id: &str, _rp: &str| -> Result<Vec<u8>> {
    Ok(vec![1, 2, 3, 4]) // Some credential data
});

let write_callback = Arc::new(|_id: &str, _rp: &str, _data: &[u8]| -> Result<()> {
    Ok(()) // Store credential data
});

let delete_callback = Arc::new(|_id: &str| -> Result<()> {
    Ok(()) // Delete credential data
});

let callbacks = Callbacks::new(
    Some(up_callback),
    Some(uv_callback),
    Some(select_callback),
    Some(read_callback),
    Some(write_callback),
    Some(delete_callback)
);

// Initialize authenticator
let mut authenticator = Authenticator::new(callbacks)?;

// Send CTAP commands
let request = vec![0x04]; // authenticatorGetInfo
let response = authenticator.handle_message(&request)?;
```

## Features

- ✅ Safe Rust API with proper error handling
- ✅ RAII-based resource management
- ✅ Callback bridging from Rust closures to C function pointers
- ✅ Complete callback system (UP/UV/Select/Read/Write/Delete)
- ✅ Basic CTAP message handling (authenticatorGetInfo)
- ✅ Examples demonstrating client and authenticator usage
- ✅ Base64-encoded credential display for debugging
- ✅ PEM-formatted certificate display in examples
- Static linking to keylib library

## Safety

The safe API ensures memory safety and proper resource cleanup. Raw FFI bindings are available in
the `raw` module for advanced use cases.

## Implementation Status

### ✅ Completed

- Callback system with trampoline functions (UP/UV/Select/Read/Write/Delete)
- Authenticator initialization and lifecycle management
- Basic CTAP command handling (authenticatorGetInfo)
- CBOR serialization/deserialization for responses
- Comprehensive examples

### 🚧 In Progress / TODO

- Full CTAP protocol implementation (MakeCredential, GetAssertion, etc.)
- Credential storage and management
- PIN/UV authentication token handling
- USB HID transport layer
- Client-side device enumeration and communication

## Limitations

- CTAP message handling is limited to authenticatorGetInfo
- No USB HID communication (examples use direct API calls)
- Credential management callbacks implemented but not fully integrated with CTAP commands
