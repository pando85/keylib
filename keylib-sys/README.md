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
cargo run --example credential_management # Credential management operations
```

## API

This crate provides safe Rust abstractions over the unsafe FFI bindings.

### Key Types

- `Authenticator`: Safe wrapper for authenticator instances with callback support
- `Callbacks`: Configuration for user interaction callbacks (UP/UV/Select/Read/Write/Delete)
- `CredentialManagement`: Safe API for managing discoverable credentials on authenticators
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

## Credential Management

The crate provides a complete API for managing discoverable credentials stored on FIDO2
authenticators.

### Basic Usage

```rust
use keylib_sys::{
    client::TransportList,
    credential_management::CredentialManagement,
};

// Enumerate and open transport
let transport_list = TransportList::enumerate()?;
let mut transport = transport_list.get(0).unwrap();
transport.open()?;

// Create credential management instance
let mut cm = CredentialManagement::new(&mut transport);

// Get metadata (requires PIN token)
let pin_token = &[0u8; 32]; // Get from ClientPin in real usage
let metadata = cm.get_metadata(pin_token, 2)?;
println!("Stored credentials: {}", metadata.existing_credentials_count);

// Enumerate relying parties
for rp in cm.enumerate_rps_begin(pin_token, 2)? {
    let rp = rp?;
    println!("RP: {}", rp.id);

    // Enumerate credentials for this RP
    // (Note: Would need separate CredentialManagement instance in real code)
}
```

### Available Operations

- **Get Metadata**: Query credential counts and storage limits
- **Enumerate RPs**: List all relying parties with stored credentials
- **Enumerate Credentials**: List all credentials for a specific RP
- **Delete Credentials**: Remove credentials by ID
- **Update User Info**: Modify user name/display name for credentials

All operations require a valid PIN token with credential management (0x04) permission.

## Features

- ✅ Safe Rust API with proper error handling
- ✅ RAII-based resource management
- ✅ Callback bridging from Rust closures to C function pointers
- ✅ Complete callback system (UP/UV/Select/Read/Write/Delete)
- ✅ Basic CTAP message handling (authenticatorGetInfo)
- ✅ **Credential Management API** - Complete implementation for managing discoverable credentials
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
- **Complete Credential Management API** - All 7 CTAP operations implemented
- Comprehensive examples

### 🚧 In Progress / TODO

- Full CTAP protocol implementation (MakeCredential, GetAssertion, etc.)
- PIN/UV authentication token handling
- USB HID transport layer
- Client-side device enumeration and communication

## Limitations

- CTAP message handling is limited to authenticatorGetInfo
- No USB HID communication (examples use direct API calls)
- **Credential management is fully implemented** - All operations available through safe Rust API
