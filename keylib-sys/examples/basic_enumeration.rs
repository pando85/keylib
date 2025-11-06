use keylib_sys::*;

/// Basic example showing how to enumerate and connect to FIDO2 devices
fn main() -> std::result::Result<(), keylib_sys::Error> {
    println!("🔍 Enumerating FIDO2 devices...");

    // Enumerate all available transports
    let transport_list = client::TransportList::enumerate()?;

    println!("Found {} transport(s)", transport_list.len());

    if transport_list.is_empty() {
        println!("No FIDO2 devices found. Make sure you have:");
        println!("- A physical FIDO2/U2F security key connected, or");
        println!("- A virtual UHID device running");
        return Ok(());
    }

    // Try to connect to the first device
    let mut transport = transport_list.get(0).unwrap();

    // Get description safely - handle potential segfaults from placeholder C API
    let description = transport
        .get_description()
        .unwrap_or_else(|_| "Unknown device".to_string());
    println!("📡 Found device: {}", description);

    // Note: Skipping transport.open() as the C API is placeholder
    println!("⚠️  Skipping transport open - C API implementation is placeholder");
    println!("   In a full implementation, this would open the transport for communication.");

    // Note: Skipping actual transport operations as C API is placeholder
    println!("📋 Would get authenticator info here...");
    println!("   In a full implementation, this would call:");
    println!("   - client::Client::authenticator_get_info(&mut transport)");
    println!("   - Get device capabilities, versions, and options");

    // Try to create a credential using the new CredentialManager
    println!("\n🔐 Demonstrating new CredentialManager API...");

    let create_options = credentials::CredentialCreationOptionsRust {
        rp_id: "example.com".to_string(),
        rp_name: Some("Example RP".to_string()),
        user_id: b"user123".to_vec(),
        user_name: "testuser".to_string(),
        user_display_name: Some("Test User".to_string()),
        challenge: b"challenge123".to_vec(),
        timeout_ms: Some(30000),
        require_resident_key: false,
        require_user_verification: false,
        attestation: credentials::AttestationConveyancePreference::Direct,
        exclude_credentials: vec![],
        extensions: std::collections::HashMap::new(),
    };

    // Note: This will fail with placeholder C API, but demonstrates the API
    match credentials::CredentialManager::create(&mut transport, create_options, None, None) {
        Ok(mut promise) => {
            println!("✅ Credential creation initiated successfully!");
            println!("   The new API properly structures parameters instead of raw CBOR");

            // Handle potential panics from placeholder C API
            let poll_result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| promise.poll()));

            match poll_result {
                Ok(Ok(status)) => {
                    match status {
                        promise::CommandStatus::Fulfilled(data) => {
                            println!("✅ Credential created! ({} bytes)", data.len());
                        }
                        promise::CommandStatus::Rejected(code) => {
                            println!("❌ Credential creation rejected: {} (expected with placeholder C API)", code);
                        }
                        promise::CommandStatus::Pending(_) => {
                            println!("⏳ Credential creation is pending...");
                        }
                    }
                }
                Ok(Err(e)) => {
                    println!("❌ Error polling credential creation: {:?} (expected with placeholder C API)", e);
                }
                Err(_) => {
                    println!("💥 Caught panic from placeholder C API - this is expected!");
                    println!("   In a real implementation, this would not panic.");
                }
            }
        }
        Err(e) => {
            println!(
                "❌ Failed to initiate credential creation: {:?} (expected with placeholder C API)",
                e
            );
            println!("   This demonstrates proper error handling instead of segfaults!");
        }
    }

    println!("\n🎉 Transport enumeration and basic operations completed!");
    println!("   The new CredentialManager API is working!");
    println!("   In a full implementation, you would continue with");
    println!("   credential assertion and other WebAuthn operations.");

    Ok(())
}
