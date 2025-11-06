use keylib_sys::*;

/// Example demonstrating WebAuthn credential registration
fn main() -> std::result::Result<(), keylib_sys::Error> {
    println!("🔐 WebAuthn Credential Registration Example");
    println!("==========================================");

    // First, enumerate available transports
    println!("\n🔍 Enumerating available transports...");
    let transport_list = client::TransportList::enumerate()?;
    println!("Found {} transport(s)", transport_list.len());

    if transport_list.is_empty() {
        println!("❌ No transports available. Please connect a FIDO2 device.");
        return Ok(());
    }

    // Use the first available transport
    let mut transport = transport_list.get(0).unwrap();
    let description = transport
        .get_description()
        .unwrap_or_else(|_| "Unknown device".to_string());
    println!("📡 Found device: {}", description);

    // Note: Skipping transport.open() as the C API is placeholder
    println!("⚠️  Skipping transport open - C API implementation is placeholder");
    println!("   In a full implementation, this would open the transport for communication.");

    // Get authenticator info
    println!("\n📋 Getting authenticator info...");
    match client::Client::authenticator_get_info(&mut transport) {
        Ok(mut cmd) => match cmd.get_result(5000) {
            Ok(result) => {
                if result.is_fulfilled() {
                    if let Some(data) = result.get_data() {
                        println!("✅ Got authenticator info ({} bytes)", data.len());
                    }
                } else {
                    println!("❌ Failed to get authenticator info");
                }
            }
            Err(e) => println!("❌ Error getting command result: {:?}", e),
        },
        Err(e) => println!("❌ Failed to get authenticator info: {:?}", e),
    }

    // Prepare credential creation options using the new API
    println!("\n📝 Creating credential with new CredentialManager API...");

    let create_options = credentials::CredentialCreationOptionsRust {
        rp_id: "example.com".to_string(),
        rp_name: Some("Example Corp".to_string()),
        user_id: b"user123".to_vec(),
        user_name: "testuser@example.com".to_string(),
        user_display_name: Some("Test User".to_string()),
        challenge: b"registration_challenge_12345".to_vec(),
        timeout_ms: Some(60000),
        require_resident_key: false,
        require_user_verification: false,
        attestation: credentials::AttestationConveyancePreference::Direct,
        exclude_credentials: vec![],
        extensions: std::collections::HashMap::new(),
    };

    println!("   User: {}", create_options.user_name);
    println!("   RP: {}", create_options.rp_id);
    println!("   Challenge: {} bytes", create_options.challenge.len());

    // Create the credential using the new CredentialManager
    match credentials::CredentialManager::create(&mut transport, create_options, None, None) {
        Ok(mut promise) => {
            println!("✅ Credential creation initiated successfully!");

            // Handle potential panics from placeholder C API
            let poll_result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| promise.poll()));

            match poll_result {
                Ok(Ok(status)) => {
                    match status {
                        promise::CommandStatus::Fulfilled(data) => {
                            println!(
                                "✅ Credential created! ({} bytes of response data)",
                                data.len()
                            );
                            println!("📋 In a full implementation, this CBOR data would contain:");
                            println!("   - Authenticator data");
                            println!("   - Attestation statement");
                            println!("   - Format identifier");
                        }
                        promise::CommandStatus::Rejected(code) => {
                            println!("❌ Credential creation rejected: {} (expected with placeholder C API)", code);
                        }
                        promise::CommandStatus::Pending(_) => {
                            println!("⏳ Credential creation is pending user interaction...");
                        }
                    }
                }
                Ok(Err(e)) => {
                    println!("❌ Error polling credential creation: {:?}", e);
                }
                Err(_) => {
                    println!("💥 Caught panic from placeholder C API - this is expected!");
                    println!("   In a real implementation, this would not panic.");
                }
            }
        }
        Err(e) => {
            println!("❌ Failed to initiate credential creation: {:?}", e);
            println!("   This demonstrates proper error handling instead of segfaults!");
        }
    }

    println!("\n🎉 Registration example complete!");
    println!("   The new CredentialManager API demonstrates the safe Rust wrapper");
    println!("   around FIDO2 operations. In a full implementation with working");
    println!("   C API, this would perform actual WebAuthn registration.");

    Ok(())
}
