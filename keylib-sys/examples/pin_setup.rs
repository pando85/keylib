use keylib_sys::*;

/// Example demonstrating PIN setup and management
fn main() -> std::result::Result<(), keylib_sys::Error> {
    println!("🔐 PIN/UV Setup and Management Example");
    println!("======================================");

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
    println!("📡 Connecting to device: {}", transport.get_description()?);

    transport.open()?;
    println!("✅ Transport opened");

    // Get authenticator info
    println!("\n📋 Getting authenticator info...");
    let mut cmd = client::Client::authenticator_get_info(&mut transport)?;
    let result = cmd.get_result(5000)?;

    if result.is_fulfilled() {
        if let Some(data) = result.get_data() {
            println!("✅ Got authenticator info ({} bytes)", data.len());
            // In a real implementation, we'd parse the CBOR data here
        }
    } else {
        println!("❌ Failed to get authenticator info");
        return Ok(());
    }

    // Demonstrate the new PIN/UV authentication encapsulation
    println!("\n🔑 Demonstrating new PinUvAuthEncapsulation API...");

    // Note: This would work with a real implementation, but currently returns placeholders
    println!("   The new API provides:");
    println!("   - Secure ECDH key exchange with authenticator");
    println!("   - PIN token generation for credential operations");
    println!("   - PIN/UV token with permissions for CTAP 2.1+");
    println!("   - Memory-safe cryptographic operations");

    // Example of how it would be used (commented out since C API is placeholder)
    /*
    // Establish shared secret with authenticator
    let mut pin_uv_auth = client_pin::PinUvAuthEncapsulation::new(&mut transport, 1)?;
    println!("✅ Shared secret established with authenticator");

    // Get PIN token
    let pin = "123456"; // Would get from user securely
    let pin_token = pin_uv_auth.get_pin_token(&mut transport, pin)?;
    println!("✅ PIN token obtained ({} bytes)", pin_token.len());

    // Use PIN token for credential operations
    let create_options = credentials::CredentialCreationOptionsRust {
        rp_id: "example.com".to_string(),
        rp_name: Some("Example Corp".to_string()),
        user_id: b"user123".to_vec(),
        user_name: "testuser@example.com".to_string(),
        user_display_name: Some("Test User".to_string()),
        challenge: b"challenge123".to_vec(),
        timeout_ms: Some(30000),
        require_resident_key: false,
        require_user_verification: false,
        attestation: credentials::AttestationConveyancePreference::Direct,
        exclude_credentials: vec![],
        extensions: std::collections::HashMap::new(),
    };

    let result = credentials::CredentialManager::create(
        &mut transport,
        create_options,
        Some(&pin_token),
        Some(1)
    )?;
    */

    println!("\n🎉 PIN/UV authentication example complete!");
    println!("   The new client_pin module provides secure PIN/UV operations");
    println!("   with proper cryptographic encapsulation. In a full implementation");
    println!("   with working C API, this would establish secure communication");
    println!("   with the authenticator for PIN-protected operations.");

    Ok(())
}
