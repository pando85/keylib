use keylib_sys::*;

/// Example demonstrating WebAuthn credential authentication
fn main() -> std::result::Result<(), keylib_sys::Error> {
    println!("🔐 WebAuthn Credential Authentication Example");
    println!("============================================");

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

    // Prepare credential assertion options using the new API
    println!("\n🔍 Requesting assertion with new CredentialManager API...");

    let assertion_options = credentials::CredentialAssertionOptionsRust {
        rp_id: "example.com".to_string(),
        challenge: b"authentication_challenge_67890".to_vec(),
        timeout_ms: Some(60000),
        user_verification: credentials::UserVerificationRequirement::Preferred,
        allow_credentials: vec![], // Empty means any credential for this RP
    };

    println!("   RP ID: {}", assertion_options.rp_id);
    println!("   Challenge: {} bytes", assertion_options.challenge.len());
    println!(
        "   Allow credentials: {}",
        assertion_options.allow_credentials.len()
    );

    // Get assertion using the new CredentialManager
    match credentials::CredentialManager::get(&mut transport, assertion_options, None, None) {
        Ok(mut promise) => {
            println!("✅ Assertion request initiated successfully!");

            match promise.poll() {
                Ok(status) => match status {
                    promise::CommandStatus::Fulfilled(data) => {
                        println!(
                            "✅ Assertion obtained! ({} bytes of response data)",
                            data.len()
                        );
                        println!("📋 In a full implementation, this CBOR data would contain:");
                        println!("   - Credential ID");
                        println!("   - Authenticator data");
                        println!("   - Signature");
                        println!("   - User handle");
                        println!("   - Sign count for replay attack prevention");
                    }
                    promise::CommandStatus::Rejected(code) => {
                        println!("❌ Assertion rejected: {}", code);
                    }
                    promise::CommandStatus::Pending(_) => {
                        println!("⏳ Assertion is pending user interaction...");
                    }
                },
                Err(e) => {
                    println!("❌ Error polling assertion: {:?}", e);
                }
            }
        }
        Err(e) => {
            println!("❌ Failed to initiate assertion: {:?}", e);
        }
    }

    println!("\n🎉 Authentication example complete!");
    println!("   The new CredentialManager API demonstrates the safe Rust wrapper");
    println!("   around FIDO2 operations. In a full implementation with working");
    println!("   C API, this would perform actual WebAuthn authentication.");

    Ok(())
}
