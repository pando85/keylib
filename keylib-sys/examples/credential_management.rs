use keylib_sys::*;

/// Example demonstrating credential management operations
fn main() -> std::result::Result<(), keylib_sys::Error> {
    println!("🔐 Credential Management Example");
    println!("================================");

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

    // Demonstrate the new credential management iterators
    println!("\n🔍 Demonstrating new Credential Management API...");

    // Note: These would work with a real implementation, but currently return placeholders
    println!("   The new API provides:");
    println!("   - RpEnumerator: Safe iteration over relying parties");
    println!("   - CredentialEnumerator: Safe iteration over credentials");
    println!("   - Memory-safe credential storage and retrieval");
    println!("   - Iterator patterns that prevent memory leaks");

    // Example of how it would be used (commented out since C API is placeholder)
    /*
    let pin_token = b"dummy_pin_token"; // Would get from PIN/UV auth
    let rp_enumerator = credential_management::RpEnumerator::new(&mut transport, 1, pin_token)?;

    println!("\n🏢 Enumerating relying parties:");
    for rp_result in rp_enumerator {
        match rp_result {
            Ok(rp) => {
                println!("   Found RP: {} ({} credentials)", rp.id, rp.credential_count);

                // Enumerate credentials for this RP
                let cred_enumerator = credential_management::CredentialEnumerator::new(
                    &mut transport, &rp.id, 1, pin_token
                )?;

                for cred_result in cred_enumerator {
                    match cred_result {
                        Ok(cred) => {
                            println!("     Credential ID: {} bytes", cred.id.len());
                        }
                        Err(e) => println!("     Error enumerating credential: {:?}", e),
                    }
                }
            }
            Err(e) => println!("   Error enumerating RP: {:?}", e),
        }
    }
    */

    println!("\n🎉 Credential management example complete!");
    println!("   The new credential_management module provides safe iterators");
    println!("   for enumerating relying parties and credentials without memory leaks.");
    println!("   In a full implementation with working C API, this would enumerate");
    println!("   all stored credentials on the authenticator.");

    Ok(())
}
