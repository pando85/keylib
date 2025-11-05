use keylib_sys::{
    client::TransportList, credential_management::CredentialManagement, error::Result,
};

fn main() -> Result<()> {
    println!("Credential Management Example\n");

    // Enumerate transports
    let transport_list = TransportList::enumerate()?;
    println!("Found {} transport(s)", transport_list.len());

    if transport_list.is_empty() {
        println!("No transports found - this example requires a real FIDO2 authenticator");
        println!("Please connect a FIDO2 security key and try again.");
        return Ok(());
    }

    let mut transport = transport_list
        .get(0)
        .ok_or(keylib_sys::error::KeylibError::Other)?;

    // Open transport
    if let Err(e) = transport.open() {
        println!("Failed to open transport: {:?}", e);
        println!("This example requires a working FIDO2 authenticator connection.");
        return Ok(());
    }
    println!("Transport opened successfully");

    // Create credential management instance
    let mut cm = CredentialManagement::new(&mut transport);

    // For this example, we'll assume PIN token is available
    // In a real application, you'd get this from ClientPin
    let pin_token = &[0u8; 32]; // Placeholder - replace with real PIN token
    let protocol = 2; // CTAP 2.1

    println!("\nNote: This example uses a placeholder PIN token.");
    println!("For real credential management, you need to:");
    println!("1. Set up a PIN on your authenticator");
    println!("2. Use ClientPin to get a valid PIN token");
    println!("3. Have some discoverable credentials stored\n");

    // Get metadata
    println!("Getting credential metadata...");
    match cm.get_metadata(pin_token, protocol) {
        Ok(metadata) => {
            println!(
                "  Existing credentials: {}",
                metadata.existing_credentials_count
            );
            println!(
                "  Max remaining: {}",
                metadata.max_possible_remaining_credentials
            );
        }
        Err(e) => {
            println!("  Failed to get metadata: {:?}", e);
            println!("  (This is expected with placeholder PIN token or no credentials)");
        }
    }

    // Try to enumerate RPs
    println!("\nEnumerating RPs...");
    match cm.enumerate_rps_begin(pin_token, protocol) {
        Ok(rp_enum) => {
            let rps: Vec<_> = rp_enum.collect(); // Collect all RPs first
            for (i, rp_result) in rps.into_iter().enumerate() {
                match rp_result {
                    Ok(rp) => {
                        println!("  RP {}: {}", i + 1, rp.id);
                        println!("    Hash: {:x?}", rp.id_hash);

                        // Try to enumerate credentials for this RP
                        println!("    Enumerating credentials...");
                        let mut cm2 = CredentialManagement::new(&mut transport);
                        match cm2.enumerate_credentials_begin(&rp.id_hash, pin_token, protocol) {
                            Ok(cred_enum) => {
                                let creds: Vec<_> = cred_enum.collect(); // Collect all credentials
                                for (j, cred_result) in creds.into_iter().enumerate() {
                                    match cred_result {
                                        Ok(cred) => {
                                            println!(
                                                "      Credential {}: ID={:x?}",
                                                j + 1,
                                                &cred.id[..16]
                                            );
                                        }
                                        Err(e) => {
                                            println!(
                                                "      Failed to get credential {}: {:?}",
                                                j + 1,
                                                e
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                println!("    Failed to enumerate credentials: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("  Failed to get RP {}: {:?}", i + 1, e);
                    }
                }
            }
        }
        Err(e) => {
            println!("  Failed to enumerate RPs: {:?}", e);
            println!("  (This is expected if no PIN token is set or no credentials exist)");
        }
    }

    // Close transport
    transport.close();
    println!("\nTransport closed");

    Ok(())
}
