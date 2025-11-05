use keylib_sys::client::{Client, TransportList};
use std::env;

fn main() {
    println!("Keylib Rust Client Example");

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let timeout_ms = if args.len() > 1 {
        args[1].parse::<i32>().unwrap_or(5000)
    } else {
        5000
    };
    println!("Using timeout: {}ms", timeout_ms);

    // Enumerate available transports
    println!("Enumerating available transports...");
    let transport_list = match TransportList::enumerate() {
        Ok(list) => list,
        Err(e) => {
            eprintln!("Failed to enumerate transports: {:?}", e);
            return;
        }
    };

    println!("Found {} transport(s)", transport_list.len());

    if transport_list.is_empty() {
        println!("No transports available. Make sure you have FIDO2 devices connected.");
        return;
    }

    // Try to use the first available transport
    let mut transport = match transport_list.get(0) {
        Some(t) => t,
        None => {
            eprintln!("Failed to get transport");
            return;
        }
    };

    println!("Transport type: {:?}", transport.get_type());

    println!(
        "Description: {}",
        transport.get_description().unwrap_or("n.a.".to_string())
    );

    // Open the transport
    if let Err(e) = transport.open() {
        eprintln!("Failed to open transport: {:?}", e);
        return;
    }

    println!("Transport opened successfully!");

    // Send authenticatorGetInfo command
    println!("Sending authenticatorGetInfo command...");
    let mut command = match Client::authenticator_get_info(&mut transport) {
        Ok(cmd) => cmd,
        Err(e) => {
            eprintln!("Failed to create authenticatorGetInfo command: {:?}", e);
            return;
        }
    };

    // Get the result
    let result = match command.get_result(timeout_ms) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Failed to get command result: {:?}", e);
            return;
        }
    };

    // Process the result
    if result.is_fulfilled() {
        if let Some(data) = result.get_data() {
            println!("Received authenticator info: {} bytes", data.len());

            // Parse CBOR data
            match ciborium::from_reader::<ciborium::value::Value, _>(data) {
                Ok(info) => {
                    println!("Parsed authenticator info successfully");

                    // Extract and display key information
                    if let ciborium::value::Value::Map(map) = info {
                        for (key, value) in map {
                            match (key, value) {
                                (ciborium::value::Value::Text(k), v) => {
                                    match k.as_str() {
                                        "versions" => println!("  Versions: {:?}", v),
                                        "extensions" => println!("  Extensions: {:?}", v),
                                        "options" => {
                                            println!("  Options: {:?}", v);
                                            // Check for credMgmt support
                                            if let ciborium::value::Value::Map(opts) = &v {
                                                let has_cred_mgmt = opts.iter().any(|(opt_key, opt_val)| {
                                                    matches!(opt_key, ciborium::value::Value::Text(k) if k == "credMgmt" || k == "credentialMgmtPreview")
                                                    && matches!(opt_val, ciborium::value::Value::Bool(true))
                                                });
                                                println!(
                                                    "  Supports credential management: {}",
                                                    has_cred_mgmt
                                                );
                                            }
                                        }
                                        "pinUvAuthProtocols" => {
                                            println!("  PIN/UV protocols: {:?}", v)
                                        }
                                        _ => println!("  {}: {:?}", k, v),
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to parse CBOR: {:?}", e);
                }
            }
        } else {
            println!("No data in response");
        }
    } else if result.is_rejected() {
        if let Some(error_code) = result.get_error() {
            eprintln!("Command failed with error code: {}", error_code);
        } else {
            eprintln!("Command failed");
        }
    } else {
        println!("Command is still pending");
    }

    // Close the transport
    transport.close();
    println!("Transport closed");

    println!("Client example completed successfully!");
}
