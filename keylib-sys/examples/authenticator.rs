use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use keylib_sys::callbacks::{UpResult, UvResult};
use keylib_sys::ctaphid::Ctaphid;
use keylib_sys::error::Result;
use keylib_sys::uhid::Uhid;
use keylib_sys::*;

use sha2::{Digest, Sha256};

const UHID_ERROR_MESSAGE: &str =
    "Make sure you have the uhid kernel module loaded and proper permissions.\n\
Run the following commands as root:\n\
  modprobe uhid\n\
  groupadd fido 2>/dev/null || true\n\
  usermod -a -G fido $USER\n\
  echo 'KERNEL==\"uhid\", GROUP=\"fido\", MODE=\"0660\"' > /etc/udev/rules.d/90-uinput.rules\n\
  udevadm control --reload-rules && udevadm trigger";

// Credential storage implementation matching Zig example
// (Using library types now)

#[derive(Clone)]
struct CredentialStore {
    credentials: HashMap<Vec<u8>, keylib_sys::Credential>,
    iteration_index: usize,
    iteration_filter: IterationFilter,
}

#[derive(Clone)]
enum IterationFilter {
    None,
    ById(Vec<u8>),
    ByRp(String),
    ByHash([u8; 32]),
}

impl CredentialStore {
    fn new() -> Self {
        Self {
            credentials: HashMap::new(),
            iteration_index: 0,
            iteration_filter: IterationFilter::None,
        }
    }

    fn read_first(
        &mut self,
        id: Option<&str>,
        rp: Option<&str>,
        hash: Option<[u8; 32]>,
    ) -> Result<keylib_sys::Credential> {
        // Reset iteration
        self.iteration_index = 0;

        // Set filter
        self.iteration_filter = if let Some(id) = id {
            IterationFilter::ById(id.as_bytes().to_vec())
        } else if let Some(rp) = rp {
            IterationFilter::ByRp(rp.to_string())
        } else if let Some(hash) = hash {
            IterationFilter::ByHash(hash)
        } else {
            IterationFilter::None
        };

        // Find first matching credential
        self.find_next()
    }

    fn read_next(&mut self) -> Result<keylib_sys::Credential> {
        self.find_next()
    }

    fn find_next(&mut self) -> Result<keylib_sys::Credential> {
        // Iterate through credentials based on filter
        let credentials: Vec<_> = self.credentials.values().collect();

        while self.iteration_index < credentials.len() {
            let cred = &credentials[self.iteration_index];
            self.iteration_index += 1;

            let matches = match &self.iteration_filter {
                IterationFilter::None => true,
                IterationFilter::ById(id) => &cred.user.id == id,
                IterationFilter::ByRp(rp) => &cred.rp.id == rp,
                IterationFilter::ByHash(hash) => {
                    // Hash RP ID and compare
                    let mut hasher = Sha256::new();
                    hasher.update(cred.rp.id.as_bytes());
                    let rp_hash: [u8; 32] = hasher.finalize().into();
                    &rp_hash == hash
                }
            };

            if matches {
                return Ok((*cred).clone());
            }
        }

        Err(keylib_sys::Error::DoesNotExist)
    }

    fn write(&mut self, cred: keylib_sys::Credential) -> Result<()> {
        self.credentials.insert(cred.user.id.clone(), cred);
        Ok(())
    }

    fn delete(&mut self, id: &str) -> Result<()> {
        let key = id.as_bytes().to_vec();
        self.credentials
            .remove(&key)
            .ok_or(keylib_sys::Error::DoesNotExist)?;
        Ok(())
    }

    fn select_users(&self, rp_id: &str) -> Vec<String> {
        self.credentials
            .values()
            .filter(|cred| cred.rp.id == rp_id)
            .map(|cred| cred.user.name.clone())
            .collect()
    }
}

lazy_static::lazy_static! {
    static ref CREDENTIAL_STORE: Arc<Mutex<CredentialStore>> =
        Arc::new(Mutex::new(CredentialStore::new()));
}

fn main() -> Result<()> {
    println!("Keylib Rust FIDO2 Authenticator");

    // Create callbacks
    let up_callback = Arc::new(
        |info: &str, user: Option<&str>, rp: Option<&str>| -> Result<UpResult> {
            println!("🔐 User Presence requested:");
            println!("   Context: {}", info);
            if let Some(user) = user {
                println!("   User: {}", user);
            }
            if let Some(rp) = rp {
                println!("   Relying Party: {}", rp);
            }
            println!("   → Accepting user presence");
            Ok(UpResult::Accepted)
        },
    );

    let uv_callback = Arc::new(
        |info: &str, user: Option<&str>, rp: Option<&str>| -> Result<UvResult> {
            println!("👤 User Verification requested:");
            println!("   Context: {}", info);
            if let Some(user) = user {
                println!("   User: {}", user);
            }
            if let Some(rp) = rp {
                println!("   Relying Party: {}", rp);
            }
            println!("   → Accepting user verification");
            Ok(UvResult::Accepted)
        },
    );

    let select_callback = Arc::new(|rp_id: &str| -> Result<Vec<String>> {
        println!("🔍 Select callback: Looking for users for RP '{}'", rp_id);
        let store = CREDENTIAL_STORE.lock().unwrap();
        let users = store.select_users(rp_id);
        println!("   Found {} users: {:?}", users.len(), users);
        Ok(users)
    });

    let read_callback = Arc::new(|id: &str, rp: &str| -> Result<Vec<u8>> {
        println!(
            "📖 Read callback: Reading credential for user '{}' at RP '{}'",
            id, rp
        );

        // For the C API, we need to implement read_first/read_next logic here
        // Since the C API doesn't support iteration, we'll return the first matching credential
        let mut store = CREDENTIAL_STORE.lock().unwrap();
        match store.read_first(Some(id), Some(rp), None) {
            Ok(cred) => {
                println!("   Found credential, serializing...");
                match cred.to_bytes() {
                    Ok(bytes) => {
                        println!("   Returning {} bytes of credential data", bytes.len());
                        Ok(bytes)
                    }
                    Err(e) => {
                        println!("   Failed to serialize credential: {:?}", e);
                        Err(e)
                    }
                }
            }
            Err(_) => {
                println!("   No credential found");
                Err(keylib_sys::Error::DoesNotExist)
            }
        }
    });

    let write_callback = Arc::new(|id: &str, rp: &str, data: &[u8]| -> Result<()> {
        println!(
            "💾 Write callback: Storing {} bytes for user '{}' at RP '{}'",
            data.len(),
            id,
            rp
        );

        // Parse data into Credential
        match keylib_sys::Credential::from_bytes(data) {
            Ok(mut cred) => {
                // Update sign count and other fields
                cred.sign_count = 0;
                cred.created = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as i64;
                cred.discoverable = true;

                let mut store = CREDENTIAL_STORE.lock().unwrap();
                store.write(cred)?;
                println!("   Credential stored successfully");
                Ok(())
            }
            Err(e) => {
                println!("   Failed to parse credential data: {:?}", e);
                Err(e)
            }
        }
    });

    let delete_callback = Arc::new(|id: &str| -> Result<()> {
        println!("🗑️  Delete callback: Deleting credential for user '{}'", id);
        let mut store = CREDENTIAL_STORE.lock().unwrap();
        store.delete(id)
    });

    let read_first_callback = Arc::new(
        |id: Option<&str>,
         rp: Option<&str>,
         hash: Option<[u8; 32]>|
         -> Result<keylib_sys::Credential> {
            println!("📖 Read first callback: Starting iteration with filters - id: {:?}, rp: {:?}, hash: {:?}", id, rp, hash);
            let mut store = CREDENTIAL_STORE.lock().unwrap();
            store.read_first(id, rp, hash)
        },
    );

    let read_next_callback = Arc::new(|| -> Result<keylib_sys::Credential> {
        println!("📖 Read next callback: Continuing iteration");
        let mut store = CREDENTIAL_STORE.lock().unwrap();
        store.read_next()
    });

    let callbacks = Callbacks::new(
        Some(up_callback),
        Some(uv_callback),
        Some(select_callback),
        Some(read_callback),
        Some(write_callback),
        Some(delete_callback),
        Some(read_first_callback),
        Some(read_next_callback),
    );

    // Initialize authenticator
    let mut auth = Authenticator::new(callbacks)?;
    println!("✅ Authenticator initialized");

    // Initialize CTAPHID handler
    let ctaphid = Ctaphid::new()?;
    println!("✅ CTAPHID initialized");

    // Open UHID device
    let uhid = Uhid::open().map_err(|e| {
        eprintln!("❌ Failed to open UHID device");
        eprintln!("{}", UHID_ERROR_MESSAGE);
        e
    })?;
    println!("✅ UHID device opened");

    println!("\n🚀 Authenticator is running!");
    println!("   Listening for USB HID messages...");
    println!("   Press Ctrl+C to stop\n");

    // Main loop
    let mut buffer = [0u8; 64];
    loop {
        // Read USB packet
        match uhid.read_packet(&mut buffer) {
            Ok(0) => {
                // No data, sleep briefly
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            Ok(n) => {
                println!("📦 Received {} bytes from USB", n);

                // Handle packet with CTAPHID
                if let Some(mut response) = ctaphid.handle(&buffer) {
                    match response.command() {
                        0x10 => {
                            // CTAPHID_CBOR
                            println!("🔄 Processing CBOR command");

                            // Call authenticator with the CBOR data
                            match auth.handle(response.data()) {
                                Ok(response_data) => {
                                    // Set the response data back
                                    if let Err(e) = response.set_data(&response_data) {
                                        eprintln!("❌ Failed to set response data: {:?}", e);
                                        continue;
                                    }
                                    println!("✅ Authenticator processed request successfully");
                                }
                                Err(e) => {
                                    eprintln!("❌ Authenticator error: {:?}", e);
                                    // For errors, we could set error response data
                                    // For now, just continue
                                    continue;
                                }
                            }
                        }
                        _ => {
                            println!("ℹ️  Non-CBOR command: {:02x}", response.command());
                        }
                    }

                    // Send response packets back
                    for packet in response.packets() {
                        uhid.write_packet(&packet)?;
                        println!("📤 Sent packet to USB");
                    }
                }
            }
            Err(e) => {
                eprintln!("❌ Error reading USB packet: {:?}", e);
                break;
            }
        }
    }

    println!("\n✅ Authenticator stopped");
    Ok(())
}
