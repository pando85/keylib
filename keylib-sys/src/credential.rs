use crate::error::{Error, Result};
use ciborium::value::Value;
use serde::{Deserialize, Serialize};

/// Borrowed (zero-copy) representation of a FIDO2 credential
///
/// This type is used for FFI callbacks to avoid heap allocations.
/// All fields are borrowed from the FFI struct and have no ownership.
#[derive(Clone, Copy, Debug)]
pub struct CredentialRef<'a> {
    /// User ID (max 64 bytes)
    pub id: &'a [u8],
    /// Relying party ID (max 128 bytes)
    pub rp_id: &'a str,
    /// Relying party name (optional, max 64 bytes)
    pub rp_name: Option<&'a str>,
    /// User ID (max 64 bytes)
    pub user_id: &'a [u8],
    /// Signature counter
    pub sign_count: u32,
    /// Algorithm (-7 for ES256)
    pub alg: i32,
    /// Private key bytes (32 bytes for ES256)
    pub private_key: &'a [u8],
    /// Creation timestamp
    pub created: i64,
    /// Is resident key
    pub discoverable: bool,
    /// Credential protection level
    pub cred_protect: Option<u8>,
}

impl<'a> CredentialRef<'a> {
    /// Convert borrowed credential to owned Credential
    pub fn to_owned(&self) -> Credential {
        Credential {
            id: self.id.to_vec(),
            rp: RelyingParty {
                id: self.rp_id.to_string(),
                name: self.rp_name.map(|s| s.to_string()),
            },
            user: User {
                id: self.user_id.to_vec(),
                name: String::new(),
                display_name: None,
            },
            sign_count: self.sign_count,
            alg: self.alg,
            private_key: self.private_key.to_vec(),
            created: self.created,
            discoverable: self.discoverable,
            extensions: Extensions {
                cred_protect: self.cred_protect,
                hmac_secret: None,
            },
        }
    }
}

/// Safe Rust representation of a FIDO2 credential
#[derive(Clone, Debug)]
pub struct Credential {
    /// User ID (max 64 bytes)
    pub id: Vec<u8>,
    /// Relying party information
    pub rp: RelyingParty,
    /// User information
    pub user: User,
    /// Signature counter
    pub sign_count: u32,
    /// Algorithm (-7 for ES256)
    pub alg: i32,
    /// Private key bytes (32 bytes for ES256)
    pub private_key: Vec<u8>,
    /// Creation timestamp
    pub created: i64,
    /// Is resident key
    pub discoverable: bool,
    /// Extension data
    pub extensions: Extensions,
}

/// Relying party information
#[derive(Clone, Debug)]
pub struct RelyingParty {
    /// RP ID (max 128 bytes)
    pub id: String,
    /// RP name (optional)
    pub name: Option<String>,
}

/// User information
#[derive(Clone, Debug)]
pub struct User {
    /// User handle (max 64 bytes)
    pub id: Vec<u8>,
    /// Username
    pub name: String,
    /// Display name (optional)
    pub display_name: Option<String>,
}

/// Extension data
#[derive(Clone, Debug, Default)]
pub struct Extensions {
    /// Credential protection level
    pub cred_protect: Option<u8>,
    /// HMAC secret extension data
    pub hmac_secret: Option<Vec<u8>>,
}

/// Authenticator metadata/settings
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Meta {
    /// PIN hash (optional)
    pub pin_hash: Option<Vec<u8>>,
    /// PIN retry counter
    pub pin_retries: u8,
}

impl Default for Meta {
    fn default() -> Self {
        Self {
            pin_hash: None,
            pin_retries: 8, // Default PIN retries
        }
    }
}

impl Credential {
    /// Create a new credential
    pub fn new(id: Vec<u8>, rp: RelyingParty, user: User, private_key: Vec<u8>, alg: i32) -> Self {
        Self {
            id,
            rp,
            user,
            sign_count: 0,
            alg,
            private_key,
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            discoverable: true,
            extensions: Extensions::default(),
        }
    }

    /// Serialize credential to CBOR bytes for C API
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        // Create CBOR map matching the format expected by the C library
        let mut map = vec![
            (Value::Text("id".to_string()), Value::Bytes(self.id.clone())),
            (
                Value::Text("rp".to_string()),
                Value::Text(self.rp.id.clone()),
            ),
            (
                Value::Text("user".to_string()),
                Value::Bytes(self.user.id.clone()),
            ),
            (
                Value::Text("signCount".to_string()),
                Value::Integer(self.sign_count.into()),
            ),
            (
                Value::Text("alg".to_string()),
                Value::Integer(self.alg.into()),
            ),
            (
                Value::Text("privateKey".to_string()),
                Value::Bytes(self.private_key.clone()),
            ),
            (
                Value::Text("created".to_string()),
                Value::Integer(self.created.into()),
            ),
            (
                Value::Text("discoverable".to_string()),
                Value::Bool(self.discoverable),
            ),
        ];

        if let Some(ref name) = self.rp.name {
            map.push((
                Value::Text("rp_name".to_string()),
                Value::Text(name.clone()),
            ));
        }

        // Extensions
        if let Some(cred_protect) = self.extensions.cred_protect {
            map.push((
                Value::Text("credProtect".to_string()),
                Value::Integer(cred_protect.into()),
            ));
        }

        if let Some(ref hmac_secret) = self.extensions.hmac_secret {
            map.push((
                Value::Text("hmacSecret".to_string()),
                Value::Bytes(hmac_secret.clone()),
            ));
        }

        // Serialize to CBOR
        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes).map_err(|_| Error::Other)?;
        Ok(bytes)
    }

    /// Deserialize credential from CBOR bytes from C API
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let value: Value = ciborium::from_reader(bytes).map_err(|_| Error::Other)?;

        let map = match value {
            Value::Map(m) => m,
            _ => return Err(Error::Other),
        };

        // Extract fields from CBOR map
        let id = extract_bytes(&map, "id")?;
        let rp_id = extract_string(&map, "rp")?;
        let rp_name = extract_string(&map, "rp_name").ok();
        let user_id = extract_bytes(&map, "user")?;
        let sign_count = extract_u32(&map, "signCount").unwrap_or(0);
        let alg = extract_i32(&map, "alg").unwrap_or(-7);
        let private_key = extract_bytes(&map, "privateKey")?;
        let created = extract_i64(&map, "created").unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
        });
        let discoverable = extract_bool(&map, "discoverable").unwrap_or(true);

        // Extensions
        let cred_protect = extract_u8(&map, "credProtect");
        let hmac_secret = extract_bytes(&map, "hmacSecret").ok();

        let extensions = Extensions {
            cred_protect,
            hmac_secret,
        };

        // Create user and RP structs
        let user = User {
            id: user_id,
            name: String::from_utf8_lossy(&id).to_string(), // Use id as name fallback
            display_name: None,
        };

        let rp = RelyingParty {
            id: rp_id,
            name: rp_name,
        };

        Ok(Self {
            id,
            rp,
            user,
            sign_count,
            alg,
            private_key,
            created,
            discoverable,
            extensions,
        })
    }
}

// Helper functions for CBOR extraction
fn extract_bytes(map: &[(Value, Value)], key: &str) -> Result<Vec<u8>> {
    for (k, v) in map {
        if let Value::Text(k_str) = k {
            if k_str == key {
                if let Value::Bytes(b) = v {
                    return Ok(b.clone());
                }
            }
        }
    }
    Err(Error::Other)
}

fn extract_string(map: &[(Value, Value)], key: &str) -> Result<String> {
    for (k, v) in map {
        if let Value::Text(k_str) = k {
            if k_str == key {
                if let Value::Text(s) = v {
                    return Ok(s.clone());
                }
            }
        }
    }
    Err(Error::Other)
}

fn extract_u32(map: &[(Value, Value)], key: &str) -> Option<u32> {
    for (k, v) in map {
        if let Value::Text(k_str) = k {
            if k_str == key {
                if let Value::Integer(i) = v {
                    return (*i).try_into().ok().map(|v: u32| v);
                }
            }
        }
    }
    None
}

fn extract_i32(map: &[(Value, Value)], key: &str) -> Option<i32> {
    for (k, v) in map {
        if let Value::Text(k_str) = k {
            if k_str == key {
                if let Value::Integer(i) = v {
                    return (*i).try_into().ok().map(|v: i32| v);
                }
            }
        }
    }
    None
}

fn extract_i64(map: &[(Value, Value)], key: &str) -> Option<i64> {
    for (k, v) in map {
        if let Value::Text(k_str) = k {
            if k_str == key {
                if let Value::Integer(i) = v {
                    return (*i).try_into().ok().map(|v: i64| v);
                }
            }
        }
    }
    None
}

fn extract_u8(map: &[(Value, Value)], key: &str) -> Option<u8> {
    for (k, v) in map {
        if let Value::Text(k_str) = k {
            if k_str == key {
                if let Value::Integer(i) = v {
                    return (*i).try_into().ok().map(|v: u8| v);
                }
            }
        }
    }
    None
}

fn extract_bool(map: &[(Value, Value)], key: &str) -> Option<bool> {
    for (k, v) in map {
        if let Value::Text(k_str) = k {
            if k_str == key {
                if let Value::Bool(b) = v {
                    return Some(*b);
                }
            }
        }
    }
    None
}
