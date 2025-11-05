use crate::raw::{
    cbor_credentials_create, cbor_credentials_get, CredentialAssertionOptions,
    CredentialCreationOptions,
};
use crate::{client::Transport, error::Result, promise::CborPromise};

/// Options for credential creation
#[derive(Debug, Clone)]
pub struct CredentialCreationOptionsRust {
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: Option<String>,
    pub challenge: Vec<u8>,
    pub timeout_ms: Option<u32>,
    pub require_resident_key: bool,
    pub require_user_verification: bool,
    pub attestation: AttestationConveyancePreference,
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
    pub extensions: std::collections::HashMap<String, ciborium::value::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AttestationConveyancePreference {
    None,
    Direct,
    Enterprise,
    Indirect,
}

#[derive(Debug, Clone)]
pub struct PublicKeyCredentialDescriptor {
    pub id: Vec<u8>,
    pub credential_type: String,
    pub transports: Vec<String>,
}

/// Options for credential assertion
#[derive(Debug, Clone)]
pub struct CredentialAssertionOptionsRust {
    pub rp_id: String,
    pub challenge: Vec<u8>,
    pub timeout_ms: Option<u32>,
    pub user_verification: UserVerificationRequirement,
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UserVerificationRequirement {
    Discouraged,
    Preferred,
    Required,
}

pub struct CredentialManager;

impl CredentialManager {
    /// Create a new credential (WebAuthn registration)
    pub fn create(
        transport: &mut Transport,
        options: CredentialCreationOptionsRust,
        _pin_uv_auth: Option<&[u8]>,
        _protocol: Option<u8>,
    ) -> Result<CborPromise> {
        // Convert options to C struct
        let c_options = CredentialCreationOptions {
            challenge: options.challenge.as_ptr() as *const std::os::raw::c_char,
            challenge_len: options.challenge.len(),
            rp_id: options.rp_id.as_ptr() as *const std::os::raw::c_char,
            rp_name: options
                .rp_name
                .as_ref()
                .map(|s| s.as_ptr() as *const std::os::raw::c_char)
                .unwrap_or(std::ptr::null()),
            user_id: options.user_id.as_ptr() as *const std::os::raw::c_char,
            user_id_len: options.user_id.len(),
            user_name: options.user_name.as_ptr() as *const std::os::raw::c_char,
            user_display_name: options
                .user_display_name
                .as_ref()
                .map(|s| s.as_ptr() as *const std::os::raw::c_char)
                .unwrap_or(std::ptr::null()),
            timeout_ms: options.timeout_ms.unwrap_or(30000),
            require_resident_key: if options.require_resident_key { 1 } else { 0 },
            require_user_verification: if options.require_user_verification {
                1
            } else {
                0
            },
            attestation_preference: match options.attestation {
                AttestationConveyancePreference::None => {
                    c"none".as_ptr() as *const std::os::raw::c_char
                }
                AttestationConveyancePreference::Direct => {
                    c"direct".as_ptr() as *const std::os::raw::c_char
                }
                AttestationConveyancePreference::Enterprise => {
                    c"enterprise".as_ptr() as *const std::os::raw::c_char
                }
                AttestationConveyancePreference::Indirect => {
                    c"indirect".as_ptr() as *const std::os::raw::c_char
                }
            },
            exclude_credentials_json: c"[]".as_ptr() as *const std::os::raw::c_char, // TODO: serialize properly
            extensions_json: c"{}".as_ptr() as *const std::os::raw::c_char, // TODO: serialize properly
        };

        // Call C function
        unsafe {
            let cmd =
                cbor_credentials_create(transport.raw_handle(), &c_options as *const _ as *mut _);
            if cmd.is_null() {
                return Err(crate::error::Error::Other);
            }
            Ok(CborPromise::from_raw(
                cmd,
                options.timeout_ms.unwrap_or(30000),
            ))
        }
    }

    /// Get an assertion (WebAuthn authentication)
    pub fn get(
        transport: &mut Transport,
        options: CredentialAssertionOptionsRust,
        _pin_uv_auth: Option<&[u8]>,
        _protocol: Option<u8>,
    ) -> Result<CborPromise> {
        // Convert options to C struct
        let c_options = CredentialAssertionOptions {
            rp_id: options.rp_id.as_ptr() as *const std::os::raw::c_char,
            challenge: options.challenge.as_ptr() as *const std::os::raw::c_char,
            challenge_len: options.challenge.len(),
            timeout_ms: options.timeout_ms.unwrap_or(30000),
            user_verification: match options.user_verification {
                UserVerificationRequirement::Discouraged => {
                    c"discouraged".as_ptr() as *const std::os::raw::c_char
                }
                UserVerificationRequirement::Preferred => {
                    c"preferred".as_ptr() as *const std::os::raw::c_char
                }
                UserVerificationRequirement::Required => {
                    c"required".as_ptr() as *const std::os::raw::c_char
                }
            },
            allow_credentials_json: c"[]".as_ptr() as *const std::os::raw::c_char, // TODO: serialize properly
        };

        // Call C function
        unsafe {
            let cmd =
                cbor_credentials_get(transport.raw_handle(), &c_options as *const _ as *mut _);
            if cmd.is_null() {
                return Err(crate::error::Error::Other);
            }
            Ok(CborPromise::from_raw(
                cmd,
                options.timeout_ms.unwrap_or(30000),
            ))
        }
    }
}
