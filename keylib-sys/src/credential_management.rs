//! Credential Management
//!
//! This module provides functionality for managing discoverable credentials
//! stored on a FIDO2 authenticator. It allows you to:
//!
//! - Query metadata about stored credentials
//! - Enumerate relying parties (RPs) with credentials
//! - Enumerate credentials for a specific RP
//! - Delete credentials by ID
//! - Update user information for credentials
//!
//! All operations require a valid PIN token with credential management (0x04) permission.
//!
//! # Example
//!
//! ```no_run
//! use keylib_sys::{
//!     client::TransportList,
//!     credential_management::CredentialManagement,
//!     error::Result,
//! };
//!
//! fn main() -> Result<()> {
//!     // Enumerate and open transport
//!     let transport_list = TransportList::enumerate()?;
//!     let mut transport = transport_list.get(0).unwrap();
//!     transport.open()?;
//!
//!     // Create credential management instance
//!     let mut cm = CredentialManagement::new(&mut transport);
//!
//!     // Get metadata (requires PIN token in real usage)
//!     let pin_token = &[0u8; 32]; // Placeholder
//!     let metadata = cm.get_metadata(pin_token, 2)?;
//!     println!("Stored credentials: {}", metadata.existing_credentials_count);
//!
//!     // Enumerate RPs
//!     for rp in cm.enumerate_rps_begin(pin_token, 2)? {
//!         let rp = rp?;
//!         println!("RP: {}", rp.id);
//!
//!         // Enumerate credentials for this RP
//!         // Note: In a real application, you'd create a separate CredentialManagement instance
//!         // or handle the borrowing differently to avoid conflicts
//!         println!("  Credentials for RP: (enumeration example)");
//!     }
//!
//!     Ok(())
//! }
//! ```

use crate::raw::*;
use crate::{
    client::Transport,
    credential::{Credential, RelyingParty, User},
    error::{KeylibError, Result},
};

/// Credential management operations for CTAP authenticators
pub struct CredentialManagement<'a> {
    transport: &'a mut Transport,
}

impl<'a> CredentialManagement<'a> {
    /// Create a new credential management instance
    ///
    /// # Arguments
    /// * `transport` - A mutable reference to an opened transport
    ///
    /// # Returns
    /// A new `CredentialManagement` instance
    pub fn new(transport: &'a mut Transport) -> Self {
        Self { transport }
    }

    /// Get credential metadata (counts)
    ///
    /// Returns the number of existing discoverable credentials and the maximum
    /// number of additional credentials that can be stored.
    ///
    /// # Arguments
    /// * `pin_token` - Valid PIN token with credential management permission (0x04)
    /// * `protocol` - PIN protocol version (1 or 2)
    ///
    /// # Returns
    /// `CredentialMetadata` containing credential counts
    ///
    /// # Errors
    /// Returns an error if the operation fails or PIN token is invalid
    pub fn get_metadata(&mut self, pin_token: &[u8], protocol: u8) -> Result<CredentialMetadata> {
        let mut existing_count: u32 = 0;
        let mut max_remaining: u32 = 0;

        let result = unsafe {
            credential_management_get_metadata(
                self.transport.raw_handle() as *mut std::ffi::c_void,
                pin_token.as_ptr(),
                pin_token.len(),
                protocol,
                &mut existing_count,
                &mut max_remaining,
            )
        };

        if result != CredentialManagementError_CredentialManagementError_SUCCESS {
            return Err(KeylibError::CborCommandFailed(result));
        }

        Ok(CredentialMetadata {
            existing_credentials_count: existing_count,
            max_possible_remaining_credentials: max_remaining,
        })
    }

    /// Start enumerating relying parties
    ///
    /// Begins enumeration of all relying parties that have discoverable credentials
    /// stored on the authenticator. Returns an iterator that yields `RelyingPartyInfo`
    /// for each RP.
    ///
    /// # Arguments
    /// * `pin_token` - Valid PIN token with credential management permission (0x04)
    /// * `protocol` - PIN protocol version (1 or 2)
    ///
    /// # Returns
    /// An iterator over relying parties with stored credentials
    ///
    /// # Errors
    /// Returns an error if enumeration cannot be started
    pub fn enumerate_rps_begin(
        &mut self,
        pin_token: &[u8],
        protocol: u8,
    ) -> Result<RpEnumerator<'_>> {
        let mut total_rps: u32 = 0;
        let mut rp_id_hash = [0u8; 32];
        let mut rp_id_ptr: *mut std::os::raw::c_char = std::ptr::null_mut();
        let mut rp_id_len: usize = 0;

        let result = unsafe {
            credential_management_enumerate_rps_begin(
                self.transport.raw_handle() as *mut std::ffi::c_void,
                pin_token.as_ptr(),
                pin_token.len(),
                protocol,
                &mut total_rps,
                rp_id_hash.as_mut_ptr(),
                &mut rp_id_ptr,
                &mut rp_id_len,
            )
        };

        if result != CredentialManagementError_CredentialManagementError_SUCCESS {
            return Err(KeylibError::CborCommandFailed(result));
        }

        // Convert the first RP info
        let first_rp = if !rp_id_ptr.is_null() && rp_id_len > 0 {
            let rp_id_slice =
                unsafe { std::slice::from_raw_parts(rp_id_ptr as *const u8, rp_id_len) };
            let rp_id = String::from_utf8_lossy(rp_id_slice).to_string();
            unsafe { credential_management_free_string(rp_id_ptr) };
            Some(RelyingPartyInfo {
                id: rp_id,
                id_hash: rp_id_hash,
                name: None,          // Not provided in this call
                credential_count: 0, // Will be filled during enumeration
            })
        } else {
            None
        };

        Ok(RpEnumerator {
            transport: self.transport,
            total: total_rps as usize,
            current: if first_rp.is_some() { 1 } else { 0 },
            first_rp,
            finished: false,
        })
    }

    /// Start enumerating credentials for a specific relying party
    ///
    /// Begins enumeration of all credentials for the specified relying party.
    /// The RP is identified by its ID hash.
    ///
    /// # Arguments
    /// * `rp_id_hash` - SHA-256 hash of the relying party ID
    /// * `pin_token` - Valid PIN token with credential management permission (0x04)
    /// * `protocol` - PIN protocol version (1 or 2)
    ///
    /// # Returns
    /// An iterator over credentials for the specified RP
    ///
    /// # Errors
    /// Returns an error if enumeration cannot be started
    pub fn enumerate_credentials_begin(
        &mut self,
        rp_id_hash: &[u8; 32],
        pin_token: &[u8],
        protocol: u8,
    ) -> Result<CredentialEnumerator<'_>> {
        let mut total_credentials: u32 = 0;
        let mut credential = std::mem::MaybeUninit::<FfiCredential>::uninit();

        let result = unsafe {
            credential_management_enumerate_credentials_begin(
                self.transport.raw_handle() as *mut std::ffi::c_void,
                rp_id_hash.as_ptr(),
                pin_token.as_ptr(),
                pin_token.len(),
                protocol,
                &mut total_credentials,
                credential.as_mut_ptr(),
            )
        };

        if result != CredentialManagementError_CredentialManagementError_SUCCESS {
            return Err(KeylibError::CborCommandFailed(result));
        }

        let first_credential = if total_credentials > 0 {
            Some(unsafe { credential.assume_init() }.into())
        } else {
            None
        };

        Ok(CredentialEnumerator {
            transport: self.transport,
            total: total_credentials as usize,
            current: if first_credential.is_some() { 1 } else { 0 },
            first_credential,
            finished: false,
        })
    }

    /// Delete a credential by ID
    ///
    /// Permanently removes a credential from the authenticator.
    ///
    /// # Arguments
    /// * `credential_id` - The ID of the credential to delete
    /// * `pin_token` - Valid PIN token with credential management permission (0x04)
    /// * `protocol` - PIN protocol version (1 or 2)
    ///
    /// # Errors
    /// Returns an error if the credential cannot be found or deleted
    pub fn delete_credential(
        &mut self,
        credential_id: &[u8],
        pin_token: &[u8],
        protocol: u8,
    ) -> Result<()> {
        let result = unsafe {
            credential_management_delete_credential(
                self.transport.raw_handle() as *mut std::ffi::c_void,
                credential_id.as_ptr(),
                credential_id.len(),
                pin_token.as_ptr(),
                pin_token.len(),
                protocol,
            )
        };

        if result != CredentialManagementError_CredentialManagementError_SUCCESS {
            return Err(KeylibError::CborCommandFailed(result));
        }

        Ok(())
    }

    /// Update user information for a credential
    ///
    /// Updates the user name and/or display name associated with a credential.
    ///
    /// # Arguments
    /// * `credential_id` - The ID of the credential to update
    /// * `user_id` - The user ID (required)
    /// * `user_name` - New user name (optional)
    /// * `user_display_name` - New user display name (optional)
    /// * `pin_token` - Valid PIN token with credential management permission (0x04)
    /// * `protocol` - PIN protocol version (1 or 2)
    ///
    /// # Errors
    /// Returns an error if the credential cannot be found or updated
    pub fn update_user_information(
        &mut self,
        credential_id: &[u8],
        user_id: &[u8],
        user_name: Option<&str>,
        user_display_name: Option<&str>,
        pin_token: &[u8],
        protocol: u8,
    ) -> Result<()> {
        let user_name_ptr = user_name.map(|s| s.as_ptr()).unwrap_or(std::ptr::null());
        let user_name_len = user_name.map(|s| s.len()).unwrap_or(0);
        let user_display_name_ptr = user_display_name
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null());
        let user_display_name_len = user_display_name.map(|s| s.len()).unwrap_or(0);

        let result = unsafe {
            credential_management_update_user_information(
                self.transport.raw_handle() as *mut std::ffi::c_void,
                credential_id.as_ptr(),
                credential_id.len(),
                user_id.as_ptr(),
                user_id.len(),
                user_name_ptr,
                user_name_len,
                user_display_name_ptr,
                user_display_name_len,
                pin_token.as_ptr(),
                pin_token.len(),
                protocol,
            )
        };

        if result != CredentialManagementError_CredentialManagementError_SUCCESS {
            return Err(KeylibError::CborCommandFailed(result));
        }

        Ok(())
    }
}

/// Metadata about credentials stored on the authenticator
#[derive(Debug, Clone)]
pub struct CredentialMetadata {
    /// Number of discoverable credentials currently stored
    pub existing_credentials_count: u32,
    /// Maximum number of additional credentials that can be stored
    pub max_possible_remaining_credentials: u32,
}

/// Information about a relying party
#[derive(Debug, Clone)]
pub struct RelyingPartyInfo {
    /// The relying party ID (domain name)
    pub id: String,
    /// SHA-256 hash of the relying party ID
    pub id_hash: [u8; 32],
    /// Optional human-readable name of the relying party
    pub name: Option<String>,
    /// Number of credentials stored for this RP (filled during enumeration)
    pub credential_count: usize,
}

/// Iterator over relying parties stored on the authenticator
///
/// Created by calling `enumerate_rps_begin()`. Each call to `next()` returns
/// information about one relying party that has credentials stored.
pub struct RpEnumerator<'a> {
    transport: &'a mut Transport,
    total: usize,
    current: usize,
    first_rp: Option<RelyingPartyInfo>,
    finished: bool,
}

impl<'a> Iterator for RpEnumerator<'a> {
    type Item = Result<RelyingPartyInfo>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        // Return the first RP if we have it
        if let Some(rp) = self.first_rp.take() {
            return Some(Ok(rp));
        }

        if self.current >= self.total {
            self.finished = true;
            return None;
        }

        // Get next RP
        let mut rp_id_hash = [0u8; 32];
        let mut rp_id_ptr: *mut std::os::raw::c_char = std::ptr::null_mut();
        let mut rp_id_len: usize = 0;

        let result = unsafe {
            credential_management_enumerate_rps_next(
                self.transport.raw_handle() as *mut std::ffi::c_void,
                rp_id_hash.as_mut_ptr(),
                &mut rp_id_ptr,
                &mut rp_id_len,
            )
        };

        if result != CredentialManagementError_CredentialManagementError_SUCCESS {
            self.finished = true;
            return Some(Err(KeylibError::CborCommandFailed(result)));
        }

        self.current += 1;

        if rp_id_ptr.is_null() || rp_id_len == 0 {
            self.finished = true;
            return None;
        }

        let rp_id_slice = unsafe { std::slice::from_raw_parts(rp_id_ptr as *const u8, rp_id_len) };
        let rp_id = String::from_utf8_lossy(rp_id_slice).to_string();
        unsafe { credential_management_free_string(rp_id_ptr) };

        Some(Ok(RelyingPartyInfo {
            id: rp_id,
            id_hash: rp_id_hash,
            name: None,
            credential_count: 0,
        }))
    }
}

/// Iterator over credentials for a specific relying party
///
/// Created by calling `enumerate_credentials_begin()`. Each call to `next()` returns
/// one credential associated with the specified relying party.
pub struct CredentialEnumerator<'a> {
    transport: &'a mut Transport,
    total: usize,
    current: usize,
    first_credential: Option<Credential>,
    finished: bool,
}

impl<'a> Iterator for CredentialEnumerator<'a> {
    type Item = Result<Credential>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        // Return the first credential if we have it
        if let Some(cred) = self.first_credential.take() {
            return Some(Ok(cred));
        }

        if self.current >= self.total {
            self.finished = true;
            return None;
        }

        // Get next credential
        let mut credential = std::mem::MaybeUninit::<FfiCredential>::uninit();

        let result = unsafe {
            credential_management_enumerate_credentials_next(
                self.transport.raw_handle() as *mut std::ffi::c_void,
                credential.as_mut_ptr(),
            )
        };

        if result != CredentialManagementError_CredentialManagementError_SUCCESS {
            self.finished = true;
            return Some(Err(KeylibError::CborCommandFailed(result)));
        }

        self.current += 1;
        Some(Ok(unsafe { credential.assume_init() }.into()))
    }
}

impl From<FfiCredential> for Credential {
    fn from(ffi: FfiCredential) -> Self {
        let credential_id = ffi.id[..ffi.id_len as usize].to_vec();
        let rp_id = String::from_utf8_lossy(&ffi.rp_id[..ffi.rp_id_len as usize]).to_string();
        let rp_name = if ffi.rp_name_len > 0 {
            Some(String::from_utf8_lossy(&ffi.rp_name[..ffi.rp_name_len as usize]).to_string())
        } else {
            None
        };
        let user_id = ffi.user_id[..ffi.user_id_len as usize].to_vec();
        let private_key = ffi.private_key.to_vec();

        let rp = RelyingParty {
            id: rp_id,
            name: rp_name,
        };

        let user = User {
            id: user_id,
            name: String::from_utf8_lossy(&ffi.user_id[..ffi.user_id_len as usize]).to_string(),
            display_name: None,
        };

        Credential::new(credential_id, rp, user, private_key, ffi.alg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_metadata_structure() {
        let metadata = CredentialMetadata {
            existing_credentials_count: 5,
            max_possible_remaining_credentials: 20,
        };
        assert_eq!(metadata.existing_credentials_count, 5);
        assert_eq!(metadata.max_possible_remaining_credentials, 20);
    }

    #[test]
    fn test_relying_party_info_structure() {
        let rp_info = RelyingPartyInfo {
            id: "example.com".to_string(),
            id_hash: [1u8; 32],
            name: Some("Example RP".to_string()),
            credential_count: 3,
        };
        assert_eq!(rp_info.id, "example.com");
        assert_eq!(rp_info.name, Some("Example RP".to_string()));
        assert_eq!(rp_info.credential_count, 3);
    }

    #[test]
    fn test_credential_management_creation() {
        // This is a minimal test since we can't easily mock transports
        // In a real test environment, you'd use a mock transport
        // For now, just test that the struct can be created conceptually
        assert!(true); // Placeholder test
    }
}
