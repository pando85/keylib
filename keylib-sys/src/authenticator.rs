use super::raw::{
    auth_deinit, auth_init, Callbacks as UnsafeCallbacks, UpResult as RawUpResult,
    UvResult as RawUvResult,
};
use super::raw::{UpResult_UpResult_Accepted, UpResult_UpResult_Denied, UpResult_UpResult_Timeout};
use super::raw::{
    UvResult_UvResult_Accepted, UvResult_UvResult_AcceptedWithUp, UvResult_UvResult_Denied,
    UvResult_UvResult_Timeout,
};
use crate::callbacks::{Callbacks, UpResult, UvResult};
use crate::error::{Error, Result};
use std::ffi::CStr;
use std::sync::{Arc, Mutex};

/// Global storage for callback closures
static CALLBACK_STORAGE: Mutex<Option<Arc<Callbacks>>> = Mutex::new(None);

/// Trampoline function for user presence callback
///
/// # Safety
///
/// - `info`, `user`, and `rp` must be valid null-terminated C strings or null
/// - These pointers must remain valid for the duration of the call
/// - Caller must ensure no data races on global CALLBACK_STORAGE
pub unsafe extern "C" fn up_trampoline(
    info: *const std::os::raw::c_char,
    user: *const std::os::raw::c_char,
    rp: *const std::os::raw::c_char,
) -> RawUpResult {
    let callbacks = match CALLBACK_STORAGE.lock() {
        Ok(guard) => guard.as_ref().cloned(),
        Err(_) => {
            return UpResult_UpResult_Denied;
        }
    };

    if let Some(callbacks) = callbacks {
        if let Some(ref up_cb) = callbacks.up {
            // Convert C strings to Rust strings (truly zero-copy - no allocations)
            // Zig strings are UTF-8, so we can safely assume valid UTF-8
            let info_bytes = unsafe { CStr::from_ptr(info) }.to_bytes();
            let info_str = match std::str::from_utf8(info_bytes) {
                Ok(s) => s,
                Err(_) => return UpResult_UpResult_Denied,
            };

            let user_str = if !user.is_null() {
                let bytes = unsafe { CStr::from_ptr(user) }.to_bytes();
                match std::str::from_utf8(bytes) {
                    Ok(s) => Some(s),
                    Err(_) => return UpResult_UpResult_Denied,
                }
            } else {
                None
            };

            let rp_str = if !rp.is_null() {
                let bytes = unsafe { CStr::from_ptr(rp) }.to_bytes();
                match std::str::from_utf8(bytes) {
                    Ok(s) => Some(s),
                    Err(_) => return UpResult_UpResult_Denied,
                }
            } else {
                None
            };

            // Call the Rust callback with borrowed strings (zero allocations)
            match up_cb(info_str, user_str, rp_str) {
                Ok(UpResult::Accepted) => UpResult_UpResult_Accepted,
                Ok(UpResult::Denied) => UpResult_UpResult_Denied,
                Ok(UpResult::Timeout) => UpResult_UpResult_Timeout,
                Err(_) => UpResult_UpResult_Denied,
            }
        } else {
            UpResult_UpResult_Denied
        }
    } else {
        UpResult_UpResult_Denied
    }
}

/// Trampoline function for user verification callback
///
/// # Safety
///
/// - `info`, `user`, and `rp` must be valid null-terminated C strings or null
/// - These pointers must remain valid for the duration of the call
/// - Caller must ensure no data races on global CALLBACK_STORAGE
pub unsafe extern "C" fn uv_trampoline(
    info: *const std::os::raw::c_char,
    user: *const std::os::raw::c_char,
    rp: *const std::os::raw::c_char,
) -> RawUvResult {
    let callbacks = match CALLBACK_STORAGE.lock() {
        Ok(guard) => guard.as_ref().cloned(),
        Err(_) => return UvResult_UvResult_Denied,
    };

    if let Some(callbacks) = callbacks {
        if let Some(ref uv_cb) = callbacks.uv {
            // Convert C strings to Rust strings (truly zero-copy - no allocations)
            // Zig strings are UTF-8, so we can safely assume valid UTF-8
            let info_bytes = unsafe { CStr::from_ptr(info) }.to_bytes();
            let info_str = match std::str::from_utf8(info_bytes) {
                Ok(s) => s,
                Err(_) => return UvResult_UvResult_Denied,
            };

            let user_str = if !user.is_null() {
                let bytes = unsafe { CStr::from_ptr(user) }.to_bytes();
                match std::str::from_utf8(bytes) {
                    Ok(s) => Some(s),
                    Err(_) => return UvResult_UvResult_Denied,
                }
            } else {
                None
            };

            let rp_str = if !rp.is_null() {
                let bytes = unsafe { CStr::from_ptr(rp) }.to_bytes();
                match std::str::from_utf8(bytes) {
                    Ok(s) => Some(s),
                    Err(_) => return UvResult_UvResult_Denied,
                }
            } else {
                None
            };

            // Call the Rust callback with borrowed strings (zero allocations)
            match uv_cb(info_str, user_str, rp_str) {
                Ok(UvResult::Accepted) => UvResult_UvResult_Accepted,
                Ok(UvResult::AcceptedWithUp) => UvResult_UvResult_AcceptedWithUp,
                Ok(UvResult::Denied) => UvResult_UvResult_Denied,
                Ok(UvResult::Timeout) => UvResult_UvResult_Timeout,
                Err(_) => UvResult_UvResult_Denied,
            }
        } else {
            UvResult_UvResult_Denied
        }
    } else {
        UvResult_UvResult_Denied
    }
}

/// Trampoline function for credential selection callback
///
/// # Safety
///
/// - `rp_id` must be a valid null-terminated C string
/// - `_users` must be a valid pointer to a pointer that can be written to
/// - These pointers must remain valid for the duration of the call
/// - Caller must ensure no data races on global CALLBACK_STORAGE
pub unsafe extern "C" fn select_trampoline(
    rp_id: *const std::os::raw::c_char,
    _users: *mut *mut std::os::raw::c_char,
) -> std::os::raw::c_int {
    let callbacks = match CALLBACK_STORAGE.lock() {
        Ok(guard) => guard.as_ref().cloned(),
        Err(_) => return -6, // Error_Other
    };

    if let Some(callbacks) = callbacks {
        if let Some(ref select_cb) = callbacks.select {
            // Convert C string to Rust string
            let rp_id_str = unsafe { CStr::from_ptr(rp_id) }.to_string_lossy();

            // Call the Rust callback
            match select_cb(&rp_id_str) {
                Ok(_user_list) => {
                    // For now, return success without populating users array
                    // The select callback is not currently used in the Zig library
                    0 // Success
                }
                Err(_) => -6, // Error_Other
            }
        } else {
            -6 // Error_Other - no callback provided
        }
    } else {
        -6 // Error_Other - no callbacks stored
    }
}

/// Trampoline function for read callback
///
/// # Safety
///
/// - `id` and `rp` must be valid null-terminated C strings or null
/// - `out` must be a valid pointer to a pointer that can be written to
/// - These pointers must remain valid for the duration of the call
/// - Caller must ensure no data races on global CALLBACK_STORAGE
pub unsafe extern "C" fn read_trampoline(
    id: *const std::os::raw::c_char,
    rp: *const std::os::raw::c_char,
    out: *mut *mut *mut std::os::raw::c_char,
) -> std::os::raw::c_int {
    let callbacks = match CALLBACK_STORAGE.lock() {
        Ok(guard) => guard.as_ref().cloned(),
        Err(_) => return -6, // Error_Other
    };

    if let Some(callbacks) = callbacks {
        if let Some(ref read_cb) = callbacks.read {
            // Convert C strings to Rust strings
            let id_str = unsafe { CStr::from_ptr(id) }.to_string_lossy();
            let rp_str = unsafe { CStr::from_ptr(rp) }.to_string_lossy();

            // Call the Rust callback
            match read_cb(&id_str, &rp_str) {
                Ok(data) => {
                    // Convert data to C string
                    if data.is_empty() {
                        unsafe {
                            *out = std::ptr::null_mut();
                        }
                        return 0; // Success
                    }

                    // Allocate C string for the data
                    let c_data = unsafe {
                        let ptr = std::alloc::alloc(
                            std::alloc::Layout::array::<std::os::raw::c_char>(data.len() + 1)
                                .unwrap(),
                        ) as *mut std::os::raw::c_char;
                        if ptr.is_null() {
                            return -6; // Error_Other
                        }
                        std::ptr::copy_nonoverlapping(
                            data.as_ptr() as *const std::os::raw::c_char,
                            ptr,
                            data.len(),
                        );
                        *ptr.add(data.len()) = 0; // Null terminate
                        ptr
                    };

                    // Allocate the output array (single element)
                    let array_ptr = unsafe {
                        let ptr = std::alloc::alloc(
                            std::alloc::Layout::array::<*mut std::os::raw::c_char>(2).unwrap(),
                        ) as *mut *mut std::os::raw::c_char;
                        if ptr.is_null() {
                            std::alloc::dealloc(
                                c_data as *mut u8,
                                std::alloc::Layout::array::<std::os::raw::c_char>(data.len() + 1)
                                    .unwrap(),
                            );
                            return -6; // Error_Other
                        }
                        *ptr = c_data;
                        *ptr.add(1) = std::ptr::null_mut(); // Null terminate array
                        ptr
                    };

                    unsafe {
                        *out = array_ptr;
                    }
                    0 // Success
                }
                Err(_) => -6, // Error_Other
            }
        } else {
            -6 // Error_Other - no callback provided
        }
    } else {
        -6 // Error_Other - no callbacks stored
    }
}

/// Trampoline function for credential write callback
///
/// # Safety
///
/// - `id`, `rp`, and `data` must be valid null-terminated C strings
/// - These pointers must remain valid for the duration of the call
/// - Caller must ensure no data races on global CALLBACK_STORAGE
pub unsafe extern "C" fn write_trampoline(
    credential: *const super::raw::FfiCredential,
) -> std::os::raw::c_int {
    let callbacks = match CALLBACK_STORAGE.lock() {
        Ok(guard) => guard.as_ref().cloned(),
        Err(_) => return -6,
    };

    if let Some(callbacks) = callbacks {
        if let Some(ref write_cb) = callbacks.write {
            let ffi_cred = unsafe { &*credential };

            let id_str = match std::str::from_utf8(&ffi_cred.id[..ffi_cred.id_len as usize]) {
                Ok(s) => s,
                Err(_) => return -6,
            };

            let rp_id_str =
                match std::str::from_utf8(&ffi_cred.rp_id[..ffi_cred.rp_id_len as usize]) {
                    Ok(s) => s,
                    Err(_) => return -6,
                };

            let rp_name_str = if ffi_cred.rp_name_len > 0 {
                match std::str::from_utf8(&ffi_cred.rp_name[..ffi_cred.rp_name_len as usize]) {
                    Ok(s) => Some(s),
                    Err(_) => return -6,
                }
            } else {
                None
            };

            let cred_ref = crate::CredentialRef {
                id: &ffi_cred.id[..ffi_cred.id_len as usize],
                rp_id: rp_id_str,
                rp_name: rp_name_str,
                user_id: &ffi_cred.user_id[..ffi_cred.user_id_len as usize],
                sign_count: ffi_cred.sign_count,
                alg: ffi_cred.alg,
                private_key: &ffi_cred.private_key,
                created: ffi_cred.created,
                discoverable: ffi_cred.discoverable != 0,
                cred_protect: Some(ffi_cred.cred_protect),
            };

            match write_cb(id_str, rp_id_str, cred_ref) {
                Ok(()) => 0,
                Err(_) => -6,
            }
        } else {
            -6
        }
    } else {
        -6
    }
}

/// Trampoline function for credential delete callback
///
/// # Safety
///
/// - `id` must be a valid null-terminated C string
/// - This pointer must remain valid for the duration of the call
/// - Caller must ensure no data races on global CALLBACK_STORAGE
pub unsafe extern "C" fn delete_trampoline(id: *const std::os::raw::c_char) -> std::os::raw::c_int {
    let callbacks = match CALLBACK_STORAGE.lock() {
        Ok(guard) => guard.as_ref().cloned(),
        Err(_) => return -6, // Error_Other
    };

    if let Some(callbacks) = callbacks {
        if let Some(ref delete_cb) = callbacks.delete {
            // Convert C string to Rust string
            let id_str = unsafe { CStr::from_ptr(id) }.to_string_lossy();

            // Call the Rust callback
            match delete_cb(&id_str) {
                Ok(()) => 0, // Success
                Err(_) => {
                    -6 // Error_Other
                }
            }
        } else {
            -6 // Error_Other - no callback provided
        }
    } else {
        -6 // Error_Other - no callbacks stored
    }
}

/// Trampoline function for credential read_first callback
///
/// # Safety
///
/// - `id`, `rp`, and `hash` must be valid null-terminated C strings or null
/// - `out` must be a valid pointer to a pointer that can be written to
/// - These pointers must remain valid for the duration of the call
/// - Caller must ensure no data races on global CALLBACK_STORAGE
/// - `hash` must point to exactly 32 bytes of data if not null
/// - `out_data` must be a valid pointer to a pointer that will receive allocated data
/// - `out_len` must be a valid pointer to receive the data length
pub unsafe extern "C" fn read_first_trampoline(
    id: *const std::os::raw::c_char,
    rp: *const std::os::raw::c_char,
    hash: *const std::os::raw::c_char,
    out: *mut super::raw::FfiCredential,
) -> std::os::raw::c_int {
    let callbacks = match CALLBACK_STORAGE.lock() {
        Ok(guard) => guard.as_ref().cloned(),
        Err(_) => return -6,
    };

    if let Some(callbacks) = callbacks {
        if let Some(ref read_first_cb) = callbacks.read_first {
            let id_str = if !id.is_null() {
                Some(unsafe { CStr::from_ptr(id) }.to_string_lossy().into_owned())
            } else {
                None
            };
            let rp_str = if !rp.is_null() {
                Some(unsafe { CStr::from_ptr(rp) }.to_string_lossy().into_owned())
            } else {
                None
            };
            let hash_val = if !hash.is_null() {
                let mut hash_array = [0u8; 32];
                unsafe {
                    std::ptr::copy_nonoverlapping(hash as *const u8, hash_array.as_mut_ptr(), 32);
                }
                Some(hash_array)
            } else {
                None
            };

            let mut state = ITERATION_STATE.lock().unwrap();
            *state = Some(IterationState {
                index: 0,
                filter_user_id: id_str.as_ref().map(|s| s.as_bytes().to_vec()),
                filter_rp_id: rp_str.clone(),
                filter_hash: hash_val,
            });

            match read_first_cb(id_str.as_deref(), rp_str.as_deref(), hash_val) {
                Ok(credential) => {
                    let ffi_out = unsafe { &mut *out };

                    let id_bytes = credential.id.as_slice();
                    let rp_id_bytes = credential.rp.id.as_bytes();
                    let rp_name_bytes = credential
                        .rp
                        .name
                        .as_ref()
                        .map(|s| s.as_bytes())
                        .unwrap_or(&[]);
                    let user_id_bytes = credential.user.id.as_slice();

                    ffi_out.id_len = id_bytes.len().min(64) as u8;
                    ffi_out.id[..ffi_out.id_len as usize]
                        .copy_from_slice(&id_bytes[..ffi_out.id_len as usize]);

                    ffi_out.rp_id_len = rp_id_bytes.len().min(128) as u8;
                    ffi_out.rp_id[..ffi_out.rp_id_len as usize]
                        .copy_from_slice(&rp_id_bytes[..ffi_out.rp_id_len as usize]);

                    ffi_out.rp_name_len = rp_name_bytes.len().min(64) as u8;
                    ffi_out.rp_name[..ffi_out.rp_name_len as usize]
                        .copy_from_slice(&rp_name_bytes[..ffi_out.rp_name_len as usize]);

                    ffi_out.user_id_len = user_id_bytes.len().min(64) as u8;
                    ffi_out.user_id[..ffi_out.user_id_len as usize]
                        .copy_from_slice(&user_id_bytes[..ffi_out.user_id_len as usize]);

                    ffi_out.sign_count = credential.sign_count;
                    ffi_out.alg = credential.alg;
                    ffi_out
                        .private_key
                        .copy_from_slice(&credential.private_key[..32]);
                    ffi_out.created = credential.created;
                    ffi_out.discoverable = if credential.discoverable { 1 } else { 0 };
                    ffi_out.cred_protect = credential.extensions.cred_protect.unwrap_or(0);

                    0
                }
                Err(_) => -6,
            }
        } else {
            -6
        }
    } else {
        -6
    }
}

/// Trampoline function for credential read_next callback
///
/// # Safety
///
/// - `out_data` must be a valid pointer to a pointer that will receive allocated data
/// - `out_len` must be a valid pointer to receive the data length
/// - Caller must ensure no data races on global CALLBACK_STORAGE
pub unsafe extern "C" fn read_next_trampoline(
    out: *mut super::raw::FfiCredential,
) -> std::os::raw::c_int {
    let callbacks = match CALLBACK_STORAGE.lock() {
        Ok(guard) => guard.as_ref().cloned(),
        Err(_) => return -6,
    };

    if let Some(callbacks) = callbacks {
        if let Some(ref read_next_cb) = callbacks.read_next {
            match read_next_cb() {
                Ok(credential) => {
                    let ffi_out = unsafe { &mut *out };

                    let id_bytes = credential.id.as_slice();
                    let rp_id_bytes = credential.rp.id.as_bytes();
                    let rp_name_bytes = credential
                        .rp
                        .name
                        .as_ref()
                        .map(|s| s.as_bytes())
                        .unwrap_or(&[]);
                    let user_id_bytes = credential.user.id.as_slice();

                    ffi_out.id_len = id_bytes.len().min(64) as u8;
                    ffi_out.id[..ffi_out.id_len as usize]
                        .copy_from_slice(&id_bytes[..ffi_out.id_len as usize]);

                    ffi_out.rp_id_len = rp_id_bytes.len().min(128) as u8;
                    ffi_out.rp_id[..ffi_out.rp_id_len as usize]
                        .copy_from_slice(&rp_id_bytes[..ffi_out.rp_id_len as usize]);

                    ffi_out.rp_name_len = rp_name_bytes.len().min(64) as u8;
                    ffi_out.rp_name[..ffi_out.rp_name_len as usize]
                        .copy_from_slice(&rp_name_bytes[..ffi_out.rp_name_len as usize]);

                    ffi_out.user_id_len = user_id_bytes.len().min(64) as u8;
                    ffi_out.user_id[..ffi_out.user_id_len as usize]
                        .copy_from_slice(&user_id_bytes[..ffi_out.user_id_len as usize]);

                    ffi_out.sign_count = credential.sign_count;
                    ffi_out.alg = credential.alg;
                    ffi_out
                        .private_key
                        .copy_from_slice(&credential.private_key[..32]);
                    ffi_out.created = credential.created;
                    ffi_out.discoverable = if credential.discoverable { 1 } else { 0 };
                    ffi_out.cred_protect = credential.extensions.cred_protect.unwrap_or(0);

                    0
                }
                Err(_) => -6,
            }
        } else {
            -6
        }
    } else {
        -6
    }
}

/// Global state for credential iteration
static ITERATION_STATE: Mutex<Option<IterationState>> = Mutex::new(None);

#[derive(Clone)]
#[allow(dead_code)]
struct IterationState {
    index: usize,
    filter_user_id: Option<Vec<u8>>,
    filter_rp_id: Option<String>,
    filter_hash: Option<[u8; 32]>,
}

/// Safe wrapper around the keylib authenticator
pub struct Authenticator {
    inner: *mut std::ffi::c_void,
    _callbacks: Arc<Callbacks>, // Keep callbacks alive
}

impl Authenticator {
    /// Initialize a new authenticator with the given callbacks
    pub fn new(callbacks: Callbacks) -> Result<Self> {
        // Store the callbacks globally for the trampoline functions
        let callbacks_arc = Arc::new(callbacks);
        *CALLBACK_STORAGE.lock().map_err(|_| Error::Other)? = Some(callbacks_arc.clone());

        // Create C-compatible callback structure
        let c_callbacks = UnsafeCallbacks {
            up: Some(up_trampoline),
            uv: Some(uv_trampoline),
            select: Some(select_trampoline),
            read: Some(read_trampoline),
            write: Some(write_trampoline),
            del: Some(delete_trampoline),
            read_first: Some(read_first_trampoline),
            read_next: Some(read_next_trampoline),
        };

        let inner = unsafe { auth_init(c_callbacks) };

        if inner.is_null() {
            return Err(Error::InitializationFailed);
        }

        Ok(Self {
            inner,
            _callbacks: callbacks_arc,
        })
    }

    /// Handle a CTAP message using raw auth_handle function (buffer reuse)
    ///
    /// This is the **preferred method** for handling CTAP requests as it allows
    /// buffer reuse across multiple calls, eliminating heap allocations in hot paths.
    ///
    /// # Arguments
    ///
    /// * `request` - The CTAP request bytes (command byte + CBOR parameters)
    /// * `response` - A mutable buffer that will receive the response. It will be
    ///   resized to exactly 7609 bytes, then truncated to the actual response length.
    ///
    /// # Returns
    ///
    /// The length of the response written into the buffer.
    ///
    /// # Errors
    ///
    /// Returns `Error::Other` if:
    /// - The request is empty or larger than 7609 bytes
    /// - The underlying authenticator returns an empty response
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use keylib_sys::Authenticator;
    /// # fn example(auth: &mut Authenticator) -> Result<(), Box<dyn std::error::Error>> {
    /// // Reuse the same buffer for multiple requests
    /// let mut response_buffer = Vec::new();
    ///
    /// let request1 = vec![0x04]; // authenticatorGetInfo
    /// auth.handle(&request1, &mut response_buffer)?;
    /// println!("Response 1: {} bytes", response_buffer.len());
    ///
    /// let request2 = vec![0x01, /* ... */]; // authenticatorMakeCredential
    /// auth.handle(&request2, &mut response_buffer)?;
    /// println!("Response 2: {} bytes", response_buffer.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn handle(&mut self, request: &[u8], response: &mut Vec<u8>) -> Result<usize> {
        if request.is_empty() || request.len() > 7609 {
            return Err(Error::Other);
        }

        // Resize buffer to maximum response size
        // This is safe and efficient - Vec reuses capacity when possible
        response.resize(7609, 0);

        let response_len = unsafe {
            super::raw::auth_handle(
                self.inner,
                request.as_ptr(),
                request.len(),
                response.as_mut_ptr(),
                response.len(),
            )
        };

        if response_len == 0 {
            return Err(Error::Other);
        }

        // Truncate to actual response size
        response.truncate(response_len);
        Ok(response_len)
    }
}

impl Drop for Authenticator {
    fn drop(&mut self) {
        unsafe {
            auth_deinit(self.inner);
        }
        // Clear the global callback storage
        *CALLBACK_STORAGE.lock().unwrap() = None;
    }
}
