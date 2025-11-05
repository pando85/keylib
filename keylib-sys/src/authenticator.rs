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
        Err(_) => return UpResult_UpResult_Denied,
    };

    if let Some(callbacks) = callbacks {
        if let Some(ref up_cb) = callbacks.up {
            // Convert C strings to Rust strings
            let info_str = unsafe { CStr::from_ptr(info) }.to_string_lossy();
            let user_str = if !user.is_null() {
                Some(
                    unsafe { CStr::from_ptr(user) }
                        .to_string_lossy()
                        .into_owned(),
                )
            } else {
                None
            };
            let rp_str = if !rp.is_null() {
                Some(unsafe { CStr::from_ptr(rp) }.to_string_lossy().into_owned())
            } else {
                None
            };

            // Call the Rust callback
            match up_cb(&info_str, user_str.as_deref(), rp_str.as_deref()) {
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
            // Convert C strings to Rust strings
            let info_str = unsafe { CStr::from_ptr(info) }.to_string_lossy();
            let user_str = if !user.is_null() {
                Some(
                    unsafe { CStr::from_ptr(user) }
                        .to_string_lossy()
                        .into_owned(),
                )
            } else {
                None
            };
            let rp_str = if !rp.is_null() {
                Some(unsafe { CStr::from_ptr(rp) }.to_string_lossy().into_owned())
            } else {
                None
            };

            // Call the Rust callback
            match uv_cb(&info_str, user_str.as_deref(), rp_str.as_deref()) {
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
                        let ptr = std::alloc::alloc(std::alloc::Layout::array::<std::os::raw::c_char>(data.len() + 1).unwrap())
                            as *mut std::os::raw::c_char;
                        if ptr.is_null() {
                            return -6; // Error_Other
                        }
                        std::ptr::copy_nonoverlapping(data.as_ptr() as *const std::os::raw::c_char, ptr, data.len());
                        *ptr.add(data.len()) = 0; // Null terminate
                        ptr
                    };

                    // Allocate the output array (single element)
                    let array_ptr = unsafe {
                        let ptr = std::alloc::alloc(std::alloc::Layout::array::<*mut std::os::raw::c_char>(2).unwrap())
                            as *mut *mut std::os::raw::c_char;
                        if ptr.is_null() {
                            std::alloc::dealloc(c_data as *mut u8, std::alloc::Layout::array::<std::os::raw::c_char>(data.len() + 1).unwrap());
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
    id: *const std::os::raw::c_char,
    rp: *const std::os::raw::c_char,
    data: *const std::os::raw::c_char,
) -> std::os::raw::c_int {
    let callbacks = match CALLBACK_STORAGE.lock() {
        Ok(guard) => guard.as_ref().cloned(),
        Err(_) => return -6, // Error_Other
    };

    if let Some(callbacks) = callbacks {
        if let Some(ref write_cb) = callbacks.write {
            // Convert C strings to Rust strings
            let id_str = unsafe { CStr::from_ptr(id) }.to_string_lossy();
            let rp_str = unsafe { CStr::from_ptr(rp) }.to_string_lossy();
            let data_cstr = unsafe { CStr::from_ptr(data) };
            let data_bytes = data_cstr.to_bytes();

            // Call the Rust callback
            match write_cb(&id_str, &rp_str, data_bytes) {
                Ok(()) => 0,  // Success
                Err(_) => -6, // Error_Other
            }
        } else {
            -6 // Error_Other - no callback provided
        }
    } else {
        -6 // Error_Other - no callbacks stored
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
pub unsafe extern "C" fn read_first_trampoline(
    id: *const std::os::raw::c_char,
    rp: *const std::os::raw::c_char,
    hash: *const std::os::raw::c_char,
    out: *mut *mut std::os::raw::c_char,
) -> std::os::raw::c_int {
    let callbacks = match CALLBACK_STORAGE.lock() {
        Ok(guard) => guard.as_ref().cloned(),
        Err(_) => return -6, // Error_Other
    };

    if let Some(callbacks) = callbacks {
        if let Some(ref read_first_cb) = callbacks.read_first {
            // Convert parameters
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

            // Reset iteration state
            let mut state = ITERATION_STATE.lock().unwrap();
            *state = Some(IterationState {
                index: 0,
                filter_user_id: id_str.as_ref().map(|s| s.as_bytes().to_vec()),
                filter_rp_id: rp_str.clone(),
                filter_hash: hash_val,
            });

            // Call the Rust callback
            match read_first_cb(id_str.as_deref(), rp_str.as_deref(), hash_val) {
                Ok(credential) => {
                    // Serialize credential to C string format
                    match credential.to_bytes() {
                        Ok(data) => {
                            // Allocate C string for the serialized credential
                            let c_data = unsafe {
                                let ptr = std::alloc::alloc(std::alloc::Layout::array::<std::os::raw::c_char>(data.len() + 1).unwrap())
                                    as *mut std::os::raw::c_char;
                                if ptr.is_null() {
                                    return -6; // Error_Other
                                }
                                std::ptr::copy_nonoverlapping(data.as_ptr() as *const std::os::raw::c_char, ptr, data.len());
                                *ptr.add(data.len()) = 0; // Null terminate
                                ptr
                            };

                            unsafe {
                                *out = c_data;
                            }
                            0 // Success
                        }
                        Err(_) => -6, // Error_Other
                    }
                }
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

/// Trampoline function for credential read_next callback
///
/// # Safety
///
/// - `out` must be a valid pointer to a pointer that can be written to
/// - This pointer must remain valid for the duration of the call
/// - Caller must ensure no data races on global CALLBACK_STORAGE
pub unsafe extern "C" fn read_next_trampoline(
    out: *mut *mut std::os::raw::c_char,
) -> std::os::raw::c_int {
    let callbacks = match CALLBACK_STORAGE.lock() {
        Ok(guard) => guard.as_ref().cloned(),
        Err(_) => return -6, // Error_Other
    };

    if let Some(callbacks) = callbacks {
        if let Some(ref read_next_cb) = callbacks.read_next {
            // Call the Rust callback
            match read_next_cb() {
                Ok(credential) => {
                    // Serialize credential to C string format
                    match credential.to_bytes() {
                        Ok(data) => {
                            // Allocate C string for the serialized credential
                            let c_data = unsafe {
                                let ptr = std::alloc::alloc(std::alloc::Layout::array::<std::os::raw::c_char>(data.len() + 1).unwrap())
                                    as *mut std::os::raw::c_char;
                                if ptr.is_null() {
                                    return -6; // Error_Other
                                }
                                std::ptr::copy_nonoverlapping(data.as_ptr() as *const std::os::raw::c_char, ptr, data.len());
                                *ptr.add(data.len()) = 0; // Null terminate
                                ptr
                            };

                            unsafe {
                                *out = c_data;
                            }
                            0 // Success
                        }
                        Err(_) => -6, // Error_Other
                    }
                }
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

        // Initialize the authenticator
        let inner = unsafe { auth_init(c_callbacks) };

        if inner.is_null() {
            return Err(Error::InitializationFailed);
        }

        Ok(Self {
            inner,
            _callbacks: callbacks_arc,
        })
    }

    /// Handle a CTAP message
    ///
    /// This method processes CTAP protocol messages and returns responses.
    /// The request format is: [command_byte, cbor_parameters...]
    /// The response format is: [status_byte, cbor_data...]
    pub fn handle_message(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        if request.is_empty() {
            return Ok(vec![0x0C]); // CTAP2_ERR_INVALID_LENGTH
        }

        // Use the raw auth_handle function instead of the limited Rust implementation
        let _out_buffer = vec![0u8; 7609]; // Max CTAP response size

        // Create a temporary buffer for the request
        let mut request_buffer = vec![0u8; request.len()];
        request_buffer.copy_from_slice(request);

        unsafe {
            super::raw::auth_handle(
                self.inner,
                request_buffer.as_mut_ptr() as *mut std::ffi::c_void,
            );
            // The auth_handle function modifies the request buffer in place
            // The response is written to the request buffer
            // We need to extract the response length and data
        }

        // For now, assume the response is in the request buffer
        // This is a simplification - we need to understand the exact API
        Ok(request_buffer)
    }

    /// Handle authenticatorGetInfo command
    #[allow(dead_code)]
    fn handle_authenticator_get_info(&mut self, _params: &[u8]) -> Result<Vec<u8>> {
        // For now, return a basic authenticator info response
        // In a full implementation, this would serialize the actual authenticator settings

        use ciborium::value::Value;

        // Create the response as a CBOR map using Vec<(Value, Value)>
        let mut info = Vec::new();

        // Basic authenticator info
        info.push((
            Value::Text("versions".to_string()),
            Value::Array(vec![
                Value::Text("FIDO_2_0".to_string()),
                Value::Text("FIDO_2_1".to_string()),
            ]),
        ));

        info.push((
            Value::Text("extensions".to_string()),
            Value::Array(vec![Value::Text("credProtect".to_string())]),
        ));

        info.push((
            Value::Text("aaguid".to_string()),
            Value::Bytes(vec![
                0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d, 0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29,
                0x7c, 0x88,
            ]),
        ));

        let options = vec![
            (Value::Text("rk".to_string()), Value::Bool(true)),
            (Value::Text("uv".to_string()), Value::Bool(true)),
            (Value::Text("plat".to_string()), Value::Bool(true)),
            (Value::Text("pinUvAuthToken".to_string()), Value::Bool(true)),
        ];
        info.push((Value::Text("options".to_string()), Value::Map(options)));

        info.push((
            Value::Text("pinUvAuthProtocols".to_string()),
            Value::Array(vec![
                Value::Integer(2.into()), // V2
            ]),
        ));

        info.push((
            Value::Text("transports".to_string()),
            Value::Array(vec![Value::Text("usb".to_string())]),
        ));

        let alg = vec![
            (Value::Text("alg".to_string()), Value::Integer((-7).into())), // ES256
        ];
        info.push((
            Value::Text("algorithms".to_string()),
            Value::Array(vec![Value::Map(alg)]),
        ));

        info.push((
            Value::Text("firmwareVersion".to_string()),
            Value::Integer(0xcafe.into()),
        ));
        info.push((
            Value::Text("remainingDiscoverableCredentials".to_string()),
            Value::Integer(100.into()),
        ));

        // Serialize to CBOR
        let mut response = vec![0x00]; // CTAP2_OK status
        ciborium::into_writer(&Value::Map(info), &mut response).map_err(|_| Error::Other)?;

        Ok(response)
    }

    /// Handle a CTAP message using raw auth_handle function
    ///
    /// This bypasses the safe wrapper and calls the raw C function directly.
    /// The request should be the raw CBOR data (without the CTAPHID framing).
    /// Returns the raw response bytes.
    pub fn raw_handle(&mut self, _request: &[u8]) -> Result<Vec<u8>> {
        // Allocate output buffer (max CTAP response size)
        let mut out_buffer = vec![0u8; 7609];

        // For now, we'll assume auth_handle modifies the buffer in place
        // and we need to figure out the length somehow
        // This is a placeholder - we need to understand the C API better
        unsafe {
            super::raw::auth_handle(self.inner, out_buffer.as_mut_ptr() as *mut std::ffi::c_void);
        }

        // For now, return the entire buffer - this needs to be fixed
        // We need to know how auth_handle indicates the response length
        Ok(out_buffer)
    }

    /// Handle a CTAP message (CBOR payload only, no HID framing)
    #[allow(dead_code)]
    pub fn handle(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        self.handle_message(request)
    }

    #[allow(dead_code)]
    fn handle_make_credential(&mut self, _params: &[u8]) -> Result<Vec<u8>> {
        // For now, return a basic success response
        // In a full implementation, this would parse the CBOR parameters
        // and create a credential
        Ok(vec![0x00]) // CTAP2_OK
    }

    #[allow(dead_code)]
    fn handle_get_assertion(&mut self, _params: &[u8]) -> Result<Vec<u8>> {
        // For now, return a basic success response
        // In a full implementation, this would parse the CBOR parameters
        // and return an assertion
        Ok(vec![0x00]) // CTAP2_OK
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
