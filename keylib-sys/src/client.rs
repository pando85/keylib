use std::ffi::CStr;

use crate::error::{Error, Result};
use crate::raw::{
    cbor_authenticator_get_info, cbor_command_free, cbor_command_get_result,
    cbor_command_result_free, transport_close, transport_enumerate, transport_free,
    transport_get_description, transport_get_type, transport_list_free, transport_open,
    transport_read, transport_write, CborCommand as RawCborCommand,
    CborCommandResult as RawCborCommandResult, CborCommandStatus_CborCommandStatus_Fulfilled,
    CborCommandStatus_CborCommandStatus_Pending, CborCommandStatus_CborCommandStatus_Rejected,
    Transport as RawTransport, TransportList as RawTransportList, TransportType,
};

/// Safe Rust wrapper for Transport
pub struct Transport {
    raw: *mut RawTransport,
}

impl Transport {
    /// Open the transport for communication
    pub fn open(&mut self) -> Result<()> {
        let result = unsafe { transport_open(self.raw) };
        if result != 0 {
            return Err(Error::Other);
        }
        Ok(())
    }

    /// Close the transport
    pub fn close(&mut self) {
        unsafe { transport_close(self.raw) };
    }

    /// Write data to the transport
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        let result = unsafe {
            transport_write(
                self.raw,
                data.as_ptr() as *const ::std::os::raw::c_char,
                data.len(),
            )
        };
        if result != 0 {
            return Err(Error::Other);
        }
        Ok(())
    }

    /// Read data from the transport with timeout
    pub fn read(&mut self, buffer: &mut [u8], timeout_ms: i32) -> Result<usize> {
        let result = unsafe {
            transport_read(
                self.raw,
                buffer.as_mut_ptr() as *mut ::std::os::raw::c_char,
                buffer.len(),
                timeout_ms,
            )
        };
        if result < 0 {
            return Err(Error::Other);
        }
        Ok(result as usize)
    }

    /// Get the transport type
    pub fn get_type(&self) -> TransportType {
        unsafe { transport_get_type(self.raw) }
    }

    /// Get the raw transport handle (for internal use)
    pub fn raw_handle(&self) -> *mut RawTransport {
        self.raw
    }

    /// Get a description of the transport
    pub fn get_description(&self) -> Result<String> {
        let description_bytes = unsafe {
            let description = transport_get_description(self.raw);
            CStr::from_ptr(description).to_bytes()
        };
        let description_str = match std::str::from_utf8(description_bytes) {
            Ok(s) => s,
            Err(_) => return Err(Error::Other),
        };
        Ok(description_str.to_string())
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        unsafe { transport_free(self.raw) };
    }
}

/// Safe Rust wrapper for TransportList
pub struct TransportList {
    raw: Option<*mut RawTransportList>,
}

impl TransportList {
    /// Enumerate all available transports
    pub fn enumerate() -> Result<Self> {
        let raw = unsafe { transport_enumerate() };
        Ok(TransportList {
            raw: if raw.is_null() { None } else { Some(raw) },
        })
    }

    /// Get the number of transports
    pub fn len(&self) -> usize {
        self.raw.map_or(0, |raw| unsafe { (*raw).count })
    }

    /// Check if the list is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get a transport at the given index
    pub fn get(&self, index: usize) -> Option<Transport> {
        if index >= self.len() {
            return None;
        }
        let raw = self.raw?;
        let transport_ptr = unsafe { *(*raw).transports.add(index) };
        if transport_ptr.is_null() {
            return None;
        }
        Some(Transport { raw: transport_ptr })
    }

    /// Iterate over all transports
    pub fn iter(&self) -> TransportListIter<'_> {
        TransportListIter {
            list: self,
            index: 0,
        }
    }
}

impl Drop for TransportList {
    fn drop(&mut self) {
        if let Some(raw) = self.raw {
            unsafe { transport_list_free(raw) };
        }
    }
}

/// Iterator for TransportList
pub struct TransportListIter<'a> {
    list: &'a TransportList,
    index: usize,
}

impl<'a> Iterator for TransportListIter<'a> {
    type Item = Transport;

    fn next(&mut self) -> Option<Self::Item> {
        let transport = self.list.get(self.index);
        if transport.is_some() {
            self.index += 1;
        }
        transport
    }
}

/// Safe Rust wrapper for CborCommand
pub struct CborCommand {
    raw: *mut RawCborCommand,
}

impl CborCommand {
    /// Get the result of the CBOR command with timeout
    pub fn get_result(&mut self, timeout_ms: i32) -> Result<CborCommandResult> {
        let result_raw = unsafe { cbor_command_get_result(self.raw, timeout_ms) };
        if result_raw.is_null() {
            return Err(Error::Timeout);
        }
        Ok(CborCommandResult { raw: result_raw })
    }
}

impl Drop for CborCommand {
    fn drop(&mut self) {
        unsafe { cbor_command_free(self.raw) };
    }
}

/// Safe Rust wrapper for CborCommandResult
pub struct CborCommandResult {
    pub(crate) raw: *mut RawCborCommandResult,
}

impl CborCommandResult {
    /// Check if the command is still pending
    pub fn is_pending(&self) -> bool {
        unsafe { (*self.raw).status == CborCommandStatus_CborCommandStatus_Pending }
    }

    /// Check if the command completed successfully
    pub fn is_fulfilled(&self) -> bool {
        unsafe { (*self.raw).status == CborCommandStatus_CborCommandStatus_Fulfilled }
    }

    /// Check if the command failed
    pub fn is_rejected(&self) -> bool {
        unsafe { (*self.raw).status == CborCommandStatus_CborCommandStatus_Rejected }
    }

    /// Get the data if the command was fulfilled
    pub fn get_data(&self) -> Option<&[u8]> {
        if !self.is_fulfilled() {
            return None;
        }
        let data_ptr = unsafe { (*self.raw).result.data };
        if data_ptr.is_null() {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts(data_ptr as *const u8, (*self.raw).data_len) })
    }

    /// Get the error code if the command was rejected
    pub fn get_error(&self) -> Option<i32> {
        if !self.is_rejected() {
            return None;
        }
        Some(unsafe { (*self.raw).result.error_code })
    }
}

impl Drop for CborCommandResult {
    fn drop(&mut self) {
        unsafe { cbor_command_result_free(self.raw) };
    }
}

/// Client for communicating with FIDO2 authenticators
pub struct Client;

impl Client {
    /// Enumerate all available transports
    pub fn enumerate_transports() -> Result<TransportList> {
        TransportList::enumerate()
    }

    /// Send authenticatorGetInfo command
    pub fn authenticator_get_info(transport: &mut Transport) -> Result<CborCommand> {
        let cmd_raw = unsafe { cbor_authenticator_get_info(transport.raw) };
        if cmd_raw.is_null() {
            return Err(Error::Other);
        }
        Ok(CborCommand { raw: cmd_raw })
    }

    /// Create a new credential (WebAuthn registration)
    pub fn credentials_create(
        _transport: &mut Transport,
        _options: crate::credentials::CredentialCreationOptionsRust,
        _pin_uv_auth: Option<&[u8]>,
        _protocol: Option<u8>,
    ) -> Result<CborCommand> {
        // TODO: Serialize options to CBOR
        // TODO: Call underlying C API cbor_credentials_create
        // TODO: Return command

        // Placeholder - return error for now
        Err(Error::Other)
    }

    /// Get an assertion (WebAuthn authentication)
    pub fn credentials_get(
        _transport: &mut Transport,
        _options: crate::credentials::CredentialAssertionOptionsRust,
        _pin_uv_auth: Option<&[u8]>,
        _protocol: Option<u8>,
    ) -> Result<CborCommand> {
        // TODO: Serialize options to CBOR
        // TODO: Call underlying C API cbor_credentials_get
        // TODO: Return command

        // Placeholder - return error for now
        Err(Error::Other)
    }
}
