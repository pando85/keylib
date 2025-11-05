use crate::error::Result;
use crate::raw;
use std::ffi::c_void;
use std::marker::PhantomData;

/// Opaque handle for the CTAPHID instance
pub struct Ctaphid {
    inner: *mut c_void,
}

/// Safe wrapper for CTAPHID response
pub struct CtaphidResponse {
    /// Raw response data from C API
    inner: *mut std::ffi::c_void,
    /// Command type (cached for convenience)
    cmd: u8,
    /// CBOR data (cached for convenience)
    data: Vec<u8>,
    _phantom: PhantomData<*mut std::ffi::c_void>,
}

/// Iterator over CTAPHID response packets
pub struct CtaphidPacketIterator {
    inner: *mut c_void,
}

impl Ctaphid {
    /// Create a new CTAPHID handler
    pub fn new() -> Result<Self> {
        let inner = unsafe { raw::ctaphid_init() };
        if inner.is_null() {
            return Err(crate::error::Error::InitializationFailed);
        }
        Ok(Self { inner })
    }

    /// Process a single 64-byte HID packet and return a response
    pub fn handle(&self, packet: &[u8; 64]) -> Option<CtaphidResponse> {
        let ptr = packet.as_ptr() as *const i8;
        let len = packet.len();
        let resp = unsafe { raw::ctaphid_handle(self.inner, ptr, len) };
        if resp.is_null() {
            None
        } else {
            Some(CtaphidResponse {
                inner: resp,
                cmd: 0x10, // CTAPHID_CBOR
                data: Vec::new(),
                _phantom: PhantomData,
            })
        }
    }
}

impl CtaphidResponse {
    /// Create a new response from raw C API data
    ///
    /// # Safety
    ///
    /// `inner` must be a valid pointer returned from the C API that hasn't been freed yet
    pub unsafe fn new(inner: *mut std::ffi::c_void) -> Option<Self> {
        let cmd = raw::ctaphid_response_get_cmd(inner);
        if cmd < 0 {
            return None;
        }

        // Get the data
        let mut data = vec![0u8; 7609]; // Max CTAP response size
        let len = raw::ctaphid_response_get_data(inner, data.as_mut_ptr() as *mut i8, data.len());
        data.truncate(len);

        Some(CtaphidResponse {
            inner,
            cmd: cmd as u8,
            data,
            _phantom: PhantomData,
        })
    }

    /// Get the command type
    pub fn command(&self) -> u8 {
        self.cmd
    }

    /// Get the CBOR data (for CBOR commands)
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Set the response data
    pub fn set_data(&mut self, data: &[u8]) -> Result<()> {
        unsafe {
            let result =
                raw::ctaphid_response_set_data(self.inner, data.as_ptr() as *const i8, data.len());
            if result == 0 {
                self.data = data.to_vec();
                Ok(())
            } else {
                Err(crate::error::Error::Other)
            }
        }
    }

    /// Create an iterator over response packets
    pub fn packets(&self) -> CtaphidPacketIterator {
        let iter = unsafe { raw::ctaphid_iterator(self.inner) };
        CtaphidPacketIterator { inner: iter }
    }
}

impl Drop for CtaphidResponse {
    fn drop(&mut self) {
        // Note: The C API doesn't seem to have a response cleanup function
        // This might be handled by the iterator cleanup
    }
}

impl Iterator for CtaphidPacketIterator {
    type Item = [u8; 64];

    fn next(&mut self) -> Option<Self::Item> {
        let mut packet = [0i8; 64];
        let result = unsafe { raw::ctaphid_iterator_next(self.inner, packet.as_mut_ptr()) };

        if result > 0 {
            // Convert i8 array to u8 array
            let mut u8_packet = [0u8; 64];
            for i in 0..64 {
                u8_packet[i] = packet[i] as u8;
            }
            Some(u8_packet)
        } else {
            None
        }
    }
}

impl Drop for CtaphidPacketIterator {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            unsafe { raw::ctaphid_iterator_deinit(self.inner) };
        }
    }
}

impl Drop for Ctaphid {
    fn drop(&mut self) {
        unsafe { raw::ctaphid_deinit(self.inner) }
    }
}
