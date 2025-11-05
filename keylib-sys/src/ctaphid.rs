use crate::error::Result;
use crate::raw;
use std::ffi::c_void;
use std::marker::PhantomData;

const MAX_DATA_SIZE: usize = 7609;

/// CTAPHID commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Cmd {
    /// Transaction that echoes the data back.
    Ping = 0x01,
    /// Encapsulated CTAP1/U2F message.
    Msg = 0x03,
    /// Place an exclusive lock for one channel
    Lock = 0x04,
    /// Allocate a new CID or synchronize channel.
    Init = 0x06,
    /// Request authenticator to provide some visual or audible identification
    Wink = 0x08,
    /// Encapsulated CTAP CBOR encoded message.
    Cbor = 0x10,
    /// Cancel any outstanding requests on the given CID.
    Cancel = 0x11,
    /// The request is still being processed
    Keepalive = 0x3b,
    /// Error response message (see `ErrorCodes`).
    Error = 0x3f,
}

impl TryFrom<u8> for Cmd {
    type Error = ();

    fn try_from(value: u8) -> core::result::Result<Self, ()> {
        match value {
            0x01 => Ok(Cmd::Ping),
            0x03 => Ok(Cmd::Msg),
            0x04 => Ok(Cmd::Lock),
            0x06 => Ok(Cmd::Init),
            0x08 => Ok(Cmd::Wink),
            0x10 => Ok(Cmd::Cbor),
            0x11 => Ok(Cmd::Cancel),
            0x3b => Ok(Cmd::Keepalive),
            0x3f => Ok(Cmd::Error),
            _ => Err(()),
        }
    }
}

impl From<Cmd> for u8 {
    fn from(cmd: Cmd) -> Self {
        cmd as u8
    }
}

/// Opaque handle for the CTAPHID instance
pub struct Ctaphid {
    inner: *mut c_void,
    /// Shared buffer for all responses - allocated once on the heap
    buffer: Box<[u8; MAX_DATA_SIZE]>,
}

/// Safe wrapper for CTAPHID response with borrowed data
///
/// The lifetime 'a ties this response to the Ctaphid instance that created it,
/// ensuring the borrowed buffer remains valid.
pub struct CtaphidResponse<'a> {
    /// Raw response data from C API
    inner: *mut std::ffi::c_void,
    /// Command type (cached for convenience)
    cmd: Cmd,
    /// CBOR data borrowed from Ctaphid's buffer
    data: &'a [u8],
    _phantom: PhantomData<&'a [u8]>,
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
        Ok(Self {
            inner,
            buffer: Box::new([0u8; MAX_DATA_SIZE]),
        })
    }

    /// Process a single 64-byte HID packet and return a response
    ///
    /// The returned response borrows from this Ctaphid's internal buffer,
    /// so only one response can be active at a time.
    pub fn handle<'a>(&'a mut self, packet: &[u8; 64]) -> Option<CtaphidResponse<'a>> {
        let ptr = packet.as_ptr() as *const i8;
        let len = packet.len();
        let resp = unsafe { raw::ctaphid_handle(self.inner, ptr, len) };
        if resp.is_null() {
            None
        } else {
            // Extract the command from the C response
            let cmd_raw = unsafe { raw::ctaphid_response_get_cmd(resp) } as u8;
            let cmd = match cmd_raw.try_into() {
                Ok(cmd) => cmd,
                Err(_) => return None, // Invalid command
            };

            // Copy data from C API into our buffer
            let data_len = unsafe {
                raw::ctaphid_response_get_data(
                    resp,
                    self.buffer.as_mut_ptr() as *mut i8,
                    self.buffer.len(),
                )
            };

            // SAFETY: We know the data_len is valid because it comes from the C API
            // and we're creating a slice from our own buffer that we control.
            // The lifetime of this slice is tied to &self through the return type.
            let data_slice = &self.buffer[..data_len];

            Some(CtaphidResponse {
                inner: resp,
                cmd,
                data: data_slice,
                _phantom: PhantomData,
            })
        }
    }
}

impl<'a> CtaphidResponse<'a> {
    /// Create a new response from raw C API data
    ///
    /// # Safety
    ///
    /// - `inner` must be a valid pointer returned from the C API that hasn't been freed yet
    /// - `buffer` must outlive the returned CtaphidResponse
    /// - The caller must ensure no other code modifies `buffer` while this response exists
    pub unsafe fn from_raw(
        inner: *mut std::ffi::c_void,
        buffer: &'a mut [u8; MAX_DATA_SIZE],
    ) -> Option<Self> {
        let cmd_raw = raw::ctaphid_response_get_cmd(inner);
        if cmd_raw < 0 {
            return None;
        }

        let cmd = match (cmd_raw as u8).try_into() {
            Ok(cmd) => cmd,
            Err(_) => return None,
        };

        // Copy data from C API into the provided buffer
        let len =
            raw::ctaphid_response_get_data(inner, buffer.as_mut_ptr() as *mut i8, buffer.len());

        Some(CtaphidResponse {
            inner,
            cmd,
            data: &buffer[..len],
            _phantom: PhantomData,
        })
    }

    /// Get the command type
    pub fn command(&self) -> Cmd {
        self.cmd
    }

    /// Get the CBOR data (for CBOR commands)
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Set the response data
    ///
    /// Note: This updates the C API's internal buffer, not our borrowed slice.
    /// After calling this, you should re-create the response to get the updated data.
    pub fn set_data(&mut self, data: &[u8]) -> Result<()> {
        unsafe {
            let result =
                raw::ctaphid_response_set_data(self.inner, data.as_ptr() as *const i8, data.len());
            if result == 0 {
                // Note: We cannot update self.data here since it borrows from Ctaphid's buffer
                // The caller needs to call handle() again to get updated data
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

impl<'a> Drop for CtaphidResponse<'a> {
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
