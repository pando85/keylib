use crate::error::Result;
use crate::raw;

/// Safe wrapper around the UHID device
pub struct Uhid {
    fd: i32,
}

impl Uhid {
    /// Open a UHID device. Returns Err if opening failed.
    pub fn open() -> Result<Self> {
        let fd = unsafe { raw::uhid_open() };
        if fd < 0 {
            return Err(crate::error::Error::Other);
        }
        Ok(Self { fd })
    }

    /// Read a 64-byte HID packet. Returns the number of bytes read.
    pub fn read_packet(&self, out: &mut [u8; 64]) -> Result<usize> {
        let ptr = out.as_mut_ptr() as *mut i8;
        let r = unsafe { raw::uhid_read_packet(self.fd, ptr) };
        if r < 0 {
            return Err(crate::error::Error::Other);
        }
        Ok(r as usize)
    }

    /// Write a 64-byte HID packet. Returns the number of bytes written.
    pub fn write_packet(&self, data: &[u8; 64]) -> Result<usize> {
        // Convert u8 array to i8 array for C API
        let mut i8_data = [0i8; 64];
        for i in 0..64 {
            i8_data[i] = data[i] as i8;
        }

        let r = unsafe { raw::uhid_write_packet(self.fd, i8_data.as_ptr() as *mut i8, 64) };
        if r < 0 {
            return Err(crate::error::Error::Other);
        }
        Ok(r as usize)
    }
}

impl Drop for Uhid {
    fn drop(&mut self) {
        unsafe { raw::uhid_close(self.fd) }
    }
}
