use std::fmt;

/// Errors that can occur when using the keylib API
#[derive(Debug, Clone, PartialEq)]
pub enum KeylibError {
    /// The given operation was successful
    Success,
    /// The given value already exists
    DoesAlreadyExist,
    /// The requested value doesn't exist
    DoesNotExist,
    /// Credentials can't be inserted into the key-store
    KeyStoreFull,
    /// The client ran out of memory
    OutOfMemory,
    /// The operation timed out
    Timeout,
    /// Unspecified operation
    Other,
    /// Initialization failed
    InitializationFailed,
    /// Invalid callback result
    InvalidCallbackResult,
    /// CBOR command failed
    CborCommandFailed(i32),
}

impl fmt::Display for KeylibError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeylibError::Success => write!(f, "Success"),
            KeylibError::DoesAlreadyExist => write!(f, "Value already exists"),
            KeylibError::DoesNotExist => write!(f, "Value does not exist"),
            KeylibError::KeyStoreFull => write!(f, "Key store is full"),
            KeylibError::OutOfMemory => write!(f, "Out of memory"),
            KeylibError::Timeout => write!(f, "Operation timed out"),
            KeylibError::Other => write!(f, "Unspecified error"),
            KeylibError::InitializationFailed => write!(f, "Initialization failed"),
            KeylibError::InvalidCallbackResult => write!(f, "Invalid callback result"),
            KeylibError::CborCommandFailed(code) => {
                write!(f, "CBOR command failed with code {}", code)
            }
        }
    }
}

impl std::error::Error for KeylibError {}

impl From<i32> for KeylibError {
    fn from(value: i32) -> Self {
        match value {
            0 => KeylibError::Success,
            -1 => KeylibError::DoesAlreadyExist,
            -2 => KeylibError::DoesNotExist,
            -3 => KeylibError::KeyStoreFull,
            -4 => KeylibError::OutOfMemory,
            -5 => KeylibError::Timeout,
            -6 => KeylibError::Other,
            _ => KeylibError::CborCommandFailed(value),
        }
    }
}

/// Result type alias for keylib operations
pub type Result<T> = std::result::Result<T, KeylibError>;

/// Alias for backward compatibility
pub type Error = KeylibError;
