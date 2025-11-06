use crate::error::Result;
use std::sync::Arc;
use std::sync::Mutex;

use crate::authenticator::{
    delete_trampoline, read_first_trampoline, read_next_trampoline, read_trampoline,
    select_trampoline, up_trampoline, uv_trampoline, write_trampoline,
};
use crate::raw::Callbacks as UnsafeCallbacks;

/// Global trampoline storage used by the raw callbacks
static CALLBACK_STORAGE: Mutex<Option<Arc<Callbacks>>> = Mutex::new(None);

/// User presence result
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UpResult {
    /// The user has denied the action
    Denied,
    /// The user has accepted the action
    Accepted,
    /// The user presence check has timed out
    Timeout,
}

/// User verification result
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UvResult {
    /// The user has denied the action
    Denied,
    /// The user has accepted the action
    Accepted,
    /// The user has accepted the action with user presence
    AcceptedWithUp,
    /// The user verification check has timed out
    Timeout,
}

/// User presence callback type
pub type UpCallback =
    Arc<dyn Fn(&str, Option<&str>, Option<&str>) -> Result<UpResult> + Send + Sync>;

/// User verification callback type
pub type UvCallback =
    Arc<dyn Fn(&str, Option<&str>, Option<&str>) -> Result<UvResult> + Send + Sync>;

/// Select callback type for choosing which user to authenticate with
pub type SelectCallback = Arc<dyn Fn(&str) -> Result<Vec<String>> + Send + Sync>;

/// Read callback type for retrieving credential data
pub type ReadCallback = Arc<dyn Fn(&str, &str) -> Result<Vec<u8>> + Send + Sync>;

/// Write callback type for storing credential data (zero-copy)
///
/// The credential data is borrowed from the FFI layer and is only valid
/// during the callback invocation. Use `CredentialRef::to_owned()` if you
/// need to store the credential beyond the callback scope.
pub type WriteCallback = Arc<dyn Fn(&str, &str, crate::CredentialRef) -> Result<()> + Send + Sync>;

/// Delete callback type for removing credential data
pub type DeleteCallback = Arc<dyn Fn(&str) -> Result<()> + Send + Sync>;

/// Read first callback type for starting credential iteration
pub type ReadFirstCallback = Arc<
    dyn Fn(Option<&str>, Option<&str>, Option<[u8; 32]>) -> Result<crate::Credential> + Send + Sync,
>;

/// Read next callback type for continuing credential iteration
pub type ReadNextCallback = Arc<dyn Fn() -> Result<crate::Credential> + Send + Sync>;

/// Safe callback wrapper that handles the unsafe FFI boundary
#[derive(Clone)]
pub struct Callbacks {
    pub up: Option<UpCallback>,
    pub uv: Option<UvCallback>,
    pub select: Option<SelectCallback>,
    pub read: Option<ReadCallback>,
    pub write: Option<WriteCallback>,
    pub delete: Option<DeleteCallback>,
    pub read_first: Option<ReadFirstCallback>,
    pub read_next: Option<ReadNextCallback>,
}

/// Builder for creating Callbacks instances
#[derive(Default)]
pub struct CallbacksBuilder {
    up: Option<UpCallback>,
    uv: Option<UvCallback>,
    select: Option<SelectCallback>,
    read: Option<ReadCallback>,
    write: Option<WriteCallback>,
    delete: Option<DeleteCallback>,
    read_first: Option<ReadFirstCallback>,
    read_next: Option<ReadNextCallback>,
}

impl CallbacksBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the user presence callback
    pub fn up(mut self, callback: UpCallback) -> Self {
        self.up = Some(callback);
        self
    }

    /// Set the user verification callback
    pub fn uv(mut self, callback: UvCallback) -> Self {
        self.uv = Some(callback);
        self
    }

    /// Set the credential selection callback
    pub fn select(mut self, callback: SelectCallback) -> Self {
        self.select = Some(callback);
        self
    }

    /// Set the credential read callback
    pub fn read(mut self, callback: ReadCallback) -> Self {
        self.read = Some(callback);
        self
    }

    /// Set the credential write callback
    pub fn write(mut self, callback: WriteCallback) -> Self {
        self.write = Some(callback);
        self
    }

    /// Set the credential delete callback
    pub fn delete(mut self, callback: DeleteCallback) -> Self {
        self.delete = Some(callback);
        self
    }

    /// Set the credential read_first callback
    pub fn read_first(mut self, callback: ReadFirstCallback) -> Self {
        self.read_first = Some(callback);
        self
    }

    /// Set the credential read_next callback
    pub fn read_next(mut self, callback: ReadNextCallback) -> Self {
        self.read_next = Some(callback);
        self
    }

    /// Build the Callbacks instance
    pub fn build(self) -> Callbacks {
        Callbacks {
            up: self.up,
            uv: self.uv,
            select: self.select,
            read: self.read,
            write: self.write,
            delete: self.delete,
            read_first: self.read_first,
            read_next: self.read_next,
        }
    }
}

impl Callbacks {
    /// Create a new Callbacks instance with the given user presence and verification callbacks
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        up: Option<UpCallback>,
        uv: Option<UvCallback>,
        select: Option<SelectCallback>,
        read: Option<ReadCallback>,
        write: Option<WriteCallback>,
        delete: Option<DeleteCallback>,
        read_first: Option<ReadFirstCallback>,
        read_next: Option<ReadNextCallback>,
    ) -> Self {
        Self {
            up,
            uv,
            select,
            read,
            write,
            delete,
            read_first,
            read_next,
        }
    }

    /// Convert into the raw UnsafeCallbacks used by the C API.
    /// This stores the Arc in a global so trampolines can access it.
    pub fn into_raw(self) -> UnsafeCallbacks {
        // store in global
        let arc = Arc::new(self);
        *CALLBACK_STORAGE.lock().unwrap() = Some(arc.clone());

        // trampolines will read from CALLBACK_STORAGE
        UnsafeCallbacks {
            up: Some(up_trampoline),
            uv: Some(uv_trampoline),
            select: Some(select_trampoline),
            read: Some(read_trampoline),
            write: Some(write_trampoline),
            del: Some(delete_trampoline),
            read_first: Some(read_first_trampoline),
            read_next: Some(read_next_trampoline),
        }
    }
}

impl Default for Callbacks {
    fn default() -> Self {
        Self::new(None, None, None, None, None, None, None, None)
    }
}
