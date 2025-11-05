#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub mod raw {
    // include the generated bindings from OUT_DIR at compile time
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

// Re-export the safe API modules
pub mod authenticator;
pub mod callbacks;
pub mod client;
pub mod credential;
pub mod ctaphid;
pub mod error;
pub mod uhid;

// Re-export the main types for convenience
pub use authenticator::Authenticator;
pub use callbacks::Callbacks;
pub use client::{CborCommand, CborCommandResult, Client, Transport, TransportList};
pub use credential::{Credential, Meta};
pub use error::Error;
