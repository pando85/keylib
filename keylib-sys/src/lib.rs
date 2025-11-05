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
pub mod client_pin;
pub mod credential;
pub mod credential_management;
pub mod credentials;
pub mod ctaphid;
pub mod error;
pub mod promise;
pub mod uhid;

// Re-export the main types for convenience
pub use authenticator::Authenticator;
pub use client::{CborCommand, CborCommandResult, Client, Transport, TransportList};
pub use credential::{Credential, CredentialRef, Meta};
pub use error::Error;
pub use promise::CborPromise;
