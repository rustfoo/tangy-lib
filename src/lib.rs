// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tang advertisements and P-521 message recovery with typed errors.
//!
//! ```
//! use tangy_lib::{create_new_key_set, KeySource, Result, TangyLib};
//!
//! fn initialize() -> Result<TangyLib> {
//!     let generated = create_new_key_set()?;
//!     let keys: Vec<&str> = generated.iter().map(String::as_str).collect();
//!     let server = TangyLib::init(KeySource::Vector(&keys))?;
//!     let _advertisement = server.adv(None)?;
//!     Ok(server)
//! }
//! # initialize()?;
//! # Ok::<(), tangy_lib::Error>(())
//! ```

// Rustdoc uses these targets before the guides' repository-relative link definitions.
#![doc = "[key-storage-guide]: crate::key_storage\n"]
#![doc = include_str!("../README.md")]

mod error;
mod jwk;
mod key_store;
mod protocol;
mod support;

pub use error::{
    Algorithm, Error, JsonError, KeyLocation, KeyOperation, RandomPurpose, Result, WriteStep,
};
pub use jwk::{create_new_key_set, MyJwkEcKey};
pub use key_store::KeySource;
pub use protocol::TangyLib;

#[doc = "[loading-keys]: crate#loading-keys\n"]
#[doc = include_str!("../KEY_STORAGE.md")]
pub mod key_storage {}

#[cfg(test)]
mod tests;
