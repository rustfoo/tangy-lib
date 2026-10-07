// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared helpers for operations that can fail during key generation and protocol responses.
//!
//! Key generation and advertisement signing both need a fresh random seed from
//! the operating system. This module obtains that seed through a fallible call,
//! so an unavailable randomness source returns an error identifying the operation.
//! It then seeds a cryptographically secure pseudorandom number generator for
//! the cryptographic routines, whose random-byte interface is infallible.
//!
//! Key thumbprints, generated keys and protocol responses also need JavaScript
//! Object Notation (JSON) serialization. The helpers here attach a description
//! of the value being serialized to any error. Keeping these policies together
//! lets the key and protocol modules share error handling without depending on
//! each other's implementation.

use p521::elliptic_curve::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{Error, RandomPurpose, Result};

// Seed a fresh cryptographically secure pseudorandom number generator through
// a fallible operating-system call before cryptographic operations.
// ChaCha20 fills cannot fail; entropy failures retain their original source and
// operation context, including before randomized signing.
pub(crate) fn crypto_rng<E: std::error::Error + Send + Sync + 'static>(
    entropy: &mut impl FnMut(&mut [u8]) -> std::result::Result<(), E>,
    operation: RandomPurpose,
) -> Result<ChaCha20Rng> {
    let mut seed = Zeroizing::new([0u8; 32]);
    entropy(seed.as_mut()).map_err(|source| Error::Randomness {
        operation,
        source: Box::new(source),
    })?;
    Ok(ChaCha20Rng::from_seed(*seed))
}

pub(crate) fn serialize<T: Serialize>(value: &T, context: &'static str) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|source| Error::Serialization { context, source })
}

pub(crate) fn serialize_string<T: Serialize>(value: &T, context: &'static str) -> Result<String> {
    serde_json::to_string(value).map_err(|source| Error::Serialization { context, source })
}
