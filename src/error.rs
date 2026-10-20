// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{fmt, io, path::PathBuf};

/// A fallible Tang operation.
pub type Result<T> = std::result::Result<T, Error>;

/// A supported server-key algorithm, used for generation and operation requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Algorithm {
    Es512,
    Ecmr,
}

impl Algorithm {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Es512 => "ES512",
            Self::Ecmr => "ECMR",
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The JWK operation required of a server key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyOperation {
    Sign,
    Verify,
    DeriveKey,
}

impl KeyOperation {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Verify => "verify",
            Self::DeriveKey => "deriveKey",
        }
    }
}

impl fmt::Display for KeyOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The persistence operation that failed while creating and publishing key files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteStep {
    /// Create a temporary key file and apply its initial permissions.
    Create,
    /// Write the private key JSON to its temporary file.
    Write,
    /// Flush file contents or the containing directory to persistent storage.
    Synchronize,
    /// Rename a complete temporary key file to its final filename.
    Publish,
}

impl fmt::Display for WriteStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Create => "create",
            Self::Write => "write",
            Self::Synchronize => "synchronize",
            Self::Publish => "publish",
        })
    }
}

/// The operation for which randomness could not be obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RandomPurpose {
    KeyGeneration,
    AdvertisementSigning,
}

impl fmt::Display for RandomPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::KeyGeneration => "key generation",
            Self::AdvertisementSigning => "advertisement signing",
        })
    }
}

/// The origin of a stored key. Active and rotated input indices are zero-based.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyLocation {
    File(PathBuf),
    Input(usize),
    RotatedInput(usize),
}

impl fmt::Display for KeyLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(path) => write!(f, "{}", path.display()),
            Self::Input(index) => write!(f, "input index {index}"),
            Self::RotatedInput(index) => write!(f, "rotated input index {index}"),
        }
    }
}

/// A JSON decoding failure with diagnostics that never echo input values.
///
/// Serde's ordinary type errors can quote private values. This wrapper retains
/// the original error but exposes only its category and position when formatted.
/// It deliberately terminates the source chain to prevent accidental disclosure.
pub struct JsonError(pub(crate) serde_json::Error);

impl JsonError {
    pub fn category(&self) -> serde_json::error::Category {
        self.0.classify()
    }

    pub fn line(&self) -> usize {
        self.0.line()
    }

    pub fn column(&self) -> usize {
        self.0.column()
    }
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "JSON {:?} error at line {}, column {}",
            self.category(),
            self.line(),
            self.column()
        )
    }
}

impl fmt::Debug for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for JsonError {}

/// Errors distinguish client inputs, server key configuration, and persistence.
/// Private key values are never included in library-generated diagnostics.
/// Validation reasons and serialization contexts are diagnostic text, not
/// stable values for matching. Match variants and operation enums instead.
///
/// Stored-key validation causes can be matched directly without downcasting:
///
/// ```
/// use tangy_lib::{Algorithm, Error, KeyLocation, KeyOperation};
///
/// let error = Error::InvalidStoredKey {
///     location: KeyLocation::Input(2),
///     source: Box::new(Error::ForbiddenOperation {
///         kid: "key-id".into(),
///         algorithm: Algorithm::Es512,
///         operation: KeyOperation::Sign,
///     }),
/// };
/// let missing_permission = match &error {
///     Error::InvalidStoredKey { source, .. } => match source.as_ref() {
///         Error::ForbiddenOperation { operation, .. } => Some(*operation),
///         _ => None,
///     },
///     _ => None,
/// };
/// assert_eq!(missing_permission, Some(KeyOperation::Sign));
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("key {kid} was not found")]
    KeyNotFound { kid: String },

    /// Each flag is true when that key role is missing.
    #[error("incomplete key set (missing signing: {signing}, missing recovery: {recovery})")]
    MissingKeys { signing: bool, recovery: bool },

    #[error("duplicate key {kid} at {first} and {second}")]
    DuplicateKey {
        kid: String,
        first: KeyLocation,
        second: KeyLocation,
    },

    #[error("key entry {} is not a regular file", path.display())]
    NotAFile { path: PathBuf },

    #[error("invalid stored key at {location}")]
    InvalidStoredKey {
        location: KeyLocation,
        #[source]
        source: Box<Error>,
    },

    #[error("invalid key: {reason}")]
    InvalidKey {
        reason: &'static str,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("invalid recovery request: {reason}")]
    InvalidRequest {
        reason: &'static str,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("key {kid} does not permit {operation} with {algorithm}")]
    ForbiddenOperation {
        kid: String,
        algorithm: Algorithm,
        operation: KeyOperation,
    },

    #[error("unable to enumerate key directory {}", path.display())]
    KeyDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("unable to read key file {}", path.display())]
    KeyRead {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("unable to {operation} key file {}", path.display())]
    KeyWrite {
        path: PathBuf,
        operation: WriteStep,
        #[source]
        source: io::Error,
    },

    #[error("unable to serialize {context}")]
    Serialization {
        /// Diagnostic text describing the serialized value; not a matching API.
        context: &'static str,
        #[source]
        source: serde_json::Error,
    },

    #[error("unable to sign advertisement with key {kid}")]
    Signing {
        kid: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("unable to obtain randomness for {operation}")]
    Randomness {
        operation: RandomPurpose,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl Error {
    pub(crate) fn invalid_key(reason: &'static str) -> Self {
        Self::InvalidKey {
            reason,
            source: None,
        }
    }

    pub(crate) fn key_cause(
        reason: &'static str,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::InvalidKey {
            reason,
            source: Some(Box::new(source)),
        }
    }

    pub(crate) fn request(reason: &'static str) -> Self {
        Self::InvalidRequest {
            reason,
            source: None,
        }
    }

    pub(crate) fn request_cause(
        reason: &'static str,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::InvalidRequest {
            reason,
            source: Some(Box::new(source)),
        }
    }
}
