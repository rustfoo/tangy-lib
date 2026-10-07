use std::{fmt, io, path::PathBuf};

/// A fallible Tang operation.
pub type Result<T> = std::result::Result<T, Error>;

/// The origin of a stored key. Vector indices are zero-based.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyLocation {
    File(PathBuf),
    Input(usize),
}

impl fmt::Display for KeyLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(path) => write!(f, "{}", path.display()),
            Self::Input(index) => write!(f, "input key at index {index}"),
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
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("key {kid} was not found")]
    KeyNotFound { kid: String },

    /// Each flag is true when that key role is missing.
    #[error("incomplete key set (missing signing: {signing}, missing recovery: {recovery})")]
    MissingKeys { signing: bool, recovery: bool },

    #[error("invalid stored key at {location}: {source}")]
    InvalidStoredKey {
        location: KeyLocation,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
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
        algorithm: &'static str,
        operation: &'static str,
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
        operation: &'static str,
        #[source]
        source: io::Error,
    },

    #[error("unable to serialize {context}")]
    Serialization {
        context: &'static str,
        #[source]
        source: serde_json::Error,
    },

    #[error("unable to sign advertisement with key {kid}")]
    Signing {
        kid: String,
        #[source]
        source: p521::ecdsa::signature::Error,
    },

    #[error("unable to obtain randomness for {operation}")]
    Randomness {
        operation: &'static str,
        #[source]
        source: elliptic_curve::rand_core::Error,
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
