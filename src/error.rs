//! Error types for `manis`.

use std::fmt;

/// Errors returned by [`crate::sys::SystemView`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemError {
    /// Target path does not exist.
    NotFound(String),
    /// Insufficient permissions to read target path.
    PermissionDenied(String),
    /// Virtual path attempted to escape the configured root directory.
    PathTraversal(String),
    /// Any other I/O error.
    Io { path: String, message: String },
}

impl SystemError {
    /// Converts a [`std::io::Error`] associated with a virtual path into a [`SystemError`].
    pub fn from_io(path: impl Into<String>, err: &std::io::Error) -> Self {
        let path = path.into();
        match err.kind() {
            std::io::ErrorKind::NotFound => Self::NotFound(path),
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied(path),
            _ => Self::Io {
                path,
                message: err.to_string(),
            },
        }
    }

    /// Returns `true` when the error indicates insufficient permissions.
    pub const fn is_permission_denied(&self) -> bool {
        matches!(self, Self::PermissionDenied(_))
    }

    /// Returns `true` when the error indicates a missing path.
    pub const fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }
}

impl fmt::Display for SystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(p) => write!(f, "not found: {p}"),
            Self::PermissionDenied(p) => write!(f, "permission denied: {p}"),
            Self::PathTraversal(p) => write!(f, "invalid path escaping root: {p}"),
            Self::Io { path, message } => write!(f, "I/O error on {path}: {message}"),
        }
    }
}

impl std::error::Error for SystemError {}

/// Top-level errors returned by the `manis` library and CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManisError {
    /// Embedded or user configuration could not be parsed or validated.
    Config(String),
    /// A requested profile name does not exist.
    UnknownProfile(String),
    /// A requested rule ID or alias does not exist.
    UnknownRule(String),
    /// Underlying system inspection error.
    System(SystemError),
    /// Output or CLI I/O error.
    Io(String),
}

impl fmt::Display for ManisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "configuration error: {msg}"),
            Self::UnknownProfile(name) => write!(f, "unknown profile '{name}'"),
            Self::UnknownRule(id) => write!(f, "unknown rule '{id}'"),
            Self::System(err) => write!(f, "system error: {err}"),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl std::error::Error for ManisError {}

impl From<SystemError> for ManisError {
    fn from(value: SystemError) -> Self {
        Self::System(value)
    }
}
