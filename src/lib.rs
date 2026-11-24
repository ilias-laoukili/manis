//! Core domain types for `manis`, a declarative Linux hardening audit CLI.

/// Result status of evaluating a single hardening rule.
///
/// Missing or unreadable system values must never silently map to [`Status::Pass`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Checked value is present and compliant.
    Pass,
    /// Checked value is present and non-compliant.
    Fail,
    /// Value could not be fully verified (e.g., missing key or insufficient permissions).
    Warn,
    /// Rule was explicitly waived or is not applicable to the target OS.
    Skip,
    /// Control cannot be reliably automated and requires manual verification.
    Manual,
    /// Unexpected internal or collector failure.
    Error,
}

impl Status {
    /// Returns the canonical uppercase label used in CLI tables and structured reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Warn => "WARN",
            Self::Skip => "SKIP",
            Self::Manual => "MANUAL",
            Self::Error => "ERROR",
        }
    }
}

/// Severity level assigned to a hardening control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::{Severity, Status};

    #[test]
    fn status_labels_are_canonical() {
        assert_eq!(Status::Pass.as_str(), "PASS");
        assert_eq!(Status::Fail.as_str(), "FAIL");
        assert_eq!(Status::Warn.as_str(), "WARN");
        assert_eq!(Status::Skip.as_str(), "SKIP");
        assert_eq!(Status::Manual.as_str(), "MANUAL");
        assert_eq!(Status::Error.as_str(), "ERROR");
    }

    #[test]
    fn severity_ordering_is_monotonic() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }
}
