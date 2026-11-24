//! Core library for `manis`, a declarative, read-only Linux hardening audit CLI.

pub mod checks;
pub mod cli;
pub mod engine;
pub mod error;
pub mod model;
pub mod report;
pub mod rules;
pub mod sys;

pub use model::{AuditReport, AuditSummary, BenchmarkRefs, RuleResult, Severity, Status};

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
