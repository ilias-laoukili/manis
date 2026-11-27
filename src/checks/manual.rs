//! `manual` check primitive for non-automatable benchmark controls.

use crate::checks::CheckOutcome;
use crate::model::Status;
use crate::rules::schema::ManualCheck;

/// Emits an explicit [`Status::Manual`] result with structured verification instructions.
pub fn evaluate(spec: &ManualCheck) -> CheckOutcome {
    CheckOutcome {
        status: Status::Manual,
        expected: Some("manual operator verification completed".to_string()),
        actual: Some("requires manual verification".to_string()),
        details: spec.verification_steps.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_returns_manual_status_with_steps() {
        let spec = ManualCheck {
            verification_steps: vec!["Check BIOS/UEFI password in firmware setup.".to_string()],
        };
        let out = evaluate(&spec);
        assert_eq!(out.status, Status::Manual);
        assert_eq!(out.details.len(), 1);
    }
}
