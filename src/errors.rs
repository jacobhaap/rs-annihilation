use core::fmt;

/// An enum representing all errors for Annihilative Keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnnihilationError {
    /// The annihilative pair is either only two keys or two antikeys.
    InvalidPair,
    /// The stored curve point is invalid and could not be decompressed,
    /// preventing recovery of the shared base point.
    PointRecovery,
    /// The comparison of two shared base curve points yielded a mismatch.
    PointMismatch,
    /// The constraints of two annihilative key solutions do not match.
    ConstraintMismatch,
    /// The proof of work constraint was not satisfied by the XOR hash.
    UnsatisfiedConstraint,
}

impl fmt::Display for AnnihilationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnnihilationError::InvalidPair => {
                write!(f, "annihilative pair has only keys or antikeys")
            }
            AnnihilationError::PointRecovery => {
                write!(f, "unable to recover shared base curve point")
            }
            AnnihilationError::PointMismatch => {
                write!(f, "recovered base curve points do not match")
            }
            AnnihilationError::ConstraintMismatch => {
                write!(f, "key and antikey constraints do not match")
            }
            AnnihilationError::UnsatisfiedConstraint => {
                write!(f, "XOR hash does not satisfy the constraint")
            }
        }
    }
}

#[test]
fn error_display() {
    // Test Display trait for InvalidPair
    assert_eq!(
        AnnihilationError::InvalidPair.to_string(),
        "annihilative pair has only keys or antikeys"
    );
    // Test Display trait for PointRecovery
    assert_eq!(
        AnnihilationError::PointRecovery.to_string(),
        "unable to recover shared base curve point"
    );
    // Test Display trait for PointMismatch
    assert_eq!(
        AnnihilationError::PointMismatch.to_string(),
        "recovered base curve points do not match"
    );
    // Test Display trait for ConstraintMismatch
    assert_eq!(
        AnnihilationError::ConstraintMismatch.to_string(),
        "key and antikey constraints do not match"
    );
    // Test Display trait for UnsatisfiedConstraint
    assert_eq!(
        AnnihilationError::UnsatisfiedConstraint.to_string(),
        "XOR hash does not satisfy the constraint"
    );
}
