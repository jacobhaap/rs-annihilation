use core::fmt::{Display, Formatter, Result};
use std::error::Error;

/// An enum representing all errors for Annihilative Keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnnihlErr {
    /// Given bytes could not decompress to a valid elliptic curve point,
    /// preventing the deserialisation of an annihilative key.
    PointDecompress,

    /// The annihilative pair's members are either both keys or both antikeys,
    /// rendering the pair invalid.
    InvalidPair,

    /// Proof-of-work constraints between the solutions of both annihilative
    /// pair members do not match.
    ConstraintMatch,

    /// The hash of an annihilative pair's XOR does not satisfy the pair's
    /// proof-of-work constraint.
    UnsatConstraint,

    /// The commitments of two solutions produce commitment collisions,
    /// rendering their annihilative pair invalid.
    CommitCollision,

    /// Base elliptic curve points do not match between two members of an
    /// annihilative pair.
    PointMismatch,

    /// Given keying material failed to authenticate a solution's body.
    UnauthBody,
}

impl Display for AnnihlErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str(match self {
            Self::PointDecompress => "cannot decompress curve point",
            Self::InvalidPair => "pair has only keys or antikeys",
            Self::ConstraintMatch => "pair constraints do not match",
            Self::UnsatConstraint => "proof-of-work constraint unsatisfied",
            Self::CommitCollision => "commitments would produce collision",
            Self::PointMismatch => "pair base curve point mismatch",
            Self::UnauthBody => "unable to authenticate solution body",
        })
    }
}

impl Error for AnnihlErr {}

#[test]
fn test_display() {
    assert_eq!(
        AnnihlErr::PointDecompress.to_string(),
        "cannot decompress curve point"
    );

    assert_eq!(
        AnnihlErr::InvalidPair.to_string(),
        "pair has only keys or antikeys"
    );

    assert_eq!(
        AnnihlErr::ConstraintMatch.to_string(),
        "pair constraints do not match"
    );

    assert_eq!(
        AnnihlErr::UnsatConstraint.to_string(),
        "proof-of-work constraint unsatisfied"
    );

    assert_eq!(
        AnnihlErr::CommitCollision.to_string(),
        "commitments would produce collision"
    );

    assert_eq!(
        AnnihlErr::PointMismatch.to_string(),
        "pair base curve point mismatch"
    );

    assert_eq!(
        AnnihlErr::UnauthBody.to_string(),
        "unable to authenticate solution body"
    );
}
