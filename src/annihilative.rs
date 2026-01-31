use curve25519_dalek::{EdwardsPoint, edwards::CompressedEdwardsY};
#[cfg(any(feature = "convergent", feature = "divergent"))]
use ed25519_dalek::{SigningKey, VerifyingKey};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(any(feature = "convergent"))]
use crate::errors::AnnihilationError;
use crate::point::Point;

/// Magic constant as a 64 bit unsigned integer value,
/// used for key point offset calculations.
pub const KEY_MAGIC: u64 = 0x9E3779B97F4A7C15;
/// Magic constant as a 64 bit unsigned integer value,
/// used for antikey point offset calculations.
pub const ANTIKEY_MAGIC: u64 = 0x61C8864680B583EB;

/// An `AnnihilativeKey` represents the proof of work solution
/// and elliptic curve point of a key or antikey.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct AnnihilativeKey {
    pub solution: AnnihilativeSolution,
    pub point: CompressedEdwardsY,
}

/// An `AnnihilativeSolution` represents the serialized
/// proof of work solution of a key or antikey.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct AnnihilativeSolution {
    pub identity: u8,
    pub commitment: u64,
    pub body: [u8; 22],
    pub constraint: u8,
}

/// Trait for deriving convergent ed25519 keys.
///
/// Any [SigningKey] or [VerifyingKey] produced by the key
/// or antikey of an annihilative pair will match, making
/// derived keys shared between both pair members.
#[cfg(feature = "convergent")]
pub trait Convergent {
    /// Derive a shared [SigningKey] from an annihilative key.
    /// The annihilative key's counterpart can derive the same
    /// signing key independently.
    fn shared_signing_key(
        &self,
        context: Option<&[u8]>,
    ) -> Result<SigningKey, AnnihilationError>;
    /// Derive a shared [VerifyingKey] from an annihilative key.
    /// The annihilative key's counterpart can derive the same
    /// verifying key independently.
    fn shared_verifying_key(
        &self,
        context: Option<&[u8]>,
    ) -> Result<VerifyingKey, AnnihilationError>;
}

/// Trait for deriving divergent ed25519 keys.
///
/// Any [SigningKey] or [VerifyingKey] produced by the key
/// or antikey of an annihilative pair will not match, making
/// derived keys unique for each pair member.
#[cfg(feature = "divergent")]
pub trait Divergent {
    /// Derive a unique [SigningKey] from an annihilative key.
    /// The annihilative key's counterpart cannot independently
    /// derive the same signing key.
    fn own_signing_key(&self, context: Option<&[u8]>) -> SigningKey;
    /// Derive a unique [VerifyingKey] from an annihilative key.
    /// The annihilative key's counterpart cannot independently
    /// derive the same verifying key.
    fn own_verifying_key(&self, context: Option<&[u8]>) -> VerifyingKey;
}

impl AnnihilativeKey {
    /// Construct an `AnnihilativeKey` by combining proof of work solution
    /// bytes and a shared base point.
    pub fn new(solution: &[u8; 32], base_point: EdwardsPoint) -> Self {
        let solution = AnnihilativeSolution::from_bytes(solution);
        // Select magic constant
        let is_key = (solution.identity & 0x80) == 0;
        let magic = if is_key { KEY_MAGIC } else { ANTIKEY_MAGIC };
        // Derive offset from commitment and magic constant
        let m_point = Point::from_u64(magic);
        let c_point = Point::from_u64(solution.commitment);
        let offset = &m_point + &c_point;
        // Point from base + offset, construct annihilative key
        let point = (base_point + offset).compress();
        AnnihilativeKey { solution, point }
    }
    /// Serialize an `AnnihilativeKey` to a 64 byte array.
    ///
    /// The first 32 bytes contain the solution, and the last 32 bytes
    /// contain the compressed curve point.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0] = self.solution.identity;
        bytes[1..9].copy_from_slice(&self.solution.commitment.to_le_bytes());
        bytes[9..31].copy_from_slice(&self.solution.body);
        bytes[31] = self.solution.constraint;
        bytes[32..].copy_from_slice(self.point.as_bytes());
        bytes
    }
    /// Deserialize an `AnnihilativeKey` from a 64 byte array.
    ///
    /// The first 32 bytes are interpreted as the solution, and the last
    /// 32 bytes as the compressed curve point.
    pub fn from_bytes(data: &[u8; 64]) -> Self {
        let mut solution_bytes = [0u8; 32];
        solution_bytes.copy_from_slice(&data[0..32]);
        let mut point_bytes = [0u8; 32];
        point_bytes.copy_from_slice(&data[32..]);
        Self {
            solution: AnnihilativeSolution::from_bytes(&solution_bytes),
            point: CompressedEdwardsY(point_bytes),
        }
    }
}

impl AnnihilativeSolution {
    /// Serialize an `AnnihilativeSolution` to a 32 byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = self.identity;
        bytes[1..9].copy_from_slice(&self.commitment.to_le_bytes());
        bytes[9..31].copy_from_slice(&self.body);
        bytes[31] = self.constraint;
        bytes
    }
    /// Deserialize an `AnnihilativeSolution` from a 32 byte array.
    pub fn from_bytes(data: &[u8; 32]) -> Self {
        let mut body = [0u8; 22];
        body.copy_from_slice(&data[9..31]);
        let commitment = u64::from_le_bytes(
            data[1..9]
                .try_into()
                .expect("data should contain a commitment"),
        );
        Self {
            identity: data[0],
            commitment,
            body,
            constraint: data[31],
        }
    }
}

impl ConstantTimeEq for AnnihilativeKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Compare both the solution and the point in constant time
        self.solution.ct_eq(&other.solution)
            & self.point.as_bytes().ct_eq(other.point.as_bytes())
    }
}

impl PartialEq for AnnihilativeKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for AnnihilativeKey {}

impl ConstantTimeEq for AnnihilativeSolution {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.to_bytes().ct_eq(&other.to_bytes())
    }
}

impl PartialEq for AnnihilativeSolution {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for AnnihilativeSolution {}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use hex_literal::hex;

    /// Construct a test key from static values and hex string literals.
    fn test_key() -> AnnihilativeKey {
        let solution = AnnihilativeSolution {
            identity: 96,
            commitment: 5764305080309989910,
            body: hex!("f0ba820d877d17bde069485f536653c1acd2242d9a10"),
            constraint: 16,
        };
        let point = CompressedEdwardsY::from_slice(&hex!(
            "3c7f61f8aa2405f42d815e310a6091c7fb94df764c296a7c777cd108bdae7742"
        ))
        .expect("hex string should represent curve point bytes");
        AnnihilativeKey { solution, point }
    }

    /// Construct a test antikey from static values and hex string literals.
    fn test_antikey() -> AnnihilativeKey {
        let solution = AnnihilativeSolution {
            identity: 133,
            commitment: 5230833101896872809,
            body: hex!("f3ea7f7f9d35dac8904beec93fec5ff0b41e852b7d1b"),
            constraint: 16,
        };
        let point = CompressedEdwardsY::from_slice(&hex!(
            "9dd0d77e09d089fc4fff6c49c2d5c9f5b515369bf532caaf739a7e1ec3e6b3ec"
        ))
        .expect("hex string should represent curve point bytes");
        AnnihilativeKey { solution, point }
    }

    /// Decompress a test shared base point from a static hex string literal.
    fn test_base_point() -> EdwardsPoint {
        CompressedEdwardsY::from_slice(&hex!(
            "40568aff34637712aa09c5adc3f9915ec454a3000b705283666a7dcd488c66ad"
        ))
        .expect("hex string should represent curve point bytes")
        .decompress()
        .expect("invalid y-coordinate for curve point")
    }

    #[test]
    fn test_new() {
        let base_point = test_base_point();
        // Construct key from solution bytes and shared base point
        let key_solution = &test_key().solution;
        let key_data = &key_solution.to_bytes();
        let key = AnnihilativeKey::new(&key_data, base_point);
        // Construct antikey from solution bytes and shared base point
        let antikey_solution = &test_antikey().solution;
        let antikey_data = &antikey_solution.to_bytes();
        let antikey = AnnihilativeKey::new(&antikey_data, base_point);
        // Different commitments + magic constants must produce
        // different points for key and antikey.
        assert_ne!(key.point, antikey.point);
        // Solutions must match input
        assert_eq!(&key.solution, key_solution);
        assert_eq!(&antikey.solution, antikey_solution);
    }

    #[test]
    fn test_key_to_from_bytes() {
        let key = test_key();
        // Convert the key to and from bytes
        let bytes = key.to_bytes();
        let recovered = AnnihilativeKey::from_bytes(&bytes);
        // Recovered key must match original
        assert_eq!(recovered, key);
    }

    #[test]
    fn test_solution_to_from_bytes() {
        let key_solution = &test_key().solution;
        let bytes = key_solution.to_bytes();
        let recovered = AnnihilativeSolution::from_bytes(&bytes);
        // Recovered solution must match original
        assert_eq!(&recovered, key_solution);
    }

    #[test]
    fn test_clone_eq() {
        let key = test_key();
        let antikey = test_antikey();
        // Clone the key
        let cloned = key.clone();
        // Key and its clone must match (constant time)
        assert_eq!(key, cloned);
        // Key and antikey must not match (constant time)
        assert_ne!(key, antikey);
    }
}
