use curve25519_dalek::{EdwardsPoint, edwards::CompressedEdwardsY};
#[cfg(any(feature = "convergent", feature = "divergent"))]
use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
#[cfg(any(feature = "convergent", feature = "divergent"))]
use sha2::Digest;
use sha2::Sha256;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::AnnihlErr;
use crate::point::Point;
use crate::solution::{Identity, Solution};

/// Golden ratio-derived magic constant equal to `floor(2^64 / φ)`,
/// where φ is the golden ratio.
///
/// Used to derive curve point offsets for keys.
pub const KEY_MAGIC: u64 = 0x9E3779B97F4A7C15;

/// Negated golden ratio-derived magic constant equal to
/// `2^64 - floor(2^64 / φ)`, where φ is the golden ratio.
///
/// Used to derive curve point offsets for antikeys.
pub const ANTIKEY_MAGIC: u64 = 0x61C8864680B583EB;

#[cfg(feature = "convergent")]
const CONVERGENT_DOMAIN_BYTE: u8 = 0x43;

#[cfg(feature = "divergent")]
const DIVERGENT_DOMAIN_BYTE: u8 = 0x44;

/// An `AnnihlKey` represents the mined proof-of-work solution
/// and elliptic curve point of an annihilative key.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct AnnihlKey {
    /// Serialised proof-of-work solution.
    pub solution: Solution,

    point: CompressedEdwardsY,
}

impl AnnihlKey {
    /// Construct a new `AnnihlKey` from a mined proof-of-work solution
    /// and shared base curve point.
    pub fn new(solution: Solution, base_point: EdwardsPoint) -> Self {
        let is_key = Choice::from(((solution.identity & 0x80) == 0) as u8);
        let magic = u64::conditional_select(&ANTIKEY_MAGIC, &KEY_MAGIC, is_key);

        let m_point = Point::from_u64(magic);
        let mut c_point = Point::from_u64(solution.commitment);
        let mut offset = m_point + c_point;

        let mut sum = base_point + offset;
        let point = (sum).compress();

        sum.zeroize();
        c_point.zeroize();
        offset.zeroize();

        AnnihlKey { solution, point }
    }

    /// Derive a new annihilative pair from keying material.
    ///
    /// Returns a pair that satisfies the given proof-of-work constraint, where
    /// each `AnnihlKey` consists of the mined [Solution], and an [EdwardsPoint]
    /// at an offset from the pair's shared base curve point.
    pub fn new_pair(ikm: &[u8], iam: &[u8], constraint: u8) -> (Self, Self) {
        let pair = Solution::mine(ikm, iam, constraint);
        let mut base_point = Point::shared_base(&pair.0, &pair.1);

        let key = Self::new(pair.0, base_point);
        let antikey = Self::new(pair.1, base_point);

        base_point.zeroize();

        (key, antikey)
    }

    /// Verify that two annihilative keys form a valid pair.
    ///
    /// First checks that both members share the same base curve point, then
    /// checks if the hash of their XOR satisfies the proof-of-work constraint.
    ///
    /// Returns the XOR hash as an artifact on success, or an error when the
    /// members do not form a valid annihilative pair.
    pub fn verify(&self, other: &Self) -> Result<[u8; 32], AnnihlErr> {
        let (key, antikey) = match Self::validate_pair(&self, &other) {
            Ok(pair) => pair,
            Err(e) => return Err(e),
        };

        // Shared base between curve points should match
        Point::verify_pair(key, antikey)?;

        // Hash of key XOR antikey must satisfy the PoW constraint
        key.solution.verify(&antikey.solution)
    }

    /// Authenticate than an `AnnihlKey` was derived from given keying material.
    ///
    /// Returns an error if the annihilative key could not be authenticated by
    /// the keying material.
    pub fn authenticate(
        &self,
        keying_material: &[u8],
    ) -> Result<(), AnnihlErr> {
        self.solution.authenticate(keying_material)
    }

    /// Compute an annihilation key from an annihilative pair.
    ///
    /// Verifies the pair, then computes an [Hmac] of the verification artifact,
    /// keyed by the sum of both curve points. Requires both a key and antikey
    /// to compute. As long as one half of the annihilative pair remains secret,
    /// the secrecy of the derived annihilation key is preserved.
    ///
    /// Returns the MAC as the annihilation key on success, or an error when the
    /// pair is invalid or the proof-of-work constraint is not satisfied.
    pub fn to_annihilation(&self, other: &Self) -> Result<[u8; 32], AnnihlErr> {
        // Artifact of constrained XOR hash
        let mut artifact = match self.verify(&other) {
            Ok(hash) => hash,
            Err(e) => return Err(e),
        };

        // Sum of curve points
        let mut self_point = self.to_edwards_point();
        let mut other_point = other.to_edwards_point();
        let mut points_sum = self_point + other_point;
        let mut compressed = points_sum.compress();

        // Return MAC of artifact keyed by sum of curve points
        let mut mac = Hmac::<Sha256>::new_from_slice(compressed.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(&artifact);

        artifact.zeroize();
        self_point.zeroize();
        other_point.zeroize();
        points_sum.zeroize();
        compressed.zeroize();

        Ok(mac.finalize().into_bytes().into())
    }

    /// Compute an annihilation key from an annihilative pair, consuming both
    /// keys.
    ///
    /// Convenience method that consumes ownership of both keys while
    /// delegating to [`to_annihilation`](Self::to_annihilation).
    ///
    /// Returns the MAC as the annihilation key on success, or an error when the
    /// pair is invalid or the proof-of-work constraint is not satisfied.
    pub fn into_annihilation(self, other: Self) -> Result<[u8; 32], AnnihlErr> {
        self.to_annihilation(&other)
    }

    /// Copy this `AnnihlKey` to a 64 byte array.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut commitment = self.solution.commitment.to_le_bytes();

        let mut bytes = [0u8; 64];
        bytes[0] = self.solution.identity;
        bytes[1..9].copy_from_slice(&commitment);
        bytes[9..31].copy_from_slice(&self.solution.body);
        bytes[31] = self.solution.constraint;
        bytes[32..].copy_from_slice(self.point.as_bytes());

        commitment.zeroize();

        bytes
    }

    /// Return this `AnnihlKey`'s curve point as an [EdwardsPoint].
    pub fn to_edwards_point(&self) -> EdwardsPoint {
        self.point
            .decompress()
            .expect("point validated during construction")
    }
}

#[cfg(feature = "convergent")]
impl AnnihlKey {
    /// Derive a [SigningKey] from an `AnnihlKey`.
    ///
    /// The signing key produced is shared between members of an annihilative
    /// pair, meaning the other pair member can independently derive the same
    /// signing key.
    pub fn shared_signing_key(&self, context: Option<&[u8]>) -> SigningKey {
        let mut base_point = Point::recover_base(&self);
        let mut compressed_point = base_point.compress();

        let context_bytes = context.unwrap_or(&[]);

        let mut hasher = Sha256::new();
        hasher.update(&[CONVERGENT_DOMAIN_BYTE]);
        hasher.update(compressed_point.as_bytes());
        hasher.update(&context_bytes);
        let mut keying_material: [u8; 32] = hasher.finalize().into();

        let signing_key = SigningKey::from_bytes(&keying_material);

        base_point.zeroize();
        compressed_point.zeroize();
        keying_material.zeroize();

        signing_key
    }

    /// Derive a [VerifyingKey] from an `AnnihlKey`.
    ///
    /// The verifying key produced is shared between members of an annihilative
    /// pair, meaning the other pair member can independently derive the same
    /// verifying key.
    pub fn shared_verifying_key(&self, context: Option<&[u8]>) -> VerifyingKey {
        let signing_key = self.shared_signing_key(context);
        signing_key.verifying_key()
    }
}

#[cfg(feature = "divergent")]
impl AnnihlKey {
    /// Derive a [SigningKey] from an `AnnihlKey`.
    ///
    /// The signing key produced is unique within an annihilative pair,
    /// meaning the other pair member cannot independently derive the
    /// same signing key.
    pub fn own_signing_key(&self, context: Option<&[u8]>) -> SigningKey {
        let mut solution_bytes = self.solution.to_bytes();

        let context_bytes = context.unwrap_or(&[]);

        let mut hasher = Sha256::new();
        hasher.update(&[DIVERGENT_DOMAIN_BYTE]);
        hasher.update(&solution_bytes);
        hasher.update(&context_bytes);
        let mut keying_material: [u8; 32] = hasher.finalize().into();

        let signing_key = SigningKey::from_bytes(&keying_material);
        solution_bytes.zeroize();
        keying_material.zeroize();

        signing_key
    }

    /// Derive a [VerifyingKey] from an `AnnihlKey`.
    ///
    /// The verifying key produced is unique within an annihilative pair,
    /// meaning the other pair member cannot independently derive the same
    /// verifying key.
    pub fn own_verifying_key(&self, context: Option<&[u8]>) -> VerifyingKey {
        let signing_key = self.own_signing_key(context);
        signing_key.verifying_key()
    }
}

impl TryFrom<&[u8; 64]> for AnnihlKey {
    type Error = AnnihlErr;

    /// Construct an `AnnihlKey` from a 64 byte array.
    fn try_from(value: &[u8; 64]) -> Result<Self, Self::Error> {
        let mut solution_bytes = [0u8; 32];
        solution_bytes.copy_from_slice(&value[0..32]);
        let solution = Solution::from(&solution_bytes);
        solution_bytes.zeroize();

        let mut point_bytes = [0u8; 32];
        point_bytes.copy_from_slice(&value[32..]);
        let mut point = CompressedEdwardsY(point_bytes);
        point_bytes.zeroize();

        match point.decompress() {
            Some(mut edwards) => edwards.zeroize(),
            None => {
                point.zeroize();
                return Err(AnnihlErr::PointDecompress);
            }
        }

        Ok(Self { solution, point })
    }
}

impl PartialEq for AnnihlKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for AnnihlKey {}

impl ConstantTimeEq for AnnihlKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Compare both the solution and the point in constant time
        let mut self_solution = self.solution.to_bytes();
        let mut other_solution = other.solution.to_bytes();
        let mut self_point = self.point.to_bytes();
        let mut other_point = other.point.to_bytes();

        let result = self_solution.ct_eq(&other_solution)
            & self_point.ct_eq(&other_point);

        self_solution.zeroize();
        other_solution.zeroize();
        self_point.zeroize();
        other_point.zeroize();

        result
    }
}

impl Identity for AnnihlKey {
    fn identity_byte(&self) -> u8 {
        self.solution.identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IKM: &'static [u8; 20] = b"End Of The World Sun";
    const IAM: &'static [u8; 24] = b"Outlier/EOTWS_Variation1";
    const ALT_IKM: &'static [u8; 25] = b"65 Doesn't Understand You";
    const ALT_IAM: &'static [u8; 21] = b"Unmake the Wild Light";

    #[test]
    fn new_uses_correct_magic_for_key() {
        let (k_sol, a_sol) = Solution::mine(IKM, IAM, 16);
        let base_point = Point::shared_base(&k_sol, &a_sol);

        // Constructor should apply key magic constant
        let k_commit = k_sol.commitment.clone();
        let key = AnnihlKey::new(k_sol, base_point);

        // Calculate expected point from magic and commitment
        let m_point = Point::from_u64(KEY_MAGIC);
        let c_point = Point::from_u64(k_commit);
        let expected = base_point + m_point + c_point;

        // Key point must match expectation (correct magic used)
        assert_eq!(key.to_edwards_point(), expected);
    }

    #[test]
    fn new_uses_correct_magic_for_antikey() {
        let (k_sol, a_sol) = Solution::mine(IKM, IAM, 16);
        let base_point = Point::shared_base(&k_sol, &a_sol);

        // Constructor should apply antikey magic constant
        let a_commit = a_sol.commitment.clone();
        let antikey = AnnihlKey::new(a_sol, base_point);

        // Calculate expected point from magic and commitment
        let m_point = Point::from_u64(ANTIKEY_MAGIC);
        let c_point = Point::from_u64(a_commit);
        let expected = base_point + m_point + c_point;

        // Antikey point must match expectation (correct magic used)
        assert_eq!(antikey.to_edwards_point(), expected);
    }

    #[test]
    fn new_pair_produces_valid_pair() {
        let (key, antikey) = AnnihlKey::new_pair(IKM, IAM, 16);

        // Must produce one key and one antikey
        assert!(key.solution.identity <= 0x7F);
        assert!(antikey.solution.identity >= 0x80);

        // Valid annihilative pair must share a base point
        let k_base = Point::recover_base(&key);
        let a_base = Point::recover_base(&antikey);
        assert_eq!(k_base, a_base);
    }

    #[test]
    fn verify_succeeds_valid_pair() {
        let (key, antikey) = AnnihlKey::new_pair(IKM, IAM, 16);

        // Must return artifact with 16 leading zero bits
        let result = key.verify(&antikey);
        assert!(result.is_ok());
        let artifact = result.unwrap();
        assert_eq!(artifact[0..2], [0u8; 2]);
    }

    #[test]
    fn verify_fails_invalid_pair() {
        let (key_1, _) = AnnihlKey::new_pair(IKM, IAM, 16);
        let (key_2, _) = AnnihlKey::new_pair(ALT_IKM, ALT_IAM, 16);

        // Invalid pair must fail verification
        let result = key_1.verify(&key_2);
        assert_eq!(result, Err(AnnihlErr::InvalidPair));
    }

    #[test]
    fn authenticate_succeeds_correct_material() {
        let (key, _) = AnnihlKey::new_pair(IKM, IAM, 16);

        // Authentication with correct keying material must yield Ok result
        let result = key.authenticate(IKM);
        assert!(result.is_ok());
    }

    #[test]
    fn authenticate_fails_incorrect_material() {
        let (key, _) = AnnihlKey::new_pair(IKM, IAM, 16);

        // Authentication with wrong keying material must result in an error
        let result = key.authenticate(IAM);
        assert_eq!(result, Err(AnnihlErr::UnauthBody));
    }

    #[test]
    fn to_annihilation_succeeds_valid_pair() {
        let (key, antikey) = AnnihlKey::new_pair(IKM, IAM, 16);

        // Annihilation between valid pair must succeed
        let result = key.to_annihilation(&antikey);
        assert!(result.is_ok());
    }

    #[test]
    fn to_annihilation_fails_mismatched_points() {
        let (key, _) = AnnihlKey::new_pair(IKM, IAM, 16);
        let (_, antikey) = AnnihlKey::new_pair(ALT_IKM, ALT_IAM, 16);

        // Key and antikey from different pairs must result in an error
        let result = key.to_annihilation(&antikey);
        assert_eq!(result, Err(AnnihlErr::PointMismatch));
    }

    #[test]
    fn into_annihilation_consumes_pair() {
        let (key, antikey) = AnnihlKey::new_pair(IKM, IAM, 16);

        // Annihilation between valid pair must succeed
        let result = key.into_annihilation(antikey);
        assert!(result.is_ok());
    }

    #[test]
    fn to_bytes_produces_64_byte_array() {
        let (key, _) = AnnihlKey::new_pair(IKM, IAM, 16);

        // Key must be exactly 32 bytes
        let bytes = key.to_bytes();
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn to_edwards_point_decompresses_stored_point() {
        let (key, _) = AnnihlKey::new_pair(IKM, IAM, 16);

        let point = key.to_edwards_point();
        let recompressed = point.compress();

        // Recompressed point should match stored point
        assert_eq!(key.point.as_bytes(), recompressed.as_bytes());
    }

    #[cfg(feature = "convergent")]
    #[test]
    fn shared_signing_key_matches_pair() {
        let (key, antikey) = AnnihlKey::new_pair(IKM, IAM, 16);

        let k_signing = key.shared_signing_key(None);
        let a_signing = antikey.shared_signing_key(None);

        // Signing keys must match between pair members
        assert_eq!(k_signing.to_bytes(), a_signing.to_bytes());
    }

    #[cfg(feature = "convergent")]
    #[test]
    fn shared_verifying_key_matches_pair() {
        let (key, antikey) = AnnihlKey::new_pair(IKM, IAM, 16);

        let k_verifying = key.shared_verifying_key(None);
        let a_verifying = antikey.shared_verifying_key(None);

        // Verifying keys must match between pair members
        assert_eq!(k_verifying.to_bytes(), a_verifying.to_bytes());
    }

    #[cfg(feature = "divergent")]
    #[test]
    fn own_signing_key_differs_in_pair() {
        let (key, antikey) = AnnihlKey::new_pair(IKM, IAM, 16);

        let k_signing = key.own_signing_key(None);
        let a_signing = antikey.own_signing_key(None);

        // Signing keys must not match between pair members
        assert_ne!(k_signing.to_bytes(), a_signing.to_bytes());
    }

    #[cfg(feature = "divergent")]
    #[test]
    fn own_verifying_key_differs_in_pair() {
        let (key, antikey) = AnnihlKey::new_pair(IKM, IAM, 16);

        let k_verifying = key.own_verifying_key(None);
        let a_verifying = antikey.own_verifying_key(None);

        // Verifying keys must not match between pair members
        assert_ne!(k_verifying.to_bytes(), a_verifying.to_bytes());
    }

    #[test]
    fn try_from_reconstructs_key() {
        let (key, _) = AnnihlKey::new_pair(IKM, IAM, 16);

        let bytes = key.to_bytes();

        // Reconstructed key must match original
        let result = AnnihlKey::try_from(&bytes);
        assert!(result.is_ok());
        let reconstructed = result.unwrap();
        assert_eq!(key, reconstructed);
    }

    #[test]
    fn try_from_fails_invalid_point() {
        let (key, _) = AnnihlKey::new_pair(IKM, IAM, 16);

        let mut bytes = key.to_bytes();
        bytes[32] = 0x02;
        bytes[33] = 0x02;
        bytes[34..].fill(0x00);

        // Reconstruction must fail for invalid curve point
        let result = AnnihlKey::try_from(&bytes);
        assert_eq!(result, Err(AnnihlErr::PointDecompress));
    }
}
