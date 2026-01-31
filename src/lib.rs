//! A Rust implementation of Annihilative Keys.
//!
//! Provides cryptographic key pairs where a key and antikey are each derived
//! from separate keying material but must jointly satisfy a proof of work
//! constraint. The mining process finds solutions where the SHA256 hash of
//! the key XOR antikey begins with a specified number of zero bits, binding
//! the pair cryptographically.
//!
//! Pairs can be verified by recovering and comparing their shared base curve
//! point, and checking that the solutions satisfy the proof of work
//! constraint. Valid pairs can be combined to produce a shared annihilation
//! key.
//!
//! With the `convergent` feature, annihilative pairs can independently derive
//! the same shared Ed25519 signing and verifying keys. With the `divergent`
//! feature, each member of the pair derives its own unique Ed25519 identity.
//!
//! ```
//! use annihilation::{AnnihilativeKey, Convergent, Divergent};
//!
//! fn main() {
//!     let k_ikm = b"End Of The World Sun";
//!     let a_ikm = b"Outlier/EOTWS_Variation1";
//!
//!     let (key, antikey) = AnnihilativeKey::new_pair(k_ikm, a_ikm, 16);
//!
//!     let artifact = key.verify(&antikey);
//!     assert!(artifact.is_ok());
//!
//!     let annihilation_key = key.to_annihilation(&antikey);
//!     assert!(annihilation_key.is_ok());
//!
//!     let context = b"65daysofstatic";
//!     let k_shared = key.shared_signing_key(Some(context));
//!     let a_shared = antikey.shared_signing_key(Some(context));
//!     assert_eq!(k_shared, a_shared);
//!
//!     let k_own = key.own_signing_key(Some(context));
//!     let a_own = antikey.own_signing_key(Some(context));
//!     assert_ne!(k_own, a_own);
//! }
//! ```
mod annihilative;
mod errors;
mod point;
mod pow;

#[cfg(any(feature = "convergent", feature = "divergent"))]
use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
#[cfg(any(feature = "convergent", feature = "divergent"))]
use sha2::Digest;
use sha2::Sha256;
#[cfg(any(feature = "convergent", feature = "divergent"))]
use zeroize::Zeroize;

pub use crate::annihilative::AnnihilativeKey;
#[cfg(feature = "convergent")]
pub use crate::annihilative::Convergent;
#[cfg(feature = "divergent")]
pub use crate::annihilative::Divergent;
pub use crate::errors::AnnihilationError;
pub use crate::point::Point;
pub use crate::pow::ProofOfWork;

#[cfg(feature = "convergent")]
const CONVERGENT_DOMAIN_BYTE: u8 = 0x43;
#[cfg(feature = "divergent")]
const DIVERGENT_DOMAIN_BYTE: u8 = 0x44;

impl AnnihilativeKey {
    /// Derive a new annihilative key and antikey pair from keying material.
    ///
    /// Mines for a valid pair satisfying the proof of work constraint where
    /// the SHA256 hash of key XOR antikey begins with the required number of
    /// zero bits. Each `AnnihilativeKey` consists of the mined solution, and
    /// a curve point at an offset from a derived shared base point.
    pub fn new_pair(
        key_material: &[u8],
        antikey_material: &[u8],
        constraint: u8,
    ) -> (Self, Self) {
        let (key_solution, antikey_solution) =
            ProofOfWork::mine(key_material, antikey_material, constraint);
        let base_point = Point::shared_base(&key_solution, &antikey_solution);
        let key = Self::new(&key_solution, base_point);
        let antikey = Self::new(&antikey_solution, base_point);
        (key, antikey)
    }
    /// Verify that two annihilative keys form a valid pair.
    ///
    /// Recovers the shared base point from each `AnnihilativeKey` and confirms
    /// they match, then verifies the proof of work constraint is satisfied.
    /// Returns the proof of work XOR hash as an artifact on success, or an
    /// error if the keys do not form a valid pair.
    pub fn verify(
        &self,
        counterpart: &Self,
    ) -> Result<[u8; 32], AnnihilationError> {
        let (key, antikey) = match Self::validate_pair(&self, &counterpart) {
            Ok(pair) => pair,
            Err(e) => return Err(e),
        };
        // Recover the base points for key and antikey, verify they match
        let k_base = match Point::recover_base(&key) {
            Ok(point) => *point.compress().as_bytes(),
            Err(e) => return Err(e),
        };
        let a_base = match Point::recover_base(&antikey) {
            Ok(point) => *point.compress().as_bytes(),
            Err(e) => return Err(e),
        };
        let recovered_base = match k_base == a_base {
            true => k_base,
            false => return Err(AnnihilationError::PointMismatch),
        };
        // Recalculate the shared base point from both solutions, then check
        // that it matches the recovered base point.
        let k_solution = &key.solution.to_bytes();
        let a_solution = &antikey.solution.to_bytes();
        let base_point = Point::shared_base(&k_solution, &a_solution);
        if recovered_base != *base_point.compress().as_bytes() {
            return Err(AnnihilationError::PointMismatch);
        }
        // Check that the SHA256 hash of key XOR antikey satisfies the
        // proof of work constraint.
        ProofOfWork::verify(&k_solution, &a_solution)
    }
    /// Compute an annihilation key from an annihilative pair.
    ///
    /// Verifies the pair, then derives an annihilation key by computing an
    /// HMAC of the constrained XOR hash artifact and body XOR, using the sum
    /// of both curve points as the key. Requires both the key and antikey to
    /// compute. Returns an error if the pair is invalid, or the constraints
    /// are not satisfied.
    pub fn to_annihilation(
        &self,
        counterpart: &Self,
    ) -> Result<[u8; 32], AnnihilationError> {
        let (key, antikey) = match Self::validate_pair(&self, &counterpart) {
            Ok(pair) => pair,
            Err(e) => return Err(e),
        };
        // Verify the annihilative pair
        let artifact = match Self::verify(&key, &antikey) {
            Ok(hash) => hash,
            Err(e) => return Err(e),
        };
        // Compute the XOR of the key and antikey solution bodies
        let mut body_xor = [0u8; 22];
        for i in 0..22 {
            body_xor[i] = key.solution.body[i] ^ antikey.solution.body[i];
        }
        // Decompress both points for the pair and get the bytes of their sum
        let k_point = key
            .point
            .decompress()
            .expect("already verified key curve point should decompress");
        let a_point = antikey
            .point
            .decompress()
            .expect("already verified antikey curve point should decompress");
        let point_sum = (k_point + a_point).compress();
        let point_sum_bytes = point_sum.as_bytes();
        // Compute an HMAC with the proof of work XOR hash artifact and body
        // XOR as the message, using the curve point sum as the key.
        let mut mac = Hmac::<Sha256>::new_from_slice(point_sum_bytes)
            .expect("HMAC can take key of any size");
        mac.update(&artifact);
        mac.update(&body_xor);
        Ok(mac.finalize().into_bytes().into())
    }
    /// Compute an annihilation key from an annihilative pair, consuming both
    /// keys.
    ///
    /// Convenience method that consumes ownership of both keys while
    /// delegating to [`to_annihilation`](Self::to_annihilation). Returns an
    /// error if the pair is invalid, or the constraints are not satisfied.
    pub fn into_annihilation(
        self,
        counterpart: Self,
    ) -> Result<[u8; 32], AnnihilationError> {
        self.to_annihilation(&counterpart)
    }
    fn validate_pair<'a>(
        &'a self,
        counterpart: &'a Self,
    ) -> Result<(&'a AnnihilativeKey, &'a AnnihilativeKey), AnnihilationError>
    {
        let self_is_key = (self.solution.identity & 0x80) == 0;
        let counterpart_is_key = (counterpart.solution.identity & 0x80) == 0;
        if self_is_key == counterpart_is_key {
            return Err(AnnihilationError::InvalidPair);
        }
        if self_is_key {
            Ok((self, counterpart))
        } else {
            Ok((counterpart, self))
        }
    }
}

#[cfg(feature = "convergent")]
impl Convergent for AnnihilativeKey {
    fn shared_signing_key(
        &self,
        context: Option<&[u8]>,
    ) -> Result<SigningKey, AnnihilationError> {
        let base_point = match Point::recover_base(&self) {
            Ok(point) => point,
            Err(e) => return Err(e),
        };
        let context_bytes = context.unwrap_or(&[0u8; 16]);
        // Keying material from hash of constraint + shared base point
        let mut hasher = Sha256::new();
        hasher.update(&[CONVERGENT_DOMAIN_BYTE]);
        hasher.update(&context_bytes);
        hasher.update(&[self.solution.constraint]);
        hasher.update(base_point.compress().as_bytes());
        let mut keying_material: [u8; 32] = hasher.finalize().into();
        let signing_key = SigningKey::from_bytes(&keying_material);
        keying_material.zeroize();
        Ok(signing_key)
    }
    fn shared_verifying_key(
        &self,
        context: Option<&[u8]>,
    ) -> Result<VerifyingKey, AnnihilationError> {
        let signing_key = self.shared_signing_key(context)?;
        Ok(signing_key.verifying_key())
    }
}

#[cfg(feature = "divergent")]
impl Divergent for AnnihilativeKey {
    fn own_signing_key(&self, context: Option<&[u8]>) -> SigningKey {
        let context_bytes = context.unwrap_or(&[0u8; 16]);
        // Keying material from hash of id + point
        let mut hasher = Sha256::new();
        hasher.update(&[DIVERGENT_DOMAIN_BYTE]);
        hasher.update(&context_bytes);
        hasher.update(&[self.solution.identity]);
        hasher.update(&self.point.as_bytes());
        let mut keying_material: [u8; 32] = hasher.finalize().into();
        let signing_key = SigningKey::from_bytes(&keying_material);
        keying_material.zeroize();
        signing_key
    }
    fn own_verifying_key(&self, context: Option<&[u8]>) -> VerifyingKey {
        let signing_key = self.own_signing_key(context);
        signing_key.verifying_key()
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use hex_literal::hex;

    use crate::annihilative::AnnihilativeSolution;

    use super::*;

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

    #[test]
    fn test_new_pair() {
        // Derive annihilative pair, constraint of 16 bits
        let (key, antikey) = AnnihilativeKey::new_pair(
            b"some key material",
            b"some antikey material",
            16,
        );
        // Identities should be <= 0x7F for key, >= 0x80 for antikey
        assert!(key.solution.identity <= 0x7F);
        assert!(antikey.solution.identity >= 0x80);
        // Verification result must return artifact, indicating keys
        // belong to the same pair.
        let artifact = key.verify(&antikey);
        assert!(artifact.is_ok());
    }

    #[test]
    fn test_verify() {
        let mut key = test_key();
        let mut antikey = test_antikey();
        // Key and antikey can verify each other, and verification must
        // return an artifact indicating they belong to the same pair.
        let result = key.verify(&antikey);
        assert!(result.is_ok());
        let result = antikey.verify(&key);
        assert!(result.is_ok());
        // Overwrite antikey solution identity to match key. Verification
        // must fail for the invalid pair.
        let tmp_id = antikey.solution.identity;
        antikey.solution.identity = key.solution.identity;
        let result = key.verify(&antikey);
        assert_eq!(result, Err(AnnihilationError::InvalidPair));
        antikey.solution.identity = tmp_id;
        // Overwrite key point to one that cannot decompress. Verification
        // against the antikey must fail for the invalid curve point.
        let tmp_point = key.point;
        key.point = CompressedEdwardsY(hex!(
            "0202000000000000000000000000000000000000000000000000000000000000"
        ));
        let result = key.verify(&antikey);
        assert_eq!(result, Err(AnnihilationError::PointRecovery));
        key.point = tmp_point;
        // Overwrite antikey point to one that cannot decompress.
        // Verification against the key must fail for the invalid curve point.
        let tmp_point = antikey.point;
        antikey.point = CompressedEdwardsY(hex!(
            "0202000000000000000000000000000000000000000000000000000000000000"
        ));
        let result = antikey.verify(&key);
        assert_eq!(result, Err(AnnihilationError::PointRecovery));
        antikey.point = tmp_point;
        // Overwrite antikey commitment with a random number. Verification
        // against the key on the base point comparison must fail.
        let tmp_commit = antikey.solution.commitment;
        antikey.solution.commitment = 2666156578537121652;
        let result = key.verify(&antikey);
        assert_eq!(result, Err(AnnihilationError::PointMismatch));
        antikey.solution.commitment = tmp_commit;
        // Corrupt the antikey body. The final verification step to regenerate
        // the shared base point depending on the entire key and antikey
        // solutions must fail.
        for i in 0..22 {
            antikey.solution.body[i] ^= 0xFF
        }
        let result = key.verify(&antikey);
        assert_eq!(result, Err(AnnihilationError::PointMismatch));
    }

    #[test]
    fn test_to_annihilation() {
        let mut key = test_key();
        let mut antikey = test_antikey();
        // Annihilative pair is capable of annihilation,
        // both directions must produce the same annihilation key.
        let result_k = key.to_annihilation(&antikey);
        let result_a = antikey.to_annihilation(&key);
        assert!(result_k.is_ok());
        assert!(result_a.is_ok());
        assert_eq!(result_k.unwrap(), result_a.unwrap());
        // Overwrite antikey solution identity to match key. Annihilation
        // must fail for the invalid pair.
        let tmp_id = antikey.solution.identity;
        antikey.solution.identity = key.solution.identity;
        let result = key.to_annihilation(&antikey);
        assert_eq!(result, Err(AnnihilationError::InvalidPair));
        antikey.solution.identity = tmp_id;
        // Overwrite key point to one that cannot decompress. Verification
        // against the antikey must fail for the invalid curve point.
        let tmp_point = key.point;
        key.point = CompressedEdwardsY(hex!(
            "0202000000000000000000000000000000000000000000000000000000000000"
        ));
        let result = key.to_annihilation(&antikey);
        assert_eq!(result, Err(AnnihilationError::PointRecovery));
        key.point = tmp_point;
        // Corrupt the antikey body. Annihilation must fail because the
        // recalculated base point won't match the recovered base point.
        for i in 0..22 {
            antikey.solution.body[i] ^= 0xFF
        }
        let result = key.to_annihilation(&antikey);
        assert_eq!(result, Err(AnnihilationError::PointMismatch));
    }

    #[test]
    fn test_into_annihilation() {
        let key = test_key();
        let antikey = test_antikey();
        // Annihilative pair is capable of annihilation, result must
        // contain an annihilation key.
        let result = key.into_annihilation(antikey);
        assert!(result.is_ok());
    }

    #[cfg(feature = "convergent")]
    #[test]
    fn test_shared_signing_key() {
        let mut key = test_key();
        let antikey = test_antikey();
        // Derive convergent signing keys. Signing keys must match.
        let key_signing = key.shared_signing_key(None).unwrap();
        let antikey_signing = antikey.shared_signing_key(None).unwrap();
        assert_eq!(key_signing, antikey_signing);
        // Overwrite key point to one that cannot decompress. Shared signing
        // key derivation must fail for the invalid curve point.
        key.point = CompressedEdwardsY(hex!(
            "0202000000000000000000000000000000000000000000000000000000000000"
        ));
        let result = key.shared_signing_key(None);
        assert_eq!(result, Err(AnnihilationError::PointRecovery));
    }

    #[cfg(feature = "convergent")]
    #[test]
    fn test_shared_verifying_key() {
        let mut key = test_key();
        let antikey = test_antikey();
        // Derive convergent verifying keys. Verifying keys must match.
        let key_verifying = key.shared_verifying_key(None).unwrap();
        let antikey_verifying = antikey.shared_verifying_key(None).unwrap();
        assert_eq!(key_verifying, antikey_verifying);
        // Overwrite key point to one that cannot decompress. Shared verifying
        // key derivation must fail for the invalid curve point.
        key.point = CompressedEdwardsY(hex!(
            "0202000000000000000000000000000000000000000000000000000000000000"
        ));
        let result = key.shared_verifying_key(None);
        assert_eq!(result, Err(AnnihilationError::PointRecovery));
    }

    #[cfg(feature = "divergent")]
    #[test]
    fn test_own_signing_key() {
        let key = test_key();
        let antikey = test_antikey();
        // Derive divergent signing keys. Signing keys must not match.
        let key_signing = key.own_signing_key(None);
        let antikey_signing = antikey.own_signing_key(None);
        assert_ne!(key_signing, antikey_signing);
    }

    #[cfg(feature = "divergent")]
    #[test]
    fn test_own_verifying_key() {
        let key = test_key();
        let antikey = test_antikey();
        // Derive divergent verifying keys. Verifying keys must not match.
        let key_verifying = key.own_verifying_key(None);
        let antikey_verifying = antikey.own_verifying_key(None);
        assert_ne!(key_verifying, antikey_verifying);
    }
}
