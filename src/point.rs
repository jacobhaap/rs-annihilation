use curve25519_dalek::{
    EdwardsPoint, Scalar, constants::ED25519_BASEPOINT_TABLE,
};

use crate::annihilative::{ANTIKEY_MAGIC, AnnihilativeKey, KEY_MAGIC};
use crate::errors::AnnihilationError;

/// A zero-sized namespace providing functions for elliptic curve point
/// operations on Curve25519 for annihilative keys.
pub struct Point;

impl Point {
    /// Derive the shared base point between key and antikey solution bytes.
    ///
    /// Each solution is converted to a [Scalar] and multiplied against the
    /// [ED25519_BASEPOINT_TABLE]. The resulting points are added together
    /// to produce teh shared base point for the annihilative pair.
    pub fn shared_base(key: &[u8; 32], antikey: &[u8; 32]) -> EdwardsPoint {
        let key_scalar = Scalar::from_bytes_mod_order(*key);
        let anti_scalar = Scalar::from_bytes_mod_order(*antikey);
        let key_point = &Self::scalar_mult(key_scalar);
        let anti_point = &Self::scalar_mult(anti_scalar);
        key_point + anti_point
    }
    /// Recover the shared base point of an annihilative pair from an
    /// [AnnihilativeKey].
    ///
    /// Subtracts an offset of the magic constant + commitment from the key's
    /// decompressed curve point to recover the base point. Returns an error
    /// if the key's curve point point cannot be decompressed.
    pub fn recover_base(
        key: &AnnihilativeKey,
    ) -> Result<EdwardsPoint, AnnihilationError> {
        // Determine magic constant for key or antikey
        let is_key = (key.solution.identity & 0x80) == 0;
        let magic = if is_key { KEY_MAGIC } else { ANTIKEY_MAGIC };
        // Derive magic and commitment points, add for offset
        let m_point = Self::from_u64(magic);
        let c_point = Self::from_u64(key.solution.commitment);
        let offset = m_point + c_point;
        // Subtract offset to recover the shared base point
        match key.point.decompress() {
            Some(point) => Ok(point - offset),
            None => return Err(AnnihilationError::PointRecovery),
        }
    }
    /// Derive a curve point from a u64 value by constructing a [Scalar]
    /// from the value and multiplying against the [ED25519_BASEPOINT_TABLE].
    pub fn from_u64(val: u64) -> EdwardsPoint {
        let scalar = Scalar::from(val);
        Self::scalar_mult(scalar)
    }
    fn scalar_mult(scalar: Scalar) -> EdwardsPoint {
        &scalar * ED25519_BASEPOINT_TABLE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::annihilative::AnnihilativeSolution;
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
    fn test_shared_base() {
        let key = test_key().solution.to_bytes();
        let antikey = test_antikey().solution.to_bytes();
        let expected = test_base_point();
        // Create shared base point from key and antikey
        let base_point = Point::shared_base(&key, &antikey);
        // Shared base point must match expected point
        assert_eq!(base_point, expected);
    }

    #[test]
    fn test_recover_base() {
        let mut key = test_key();
        let expected = test_base_point();
        // Attempt to recover the shared base point. Recovered base point
        // must match the expected point.
        let recovered = Point::recover_base(&key);
        assert_eq!(recovered, Ok(expected));
        // Overwrite key point to one that cannot decompress. Shared base
        // point recovery must fail for the invalid curve point.
        key.point = CompressedEdwardsY(hex!(
            "0202000000000000000000000000000000000000000000000000000000000000"
        ));
        let recovered = Point::recover_base(&key);
        assert_eq!(recovered, Err(AnnihilationError::PointRecovery));
    }

    #[test]
    fn test_from_u64() {
        // Create a point from a u64 magic constant
        let point = Point::from_u64(KEY_MAGIC);
        // Compress the point, then decompress to recover
        let compressed = point.compress();
        let decompressed = compressed
            .decompress()
            .expect("invalid y-coordinate for curve point");
        // The decompressed point must match the original
        assert_eq!(decompressed, point);
    }
}
