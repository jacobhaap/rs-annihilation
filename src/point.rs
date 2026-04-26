use curve25519_dalek::{
    EdwardsPoint, Scalar, constants::ED25519_BASEPOINT_TABLE,
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use crate::AnnihlErr;
use crate::annihilative::{ANTIKEY_MAGIC, AnnihlKey, KEY_MAGIC};
use crate::solution::Solution;

/// A zero-sized namespace providing functionality for elliptic curve point
/// operations for annihilative keys.
pub struct Point;

impl Point {
    /// Derive a shared base curve point between two solutions.
    ///
    /// Converts each solution to a [Scalar] and multiplies against the
    /// [ED25519_BASEPOINT_TABLE] to produce two curve points, returning
    /// their sum.
    pub fn shared_base(key: &Solution, antikey: &Solution) -> EdwardsPoint {
        let mut k_bytes = key.to_bytes();
        let mut a_bytes = antikey.to_bytes();
        let mut k_scalar = Scalar::from_bytes_mod_order(k_bytes);
        let mut a_scalar = Scalar::from_bytes_mod_order(a_bytes);
        k_bytes.zeroize();
        a_bytes.zeroize();

        let mut k_point = &k_scalar * ED25519_BASEPOINT_TABLE;
        let mut a_point = &a_scalar * ED25519_BASEPOINT_TABLE;
        k_scalar.zeroize();
        a_scalar.zeroize();

        let base_point = k_point + a_point;
        k_point.zeroize();
        a_point.zeroize();

        base_point
    }

    /// Recover the base curve point of an [AnnihlKey].
    ///
    /// Using the key's solution, subtracts a commitment-derived offset from
    /// the key's point to recover the base curve point.
    pub fn recover_base(key: &AnnihlKey) -> EdwardsPoint {
        let is_key = Choice::from(((key.solution.identity & 0x80) == 0) as u8);
        let magic = u64::conditional_select(&ANTIKEY_MAGIC, &KEY_MAGIC, is_key);

        let m_point = Self::from_u64(magic);
        let mut c_point = Self::from_u64(key.solution.commitment);
        let mut offset = m_point + c_point;

        let base_point = key.to_edwards_point() - offset;
        c_point.zeroize();
        offset.zeroize();

        base_point
    }

    /// Verify that an annihilative pair share the same base curve point.
    ///
    /// For both member of the pair, base curve points are recovered using
    /// each member's solution, subtracting a commitment-derived offset from
    /// the member's point to recover the base point. Both recovered points
    /// are compared to check for a match.
    ///
    /// Returns an error if the base curve points for each member of the pair
    /// do not match.
    pub fn verify_pair(
        key: &AnnihlKey,
        antikey: &AnnihlKey,
    ) -> Result<(), AnnihlErr> {
        // Recovered base points for key and antikey should match
        let mut k_base = Point::recover_base(&key);
        let mut a_base = Point::recover_base(&antikey);
        if !bool::from(k_base.ct_eq(&a_base)) {
            k_base.zeroize();
            a_base.zeroize();

            return Err(AnnihlErr::PointMismatch);
        }
        a_base.zeroize();

        // Recalculated shared base point should match expected point
        let mut base = Point::shared_base(&key.solution, &antikey.solution);
        if !bool::from(k_base.ct_eq(&base)) {
            k_base.zeroize();
            base.zeroize();

            return Err(AnnihlErr::PointMismatch);
        }
        k_base.zeroize();
        base.zeroize();

        Ok(())
    }

    /// Derive a curve point by constructing a Scalar from a `u64` value,
    /// then multiplying it against the [ED25519_BASEPOINT_TABLE].
    pub fn from_u64(val: u64) -> EdwardsPoint {
        let mut scalar = Scalar::from(val);
        let point = &scalar * ED25519_BASEPOINT_TABLE;

        scalar.zeroize();
        point
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::traits::Identity;

    use super::*;
    use crate::annihilative::AnnihlKey;

    const IKM: &'static [u8; 20] = b"End Of The World Sun";
    const IAM: &'static [u8; 24] = b"Outlier/EOTWS_Variation1";
    const ALT_IKM: &'static [u8; 25] = b"65 Doesn't Understand You";
    const ALT_IAM: &'static [u8; 21] = b"Unmake the Wild Light";

    #[test]
    fn shared_base_is_commutative() {
        let (k_sol, a_sol) = Solution::mine(IKM, IAM, 16);

        let base_1 = Point::shared_base(&k_sol, &a_sol);
        let base_2 = Point::shared_base(&a_sol, &k_sol);

        // Order must not matter, point addition is commutative
        assert_eq!(base_1, base_2);
    }

    #[test]
    fn recover_base_with_key() {
        let (k_sol, a_sol) = Solution::mine(IKM, IAM, 16);

        let shared_base = Point::shared_base(&k_sol, &a_sol);

        let key = AnnihlKey::new(k_sol, shared_base);
        let recovered = Point::recover_base(&key);

        // Must recover shared base curve point from key alone
        assert_eq!(recovered, shared_base);
    }

    #[test]
    fn recover_base_with_antikey() {
        let (k_sol, a_sol) = Solution::mine(IKM, IAM, 16);

        let shared_base = Point::shared_base(&k_sol, &a_sol);

        let antikey = AnnihlKey::new(a_sol, shared_base);
        let recovered = Point::recover_base(&antikey);

        // Must recover shared base curve point from antikey alone
        assert_eq!(recovered, shared_base);
    }

    #[test]
    fn verify_pair_succeeds_valid_pair() {
        let (key, antikey) = AnnihlKey::new_pair(IKM, IAM, 16);

        // Valid pair must verify successfully
        let result = Point::verify_pair(&key, &antikey);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_pair_fails_recovered_bases_mismatch() {
        let (key, _) = AnnihlKey::new_pair(IKM, IAM, 16);
        let (_, antikey) = AnnihlKey::new_pair(ALT_IKM, ALT_IAM, 16);

        // Mismatch between recovered key and antikey shared base curve
        // points must result in an error
        let result = Point::verify_pair(&key, &antikey);
        assert_eq!(result, Err(AnnihlErr::PointMismatch));
    }

    #[test]
    fn verify_pair_fails_shared_base_mismatch() {
        let (mut key, mut antikey) = AnnihlKey::new_pair(IKM, IAM, 16);

        key.solution.commitment += 100;
        antikey.solution.commitment += 100;

        // Mismatch between recalculated and recovered shared base curve
        // points must result in an error
        let result = Point::verify_pair(&key, &antikey);
        assert_eq!(result, Err(AnnihlErr::PointMismatch));
    }

    #[test]
    fn from_u64_zero_produces_identity() {
        let point = Point::from_u64(0);

        // Zero scalar should produce the identity point
        assert_eq!(point, EdwardsPoint::identity());
    }
}
