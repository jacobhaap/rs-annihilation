use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::{
    Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::annihilative::{ANTIKEY_MAGIC, KEY_MAGIC};
use crate::errors::AnnihlErr;

const KEY_DOMAIN_BYTE: u8 = 0x4B;
const ANTIKEY_DOMAIN_BYTE: u8 = 0x41;

pub(crate) trait Identity {
    fn identity_byte(&self) -> u8;

    fn validate_pair<'a>(
        &'a self,
        other: &'a Self,
    ) -> Result<(&'a Self, &'a Self), AnnihlErr> {
        let self_is_key =
            Choice::from(((self.identity_byte() & 0x80) == 0) as u8);
        let other_is_key =
            Choice::from(((other.identity_byte() & 0x80) == 0) as u8);

        // Cannot be two keys or two antikeys
        if !bool::from(self_is_key ^ other_is_key) {
            return Err(AnnihlErr::InvalidPair);
        }

        // Return the valid key and antikey tuple
        if bool::from(self_is_key) {
            Ok((self, other))
        } else {
            Ok((other, self))
        }
    }
}

/// A `Solution` represents the serialised proof-of-work solution of an
/// annihilative key.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Solution {
    /// Identifies whether the solution represents a key or antikey.
    ///
    /// Values of `0x7F` or below identify key solutions, and values of
    /// `0x80` or above identify antikey solutions.
    pub identity: u8,

    /// Cryptographic commitment used for binding the solution to its keying
    /// material, and as a pseudorandom value for deriving a curve point
    /// offset.
    pub commitment: u64,

    /// HMAC digest authenticating the solution's identity, commitment, and
    /// constraint against its keying material.
    pub body: [u8; 22],

    /// Proof-of-Work constraint, as a number of leading zero bits.
    pub constraint: u8,
}

impl Solution {
    /// Mine for a pair of solutions that satisfy the given proof-of-work
    /// constraint.
    ///
    /// Repeatedly derives candidates from the keying material with incremental
    /// nonce values until finding a pair where the [Sha256] hash of their XOR
    /// begins with a number of leading zero bits to satisfy the constraint.
    ///
    /// Each solution's body is authenticated by its keying material.
    pub fn mine(
        ikm: &[u8],
        iam: &[u8],
        constraint: u8,
    ) -> (Solution, Solution) {
        let mut nonce = 0u128;

        loop {
            let mut key_solution =
                Self::derive_key(ikm, nonce, constraint, KEY_DOMAIN_BYTE);
            let mut antikey_solution =
                Self::derive_key(iam, nonce, constraint, ANTIKEY_DOMAIN_BYTE);

            key_solution[31] = constraint;
            antikey_solution[31] = constraint;

            // 0x7F or below identifies key, 0x80 or above identifies antikey
            let k_id_ok = Choice::from((key_solution[0] <= 0x7F) as u8);
            let a_id_ok = Choice::from((antikey_solution[0] >= 0x80) as u8);

            let key = Self::from(&key_solution);
            let antikey = Self::from(&antikey_solution);
            key_solution.zeroize();
            antikey_solution.zeroize();

            // Hash of key XOR antikey should satisfy PoW constraint
            let satisfied = match key.verify(&antikey) {
                Ok(mut xor_hash) => {
                    xor_hash.zeroize();
                    Choice::from(1u8)
                }
                Err(_) => Choice::from(0u8),
            };

            let all_ok = k_id_ok & a_id_ok & satisfied;
            if bool::from(all_ok) {
                return (key, antikey);
            }

            nonce += 1;
        }
    }

    /// Verify that a pair of solutions satisfy their proof-of-work constraint.
    ///
    /// Computes the XOR of both solutions, and verifies that its hash begins
    /// with the required number of zero bits.
    ///
    /// Returns the hash as an artifact on success, or an error when a
    /// constraint mismatch or unsatisfied constraint is encountered.
    pub fn verify(&self, other: &Solution) -> Result<[u8; 32], AnnihlErr> {
        let (key, antikey) = match Self::validate_pair(&self, &other) {
            Ok(pair) => pair,
            Err(e) => return Err(e),
        };

        let constraint = key.constraint as usize;
        if !bool::from(key.constraint.ct_eq(&antikey.constraint)) {
            return Err(AnnihlErr::ConstraintMatch);
        }

        let magic_diff = KEY_MAGIC.wrapping_sub(ANTIKEY_MAGIC);
        let mut k_plus = key.commitment.wrapping_add(magic_diff);

        // Overflow occurred if result is less than input
        let k_wrapped = k_plus.ct_lt(&key.commitment);

        // Commitments cannot be equal, antikey commitment cannot equal
        // key commitment plus magic diff unless wrap occurred
        let collision = key.commitment.ct_eq(&antikey.commitment)
            | (antikey.commitment.ct_eq(&k_plus) & !k_wrapped);

        k_plus.zeroize();

        if bool::from(collision) {
            return Err(AnnihlErr::CommitCollision);
        }

        let mut pair_xor = [0u8; 32];
        let mut key_bytes = key.to_bytes();
        let mut antikey_bytes = antikey.to_bytes();
        for i in 0..32 {
            pair_xor[i] = key_bytes[i] ^ antikey_bytes[i];
        }
        key_bytes.zeroize();
        antikey_bytes.zeroize();

        let mut hasher = Sha256::new();
        hasher.update(&pair_xor);
        let mut xor_hash: [u8; 32] = hasher.finalize().into();
        pair_xor.zeroize();

        let bytes = constraint / 8;
        let bits = constraint % 8;

        // Verify first N bytes are zero, following N bits are zero
        let mut satisfied = Choice::from(1u8);
        for i in 0..bytes {
            satisfied &= xor_hash[i].ct_eq(&0u8);
        }
        if bits > 0 {
            let mask = (0xFF << (8 - bits)) as u8;
            satisfied &= (xor_hash[bytes] & mask).ct_eq(&0u8);
        }
        if !bool::from(satisfied) {
            xor_hash.zeroize();
            return Err(AnnihlErr::UnsatConstraint);
        }

        Ok(xor_hash)
    }

    /// Verify that a solution's `body` is authenticated by given keying
    /// material.
    ///
    /// Recomputes the expected body from the solution's identity, commitment,
    /// and constraint, along with the given keying material, then verifies it
    /// matches the actual body.
    ///
    /// Returns an error if the recomputed body does not match the actual body.
    pub fn authenticate(&self, ikm: &[u8]) -> Result<(), AnnihlErr> {
        let is_key = Choice::from((self.identity <= 0x7F) as u8);
        let domain = u8::conditional_select(
            &ANTIKEY_DOMAIN_BYTE,
            &KEY_DOMAIN_BYTE,
            is_key,
        );

        let mut commitment = self.commitment.to_le_bytes();
        let mut body = Self::authenticate_ikm(
            ikm,
            self.identity,
            &commitment,
            self.constraint,
            domain,
        );
        commitment.zeroize();

        let matches: bool = body.ct_eq(&self.body).into();
        body.zeroize();

        if matches {
            Ok(())
        } else {
            Err(AnnihlErr::UnauthBody)
        }
    }

    /// Copy this `Solution` to a 32 byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut commitment = self.commitment.to_le_bytes();

        let mut bytes = [0u8; 32];
        bytes[0] = self.identity;
        bytes[1..9].copy_from_slice(&commitment);
        bytes[9..31].copy_from_slice(&self.body);
        bytes[31] = self.constraint;

        commitment.zeroize();

        bytes
    }

    fn derive_key(
        ikm: &[u8],
        nonce: u128,
        constraint: u8,
        domain: u8,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&[domain]);
        hasher.update(&ikm);
        hasher.update(&nonce.to_le_bytes());
        hasher.update(&[constraint]);
        let mut okm: [u8; 32] = hasher.finalize().into();

        let identity = okm[0];
        let commitment = &okm[1..9];

        let mut body = Self::authenticate_ikm(
            ikm, identity, commitment, constraint, domain,
        );

        okm[9..31].copy_from_slice(&body);
        body.zeroize();
        okm
    }

    fn authenticate_ikm(
        ikm: &[u8],
        identity: u8,
        commitment: &[u8],
        constraint: u8,
        domain: u8,
    ) -> [u8; 22] {
        let mut mac = Hmac::<Sha256>::new_from_slice(ikm)
            .expect("HMAC can take key of any size");
        mac.update(&[domain]);
        mac.update(&[identity]);
        mac.update(commitment);
        mac.update(&[constraint]);
        let mut digest: [u8; 32] = mac.finalize().into_bytes().into();

        let mut body = [0u8; 22];
        body.copy_from_slice(&digest[..22]);
        digest.zeroize();
        body
    }
}

impl From<&[u8; 32]> for Solution {
    /// Construct a `Solution` from a 32 byte array.
    fn from(value: &[u8; 32]) -> Self {
        let mut body = [0u8; 22];
        body.copy_from_slice(&value[9..31]);

        let commitment = u64::from_le_bytes([
            value[1], value[2], value[3], value[4], value[5], value[6],
            value[7], value[8],
        ]);

        Self {
            identity: value[0],
            commitment,
            body,
            constraint: value[31],
        }
    }
}

impl PartialEq for Solution {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Solution {}

impl ConstantTimeEq for Solution {
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut self_bytes = self.to_bytes();
        let mut other_bytes = other.to_bytes();

        let result = self_bytes.ct_eq(&other_bytes);

        self_bytes.zeroize();
        other_bytes.zeroize();

        result
    }
}

impl Identity for Solution {
    fn identity_byte(&self) -> u8 {
        self.identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IKM: &'static [u8; 20] = b"End Of The World Sun";
    const IAM: &'static [u8; 24] = b"Outlier/EOTWS_Variation1";

    #[test]
    fn mine_produces_valid_identities() {
        let (k_sol, a_sol) = Solution::mine(IKM, IAM, 16);

        // Identity bytes must be <= 0x7F for key, >= 0x80 for antikey
        assert!(k_sol.identity <= 0x7F);
        assert!(a_sol.identity >= 0x80);
    }

    #[test]
    fn mine_prevents_commitment_collisions() {
        let (k_sol, a_sol) = Solution::mine(IKM, IAM, 16);

        let magic_diff = KEY_MAGIC.wrapping_sub(ANTIKEY_MAGIC);
        let k_plus = k_sol.commitment.wrapping_add(magic_diff);
        let k_wrapped = k_plus < k_sol.commitment;

        // Commitments must not produce collision conditions
        assert!(!(k_sol.commitment == a_sol.commitment));
        assert!(!(a_sol.commitment == k_plus && !k_wrapped))
    }

    #[test]
    fn mine_produces_matching_constraints() {
        let (k_sol, a_sol) = Solution::mine(IKM, IAM, 16);

        // Constraints must match
        assert_eq!(k_sol.constraint, a_sol.constraint);
    }

    #[test]
    fn verify_succeeds_valid_pair() {
        let (k_sol, a_sol) = Solution::mine(IKM, IAM, 16);

        // The verification artifact must begin with 16 zero bits
        let result = k_sol.verify(&a_sol);
        assert!(result.is_ok());
        let artifact = result.unwrap();
        assert_eq!(artifact[0..2], [0u8; 2]);
    }

    #[test]
    fn verify_fails_invalid_pair() {
        let (k_sol, _) = Solution::mine(IKM, IAM, 16);

        // Invalid pair must result in an error
        let result = k_sol.verify(&k_sol);
        assert_eq!(result, Err(AnnihlErr::InvalidPair));
    }

    #[test]
    fn verify_fails_mismatched_constraints() {
        let (mut k_sol, mut a_sol) = Solution::mine(IKM, IAM, 16);

        k_sol.constraint = 12;
        a_sol.constraint = 20;

        // Non-matching constraints must result in an error
        let result = k_sol.verify(&a_sol);
        assert_eq!(result, Err(AnnihlErr::ConstraintMatch));
    }

    #[test]
    fn verify_fails_colliding_commitments() {
        let (mut k_sol, mut a_sol) = Solution::mine(IKM, IAM, 16);

        a_sol.commitment = k_sol.commitment;
        k_sol.constraint = 16;
        a_sol.constraint = 16;

        // Colliding commitments must result in an error
        let result = k_sol.verify(&a_sol);
        assert_eq!(result, Err(AnnihlErr::CommitCollision));
    }

    #[test]
    fn verify_fails_unsatisfied_byte_constraint() {
        let (mut k_sol, mut a_sol) = Solution::mine(IKM, IAM, 16);

        k_sol.constraint = 24;
        a_sol.constraint = 24;

        // Unsatisfied constraint on byte level must result in an error
        let result = k_sol.verify(&a_sol);
        assert_eq!(result, Err(AnnihlErr::UnsatConstraint));
    }

    #[test]
    fn verify_fails_unsatisfied_bit_constraint() {
        let (mut k_sol, mut a_sol) = Solution::mine(IKM, IAM, 16);

        k_sol.constraint = 20;
        a_sol.constraint = 20;

        // Unsatisfied constraint on bit level must result in an error
        let result = k_sol.verify(&a_sol);
        assert_eq!(result, Err(AnnihlErr::UnsatConstraint));
    }

    #[test]
    fn authenticate_succeeds_correct_ikm() {
        let (solution, _) = Solution::mine(IKM, IAM, 16);

        // Authentication with correct keying material must yield Ok result
        let result = solution.authenticate(IKM);
        assert!(result.is_ok());
    }

    #[test]
    fn authenticate_fails_incorrect_ikm() {
        let (solution, _) = Solution::mine(IKM, IAM, 16);

        // Authentication with wrong keying material must result in an error
        let result = solution.authenticate(IAM);
        assert_eq!(result, Err(AnnihlErr::UnauthBody));
    }

    #[test]
    fn to_bytes_produces_32_byte_array() {
        let (solution, _) = Solution::mine(IKM, IAM, 16);

        // Solution must be exactly 32 bytes
        let bytes = solution.to_bytes();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn from_reconstructs_solution() {
        let (solution, _) = Solution::mine(IKM, IAM, 16);

        let bytes = solution.to_bytes();
        let reconstructed = Solution::from(&bytes);

        // Reconstructed solution must match original
        assert_eq!(solution, reconstructed);
    }
}
