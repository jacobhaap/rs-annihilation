use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use crate::constants::{ANTIKEY_MAGIC, KEY_MAGIC};
use crate::errors::AnnihlErr;

/*
/// Domain separation byte for keys.
const KEY: u8 = 0x4B;

/// Domain separation byte for antikeys.
const ANTIKEY: u8 = 0x41;

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
    */

/// Mine for a pair of solutions that satisfy the given proof-of-work
/// constraint.
///
/// Repeatedly derives candidates from the keying material with incremental
/// nonce values until finding a pair where the [Sha256] hash of their XOR
/// begins with a number of leading zero bits to satisfy the constraint.
///
/// Each solution's body is authenticated by its keying material.
pub fn pow_mine(ikm: &[u8], iam: &[u8], n: u8) -> ([u8; 32], [u8; 32]) {
    let mut nonce = 0u128;
    let mut k_candidate = [0u8; 32];
    let mut a_candidate = [0u8; 32];

    loop {
        derive_key(
            &mut k_candidate,
            ikm,
            nonce.wrapping_add(KEY_MAGIC as u128),
            n,
        );
        derive_key(
            &mut a_candidate,
            iam,
            nonce.wrapping_add(ANTIKEY_MAGIC as u128),
            n,
        );

        // 0x7F or below identifies key, 0x80 or above identifies antikey
        let k_id_ok = Choice::from((k_candidate[0] <= 0x7F) as u8);
        let a_id_ok = Choice::from((a_candidate[0] >= 0x80) as u8);

        // Hash of key XOR antikey should satisfy PoW constraint
        let pow_ok = match check_candidates(&k_candidate, &a_candidate) {
            Ok(mut xor_hash) => {
                xor_hash.zeroize();
                Choice::from(1u8)
            }
            Err(_) => Choice::from(0u8),
        };

        let satisfied = k_id_ok & a_id_ok & pow_ok;
        if bool::from(satisfied) {
            return (k_candidate, a_candidate);
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
pub fn check_candidates(
    key: &[u8; 32],
    antikey: &[u8; 32],
) -> Result<[u8; 32], AnnihlErr> {
    let n = key[1] as usize;
    if !bool::from(key[1].ct_eq(&antikey[1])) {
        return Err(AnnihlErr::ConstraintMatch);
    }

    let mut pair_xor = [0u8; 32];
    for i in 0..32 {
        pair_xor[i] = key[i] ^ antikey[i];
    }

    let mut hasher = Sha256::new();
    hasher.update(pair_xor);
    let mut artifact: [u8; 32] = hasher.finalize().into();
    pair_xor.zeroize();

    let bytes = n / 8;
    let bits = n % 8;

    // Verify first N bytes are zero, following N bits are zero
    let mut satisfied = Choice::from(1u8);
    for i in 0..bytes {
        satisfied &= artifact[i].ct_eq(&0u8);
    }
    if bits > 0 {
        let mask = (0xFF << (8 - bits)) as u8;
        satisfied &= (artifact[bytes] & mask).ct_eq(&0u8);
    }
    if !bool::from(satisfied) {
        artifact.zeroize();
        return Err(AnnihlErr::UnsatConstraint);
    }

    Ok(artifact)
}

/// Verify that a solution's `body` is authenticated by given keying
/// material.
///
/// Recomputes the expected body from the solution's identity, commitment,
/// and constraint, along with the given keying material, then verifies it
/// matches the actual body.
///
/// Returns an error if the recomputed body does not match the actual body.
pub fn authenticate(ikm: &[u8], key: [u8; 32]) -> Result<(), AnnihlErr> {
    let mut identity = key[0];
    let mut constraint = key[1];

    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&key[2..18]);

    let mut body = authenticate_ikm(ikm, identity, constraint, &nonce);
    identity.zeroize();
    constraint.zeroize();
    nonce.zeroize();

    let matches: bool = body.ct_eq(&key[18..32]).into();
    body.zeroize();

    if matches {
        Ok(())
    } else {
        Err(AnnihlErr::UnauthBody)
    }
}

fn derive_key(dst: &mut [u8; 32], ikm: &[u8], nonce: u128, constraint: u8) {
    let mut nonce_bytes = nonce.to_le_bytes();

    let mut hasher = Sha256::new();
    hasher.update(ikm);
    hasher.update(&nonce_bytes);
    hasher.update([constraint]);
    let mut okm: [u8; 32] = hasher.finalize().into();

    let identity = okm[0];
    dst[0] = identity;
    dst[1] = constraint;
    dst[2..18].copy_from_slice(&nonce_bytes);

    let mut body = authenticate_ikm(ikm, identity, constraint, &nonce_bytes);
    dst[18..32].copy_from_slice(&body);

    body.zeroize();
}

fn authenticate_ikm(
    ikm: &[u8],
    identity: u8,
    constraint: u8,
    nonce: &[u8; 16],
) -> [u8; 14] {
    let mut mac = Hmac::<Sha256>::new_from_slice(ikm)
        .expect("HMAC can take key of any size");
    mac.update(&[identity]);
    mac.update(&[constraint]);
    mac.update(nonce);
    let mut digest: [u8; 32] = mac.finalize().into_bytes().into();

    let mut body = [0u8; 14];
    body.copy_from_slice(&digest[..14]);
    digest.zeroize();
    body
}

/*
#[cfg(test)]
mod tests {
    use super::*;

    const IKM: &'static [u8; 20] = b"End Of The World Sun";
    const IAM: &'static [u8; 24] = b"Outlier/EOTWS_Variation1";

    #[test]
    fn mine_produces_valid_identities() {
        let (k_sol, a_sol) = Solution::mine(IKM, IAM, 8);

        // Identity bytes must be <= 0x7F for key, >= 0x80 for antikey
        assert!(k_sol.identity <= 0x7F);
        assert!(a_sol.identity >= 0x80);
    }

    #[test]
    fn mine_prevents_commitment_collisions() {
        let (k_sol, a_sol) = Solution::mine(IKM, IAM, 8);

        let magic_diff = KEY_MAGIC.wrapping_sub(ANTIKEY_MAGIC);
        let k_plus = k_sol.commitment.wrapping_add(magic_diff);
        let k_wrapped = k_plus < k_sol.commitment;

        // Commitments must not produce collision conditions
        assert!(!(k_sol.commitment == a_sol.commitment));
        assert!(!(a_sol.commitment == k_plus && !k_wrapped))
    }

    #[test]
    fn mine_produces_matching_constraints() {
        let (k_sol, a_sol) = Solution::mine(IKM, IAM, 8);

        // Constraints must match
        assert_eq!(k_sol.constraint, a_sol.constraint);
    }

    #[test]
    fn verify_succeeds_valid_pair() {
        let (k_sol, a_sol) = Solution::mine(IKM, IAM, 8);

        // The verification artifact must begin with 8 zero bits
        let result = k_sol.verify(&a_sol);
        assert!(result.is_ok());
        let artifact = result.unwrap();
        assert_eq!(artifact[0..1], [0u8; 1]);
    }

    #[test]
    fn verify_fails_invalid_pair() {
        let (k_sol, _) = Solution::mine(IKM, IAM, 8);

        // Invalid pair must result in an error
        let result = k_sol.verify(&k_sol);
        assert_eq!(result, Err(AnnihlErr::InvalidPair));
    }

    #[test]
    fn verify_fails_mismatched_constraints() {
        let (mut k_sol, mut a_sol) = Solution::mine(IKM, IAM, 8);

        k_sol.constraint = 12;
        a_sol.constraint = 20;

        // Non-matching constraints must result in an error
        let result = k_sol.verify(&a_sol);
        assert_eq!(result, Err(AnnihlErr::ConstraintMatch));
    }

    #[test]
    fn verify_fails_colliding_commitments() {
        let (mut k_sol, mut a_sol) = Solution::mine(IKM, IAM, 8);

        a_sol.commitment = k_sol.commitment;
        k_sol.constraint = 8;
        a_sol.constraint = 8;

        // Colliding commitments must result in an error
        let result = k_sol.verify(&a_sol);
        assert_eq!(result, Err(AnnihlErr::CommitCollision));
    }

    #[test]
    fn verify_fails_unsatisfied_byte_constraint() {
        let (mut k_sol, mut a_sol) = Solution::mine(IKM, IAM, 8);

        k_sol.constraint = 24;
        a_sol.constraint = 24;

        // Unsatisfied constraint on byte level must result in an error
        let result = k_sol.verify(&a_sol);
        assert_eq!(result, Err(AnnihlErr::UnsatConstraint));
    }

    #[test]
    fn verify_fails_unsatisfied_bit_constraint() {
        let (mut k_sol, mut a_sol) = Solution::mine(IKM, IAM, 8);

        k_sol.constraint = 20;
        a_sol.constraint = 20;

        // Unsatisfied constraint on bit level must result in an error
        let result = k_sol.verify(&a_sol);
        assert_eq!(result, Err(AnnihlErr::UnsatConstraint));
    }

    #[test]
    fn authenticate_succeeds_correct_ikm() {
        let (solution, _) = Solution::mine(IKM, IAM, 8);

        // Authentication with correct keying material must yield Ok result
        let result = solution.authenticate(IKM);
        assert!(result.is_ok());
    }

    #[test]
    fn authenticate_fails_incorrect_ikm() {
        let (solution, _) = Solution::mine(IKM, IAM, 8);

        // Authentication with wrong keying material must result in an error
        let result = solution.authenticate(IAM);
        assert_eq!(result, Err(AnnihlErr::UnauthBody));
    }

    #[test]
    fn to_bytes_produces_32_byte_array() {
        let (solution, _) = Solution::mine(IKM, IAM, 8);

        // Solution must be exactly 32 bytes
        let bytes = solution.to_bytes();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn from_reconstructs_solution() {
        let (solution, _) = Solution::mine(IKM, IAM, 8);

        let bytes = solution.to_bytes();
        let reconstructed = Solution::from(bytes);

        // Reconstructed solution must match original
        assert_eq!(solution, reconstructed);
    }
}
*/
