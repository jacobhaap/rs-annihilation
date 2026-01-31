use sha2::{Digest, Sha256};

use crate::annihilative::{ANTIKEY_MAGIC, KEY_MAGIC};
use crate::errors::AnnihilationError;

const KEY_DOMAIN_BYTE: u8 = 0x4B;
const ANTIKEY_DOMAIN_BYTE: u8 = 0x41;

/// A zero-sized namespace providing functions for proof of work operations
/// to mine annihilative key pair solutions and verify that solutions satisfy
/// the proof of work constraint.
pub struct ProofOfWork;

impl ProofOfWork {
    /// Mine for a valid annihilative key and antikey pair that satisfies the
    /// given constraint.
    ///
    /// Incrementally derives key and antikey candidates from the keying
    /// material with different nonce values until finding a pair where the
    /// SHA256 hash of their XOR begins with the required number of zero bits
    /// specified by the constraint parameter.
    pub fn mine(
        key_material: &[u8],
        antikey_material: &[u8],
        constraint: u8,
    ) -> ([u8; 32], [u8; 32]) {
        let mut nonce = 0u128;
        let magic_diff = KEY_MAGIC.wrapping_sub(ANTIKEY_MAGIC);
        loop {
            // Create new candidates from keying material, nonce, constraint
            let mut key = Self::derive_key(
                key_material,
                nonce,
                constraint,
                KEY_DOMAIN_BYTE,
            );
            let mut antikey = Self::derive_key(
                antikey_material,
                nonce,
                constraint,
                ANTIKEY_DOMAIN_BYTE,
            );
            // Mine for a pair where the first byte of the key is below 0x7F,
            // the first byte of the antikey is 0x80 or above.
            let k_id_ok = key[0] <= 0x7F;
            let a_id_ok = antikey[0] >= 0x80;
            // Check to prevent commitment collision conditions
            let k_commit = u64::from_le_bytes(
                key[1..9]
                    .try_into()
                    .expect("key commitment should be 8 bytes"),
            );
            let a_commit = u64::from_le_bytes(
                antikey[1..9]
                    .try_into()
                    .expect("antikey commitment should be 8 bytes"),
            );
            let commitment_ok = k_commit != a_commit
                && a_commit != k_commit.wrapping_add(magic_diff)
                && k_commit != a_commit.wrapping_sub(magic_diff);
            // Set the constraint on the final byte of each
            key[31] = constraint;
            antikey[31] = constraint;
            // The hash of the key XOR antikey result begins with leading
            // zeros to satisfy the constraint.
            let satisfied = Self::verify(&key, &antikey).is_ok();
            if k_id_ok && a_id_ok && commitment_ok && satisfied {
                return (key, antikey);
            }
            nonce += 1;
        }
    }
    /// Verify that an annihilative key and antikey pair satisfies their
    /// proof of work constraint.
    ///
    /// Computes the XOR of the key and antikey, and verifies that its
    /// hash begins with the required number of zero bits. Returns the hash
    /// as an artifact on success, or an error when a constraint mismatch
    /// or unsatisfied constraint is encountered.
    pub fn verify(
        key: &[u8; 32],
        antikey: &[u8; 32],
    ) -> Result<[u8; 32], AnnihilationError> {
        // Extract the constraint, verify constraints match
        let constraint = key[31] as usize;
        if key[31] != antikey[31] {
            return Err(AnnihilationError::ConstraintMismatch);
        }
        // Compute key XOR antikey, hash the result
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = key[i] ^ antikey[i];
        }
        let mut hasher = Sha256::new();
        hasher.update(&result);
        let xor_hash: [u8; 32] = hasher.finalize().into();
        // Calculate constraint bytes and bits
        let bytes = constraint / 8;
        let bits = constraint % 8;
        // Verify first N bytes are zero
        if !xor_hash[..bytes].iter().all(|&b| b == 0) {
            return Err(AnnihilationError::UnsatisfiedConstraint);
        }
        // Verify following N bits are zero
        if bits > 0 {
            let mask = (0xFF << (8 - bits)) as u8;
            if (xor_hash[bytes] & mask) != 0 {
                return Err(AnnihilationError::UnsatisfiedConstraint);
            }
        }
        Ok(xor_hash)
    }
    fn derive_key(
        ikm: &[u8],
        nonce: u128,
        constraint: u8,
        domain: u8,
    ) -> [u8; 32] {
        // Hash keying material with nonce and constraint
        let mut hasher = Sha256::new();
        hasher.update(&[domain]);
        hasher.update(&ikm);
        hasher.update(&nonce.to_le_bytes());
        hasher.update(&[constraint]);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_mine() {
        // Mine for key and antikey pair, constraint of 16 bits
        let (key, antikey) = ProofOfWork::mine(
            b"some key material",
            b"some antikey material",
            16,
        );
        // Identity bytes must be <= 0x7F for key, >= 0x80 for antikey
        assert!(key[0] <= 0x7F);
        assert!(antikey[0] >= 0x80);
        // Commitments must be unrelated
        let k_commit = u64::from_le_bytes(key[1..9].try_into().unwrap());
        let a_commit = u64::from_le_bytes(antikey[1..9].try_into().unwrap());
        let magic_diff = KEY_MAGIC.wrapping_sub(ANTIKEY_MAGIC);
        assert_ne!(k_commit, a_commit);
        assert_ne!(a_commit, k_commit.wrapping_add(magic_diff));
        assert_ne!(k_commit, a_commit.wrapping_sub(magic_diff));
        // Constraint bytes must match
        assert_eq!(key[31], antikey[31]);
    }

    #[test]
    fn test_verify() {
        // Key and antikey solutions from hex literals
        let mut key = hex!(
            "601642db10eeecfe4ff0ba820d877d17bde069485f536653c1acd2242d9a1010"
        );
        let mut antikey = hex!(
            "8569f3eaf5fda69748f3ea7f7f9d35dac8904beec93fec5ff0b41e852b7d1b10"
        );
        // Verify that the pair satisfies the proof of work constraint,
        // where the verification artifact begins with 16 zero bits.
        let result = ProofOfWork::verify(&key, &antikey).unwrap();
        assert_eq!(result[0..2], [0u8; 2]);
        // Overwrite each constraint to force a mismatch error
        key[31] = 12;
        antikey[31] = 20;
        let result = ProofOfWork::verify(&key, &antikey);
        assert_eq!(result, Err(AnnihilationError::ConstraintMismatch));
        // Increase constraint to require 3 bytes to force an unsatisfied
        // constraint error for the zero bytes of the resulting XOR hash.
        key[31] = 24;
        antikey[31] = 24;
        let result = ProofOfWork::verify(&key, &antikey);
        assert_eq!(result, Err(AnnihilationError::UnsatisfiedConstraint));
        // Set constraint to require 20 bits to force an unsatisfied
        // constraint error for the zero bits of the resulting XOR hash.
        key[31] = 20;
        antikey[31] = 20;
        let result = ProofOfWork::verify(&key, &antikey);
        assert_eq!(result, Err(AnnihilationError::UnsatisfiedConstraint));
    }
}
