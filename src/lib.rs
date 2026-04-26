//! A Rust implementation of Annihilative Keys, providing a novel construction
//! where a pair of cryptographic keys, consisting of a key and antikey, are
//! derived from separate keying materials. The pair is bound through two
//! mechanisms: computational proof-of-work, and an elliptic curve point
//! relationship.
//!
//! An **annihilative key** consists of:
//! - A mined proof-of-work **solution**, consisting of an identity byte,
//! cryptographic commitment, authenticated body, and constraint parameter.
//! - A compressed elliptic **curve point** on Curve25519.
//!
//! A **key** is derived from initial keying material, and is identified by
//! identity bytes <= `0x7F`. An **antikey** is derived from initial antikeying
//! material, and is identified by identity bytes >= `0x80`. An **annihilative
//! pair** consists of a key and an antikey whose solutions satisfy a given
//! proof-of-work constraint, and whose curve points share the same base point.
//!
//! Each pair member's solution includes a body that authenticates the
//! solution's identity, commitment, and constraint against the member's
//! keying material, binding all three to its source material.
//!
//! The mining process finds proof-of-work solutions where the SHA256 hash of
//! an annihilative pair's XOR begins with a constrained number of zero bits,
//! binding the pair cryptographically. A shared base curve point is jointly
//! derived from the solutions of both pair members, from which each member's
//! curve point is derived by applying a commitment-derived offset.
//!
//! Annihilative pairs are verified by validating that their elliptic curve
//! points share a base point, and by checking that the hash of their solutions
//! XOR begins with the constrained number of zero bits.
//!
//! # Annihilation
//!
//! A valid annihilative pair is capable of annihilation, where an
//! **annihilation key** is derived by computing an HMAC of the pair's
//! verification artifact (XOR hash), keyed by the sum of both members' curve
//! points. Annihilation requires both a key and antikey to compute. As long as
//! one half of the annihilative pair remains secret, the secrecy of the
//! derived annihilation key is preserved.
//!
//! # Features
//!
//! Annihilative keys can derive convergent and divergent Ed25519 identities,
//! where:
//!
//! - With the `convergent` feature, both members of an annihilative pair can
//! independently derive the same shared signing and verifying keys.
//! - With the `divergent` feature, both members of an annihilative pair derive
//! their own unique signing and verifying keys.
//!
//! # Example
//! ```
//! use annihilation::AnnihlKey;
//!
//! fn main() {
//!     let ikm = b"End Of The World Sun";
//!     let iam = b"Outlier/EOTWS_Variation1";
//!
//!     // Mine for a pair with a 16 bit proof-of-work constraint
//!     let (key, antikey) = AnnihlKey::new_pair(ikm, iam, 16);
//!
//!     // Authenticate each member against its source material
//!     let k_auth = key.authenticate(ikm);
//!     let a_auth = antikey.authenticate(iam);
//!     assert!(k_auth.is_ok());
//!     assert!(a_auth.is_ok());
//!
//!     // Check if the pair is valid, then annihilate
//!     let result = key.verify(&antikey);
//!     assert!(result.is_ok());
//!
//!     let annihilation_key = key.to_annihilation(&antikey);
//!     assert!(annihilation_key.is_ok());
//!
//!     #[cfg(feature = "convergent")]
//!     {
//!         // Derive Ed25519 convergent identities
//!         let context = b"65daysofstatic";
//!
//!         let k_shared = key.shared_signing_key(Some(context));
//!         let a_shared = antikey.shared_signing_key(Some(context));
//!         assert_eq!(k_shared, a_shared);
//!     }
//!
//!     #[cfg(feature = "divergent")]
//!     {
//!         // Derive Ed25519 divergent identities
//!         let context = b"65daysofstatic";
//!
//!         let k_own = key.own_signing_key(Some(context));
//!         let a_own = antikey.own_signing_key(Some(context));
//!         assert_ne!(k_own, a_own);
//!     }
//! }
//! ```
mod annihilative;
mod errors;
mod point;
mod solution;

pub use crate::annihilative::AnnihlKey;
pub use crate::errors::AnnihlErr;
pub use crate::point::Point;
pub use crate::solution::Solution;
