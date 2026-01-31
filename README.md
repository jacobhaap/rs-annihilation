# Annihilative Keys in Rust
A Rust implementation of Annihilative Keys.

> This project contains new and experimental cryptography that has not undergone any review or audit. In the absence of cryptanalysis, use at your own risk.

Provides cryptographic key pairs where a key and antikey are each derived from separate keying material but must jointly satisfy a proof of work constraint. The mining process finds solutions where the SHA256 hash of the key XOR antikey begins with a specified number of zero bits, binding the pair cryptographically.

Pairs can be verified by recovering and comparing their shared base curve point, and checking that the solutions satisfy the proof of work constraint. Valid pairs can be combined to produce a shared annihilation key.

With the `convergent` feature, annihilative pairs can independently derive the same shared Ed25519 signing and verifying keys. With the `divergent` feature, each member of the pair derives its own unique Ed25519 identity.

```rust
use annihilation::{AnnihilativeKey, Convergent, Divergent};

fn main() {
    let k_ikm = b"End Of The World Sun";
    let a_ikm = b"Outlier/EOTWS_Variation1";

    let (key, antikey) = AnnihilativeKey::new_pair(k_ikm, a_ikm, 16);

    let artifact = key.verify(&antikey);
    assert!(artifact.is_ok());

    let annihilation_key = key.to_annihilation(&antikey);
    assert!(annihilation_key.is_ok());

    let context = b"65daysofstatic";
    let k_shared = key.shared_signing_key(Some(context));
    let a_shared = antikey.shared_signing_key(Some(context));
    assert_eq!(k_shared, a_shared);

    let k_own = key.own_signing_key(Some(context));
    let a_own = antikey.own_signing_key(Some(context));
    assert_ne!(k_own, a_own);
}
```
