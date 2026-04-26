# Annihilative Keys in Rust

![Crates.io Version](https://img.shields.io/crates/v/annihilation)
![Crates.io License](https://img.shields.io/crates/l/annihilation)
![docs.rs](https://img.shields.io/docsrs/annihilation)

Pure Rust implementation of Annihilative Keys.

[Documentation](https://docs.rs/annihilation/)

> This project contains new and experimental cryptography that has not undergone any review or audit. In the absence of cryptanalysis, use at your own risk.

# About

Annihilative Keys provide a novel construction where a pair of cryptographic keys, consisting of a key and antikey, are derived from separate keying materials. An annihilative key consists of:

 - A mined proof-of-work solution, consisting of an identity byte, cryptographic commitment, authenticated body, and constraint parameter.
 - A compressed elliptic curve point on Curve25519.

A key and antikey together form an annihilative pair, bound through computational proof-of-work and an elliptic curve point relationship. A valid pair is capable of producing a symmetric key through annihilation. As long as one half of the pair remains secret, the secrecy of the derived annihilation key is preserved.

# Minimum Supported Rust Version

Rust **1.85.1** or higher.

# License

Licensed under the [MIT License](https://opensource.org/license/MIT).
