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
