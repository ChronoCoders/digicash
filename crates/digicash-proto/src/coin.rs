use serde::{Deserialize, Serialize};

/// A coin: a bearer instrument. Whoever holds the serialized value can deposit it.
///
/// `signature` is an RFC 9474 blind signature over `serial_number`, produced under the
/// bank's `(denomination_cents, scheme_id)` key. `scheme_id` 0 is
/// RSABSSA-SHA384-PSS-Deterministic (the value `digicash_core::SCHEME_ID_RSA_DETERMINISTIC`);
/// the coin's value is determined entirely by which key signed it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Coin {
    /// Which signature scheme signed the coin; `0` is RSABSSA-SHA384-PSS-Deterministic.
    pub scheme_id: u8,
    /// The coin's face value, in integer cents.
    pub denomination_cents: u64,
    /// The 256-bit serial the signature covers; unique per coin.
    pub serial_number: [u8; 32],
    /// The bank's RFC 9474 blind signature over `serial_number`.
    pub signature: Vec<u8>,
}
