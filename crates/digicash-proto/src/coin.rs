use serde::{Deserialize, Serialize};

/// A coin: a bearer instrument. Whoever holds the serialized value can deposit it.
///
/// `signature` is an RFC 9474 blind signature over `serial_number`, produced under the
/// bank's `(denomination_cents, scheme_id)` key. `scheme_id` 0 is
/// RSABSSA-SHA384-PSS-Deterministic (the value `digicash_core::SCHEME_ID_RSA_DETERMINISTIC`);
/// the coin's value is determined entirely by which key signed it.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Coin {
    pub scheme_id: u8,
    pub denomination_cents: u64,
    pub serial_number: [u8; 32],
    pub signature: Vec<u8>,
}
