use serde::{Deserialize, Serialize};

/// `POST /members` request (admin): register a member bank's Ed25519 request-signing key
/// (production-spec v1.4 section 10). Admission is a governance decision made off-protocol.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct RegisterMemberRequest {
    /// The member bank's identifier.
    pub bank_id: String,
    /// The member's Ed25519 public key, 32 bytes as lowercase hex.
    pub pubkey_hex: String,
}

/// One member bank in the registry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemberInfo {
    /// The member bank's identifier.
    pub bank_id: String,
    /// The member's Ed25519 public key, lowercase hex.
    pub pubkey_hex: String,
    /// Whether the member is the governance admin.
    pub is_admin: bool,
}

/// Response of `GET /members`: the registered member banks.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct MembersResponse {
    /// The registered members, in ascending `bank_id` order.
    pub members: Vec<MemberInfo>,
}

/// `POST /serials` request: a depositing bank submits a coin's serial and a transcript digest
/// at deposit time, to the shared spent-serial store (production-spec v1.4 section 10). The
/// depositing bank is the authenticated caller, not a body field.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SerialSubmission {
    /// The bank that issued the coin (whose receivable this deposit grows).
    pub issuing_bank_id: String,
    /// The coin denomination, in cents.
    pub denomination_cents: u64,
    /// The coin's signature scheme.
    pub scheme_id: u8,
    /// The coin serial, lowercase hex.
    pub serial_hex: String,
    /// The transcript digest `H(coin_serial || depositing_bank_id || timestamp)`, lowercase
    /// hex, for bank-level attribution on a collision.
    pub transcript: String,
}

/// Whether a submitted serial was fresh or a double-spend.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SerialOutcome {
    /// The serial was not seen before; the deposit may proceed.
    Accepted,
    /// The serial was already deposited (possibly at another bank).
    DoubleSpend,
}

/// One submitted transcript digest for a serial, retained for attribution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TranscriptEntry {
    /// The bank that submitted this transcript.
    pub bank_id: String,
    /// The transcript digest, lowercase hex.
    pub transcript: String,
    /// When it was submitted, Unix seconds.
    pub seen_at: u64,
}

/// `POST /serials` response.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SerialResponse {
    /// Whether the serial was accepted or is a double-spend.
    pub outcome: SerialOutcome,
    /// On a double-spend, every transcript recorded for the serial (both banks' digests);
    /// empty when accepted.
    pub transcripts: Vec<TranscriptEntry>,
}
