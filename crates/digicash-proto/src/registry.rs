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

/// Whether a submitted serial was accepted, rejected as a double-spend, or blocked by the
/// per-issuer exposure cap.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SerialOutcome {
    /// The serial was not seen before; the deposit may proceed.
    Accepted,
    /// The serial was already deposited (possibly at another bank).
    DoubleSpend,
    /// The depositing bank's outstanding receivable against the issuer has reached the cap;
    /// no further coins from that issuer are accepted until settlement clears.
    ExposureCapExceeded,
}

/// `POST /caps` request (admin): set the per-issuer exposure cap for a bank pair.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SetCapRequest {
    /// The issuing bank the cap limits exposure to.
    pub issuing_bank_id: String,
    /// The depositing bank that holds the receivable.
    pub depositing_bank_id: String,
    /// The maximum outstanding receivable, in cents.
    pub cap_cents: u64,
}

/// One published exposure cap.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapInfo {
    /// The issuing bank.
    pub issuing_bank_id: String,
    /// The depositing bank.
    pub depositing_bank_id: String,
    /// The cap, in cents.
    pub cap_cents: u64,
}

/// Response of `GET /caps`: the published exposure caps.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct CapsResponse {
    /// The caps, in ascending `(issuing, depositing)` order.
    pub caps: Vec<CapInfo>,
}

/// One netted settlement claim: the depositing bank is owed `net_amount_cents` by the issuing
/// bank for the window (production-spec v1.4 section 10). No money moves automatically.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SettlementClaimInfo {
    /// The bank that owes (issued the net coins).
    pub issuing_bank_id: String,
    /// The bank that is owed (deposited the net coins).
    pub depositing_bank_id: String,
    /// The net amount owed, in cents.
    pub net_amount_cents: u64,
    /// The settlement window end, Unix seconds.
    pub window_end: u64,
}

/// Response of `POST /settle`: the settlement claims produced by netting the accumulated
/// receivables. Empty if there was nothing to net (an idempotent re-run).
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SettleResponse {
    /// The claims written, one per bank pair with a nonzero net.
    pub claims: Vec<SettlementClaimInfo>,
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
