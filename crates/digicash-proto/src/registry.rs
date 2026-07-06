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
