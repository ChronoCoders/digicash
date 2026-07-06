use std::fmt;

/// Header carrying the account id a request's signature is claimed under.
pub const HEADER_ACCOUNT: &str = "x-digicash-account";
/// Header carrying the request timestamp, Unix seconds UTC, as decimal ASCII.
pub const HEADER_TIMESTAMP: &str = "x-digicash-timestamp";
/// Header carrying the request nonce, 16 random bytes as lowercase hex.
pub const HEADER_NONCE: &str = "x-digicash-nonce";
/// Header carrying the Ed25519 request signature, lowercase hex.
pub const HEADER_SIGNATURE: &str = "x-digicash-signature";

/// The per-request authentication metadata a wallet attaches to every call.
///
/// It travels in HTTP headers, not the body, so the request body (and therefore its hash
/// in the canonical payload) stays byte-stable regardless of proxies or reserializers
/// (spec v1.2 section 2). The signed bytes are the canonical payload built in
/// `digicash-core`; these headers only carry the account claim, the anti-replay
/// timestamp/nonce, and the signature over that payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthHeaders {
    /// The account id the signature is claimed under; the bank verifies against the Ed25519
    /// key registered for this account and rejects a mismatch with the request target.
    pub account_id: String,
    /// Request timestamp, Unix seconds UTC.
    pub timestamp: u64,
    /// Request nonce, 16 random bytes as lowercase hex.
    pub nonce: String,
    /// Ed25519 signature over the canonical payload, lowercase hex.
    pub signature: String,
}

impl AuthHeaders {
    /// The four `(name, value)` header pairs to attach to a request, in a fixed order.
    pub fn to_pairs(&self) -> [(&'static str, String); 4] {
        [
            (HEADER_ACCOUNT, self.account_id.clone()),
            (HEADER_TIMESTAMP, self.timestamp.to_string()),
            (HEADER_NONCE, self.nonce.clone()),
            (HEADER_SIGNATURE, self.signature.clone()),
        ]
    }

    /// Parse the metadata from a header lookup (the server side). `lookup` returns a header
    /// value by name, or `None` if absent. A missing or empty header, or a non-numeric
    /// timestamp, is an error - the bank rejects such a request before any handler runs.
    pub fn from_lookup<F>(lookup: F) -> Result<Self, AuthHeaderError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let account_id = require(&lookup, HEADER_ACCOUNT)?;
        let timestamp = require(&lookup, HEADER_TIMESTAMP)?
            .parse::<u64>()
            .map_err(|_| AuthHeaderError::Malformed {
                header: HEADER_TIMESTAMP,
            })?;
        let nonce = require(&lookup, HEADER_NONCE)?;
        let signature = require(&lookup, HEADER_SIGNATURE)?;
        Ok(Self {
            account_id,
            timestamp,
            nonce,
            signature,
        })
    }
}

fn require<F>(lookup: &F, header: &'static str) -> Result<String, AuthHeaderError>
where
    F: Fn(&str) -> Option<String>,
{
    lookup(header)
        .filter(|v| !v.is_empty())
        .ok_or(AuthHeaderError::Missing { header })
}

/// Why parsing the authentication headers failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthHeaderError {
    /// A required header was absent or empty.
    Missing {
        /// The header that was missing.
        header: &'static str,
    },
    /// A header was present but could not be parsed (a non-numeric timestamp).
    Malformed {
        /// The header that was malformed.
        header: &'static str,
    },
}

impl fmt::Display for AuthHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthHeaderError::Missing { header } => {
                write!(f, "missing or empty authentication header: {header}")
            }
            AuthHeaderError::Malformed { header } => {
                write!(f, "malformed authentication header: {header}")
            }
        }
    }
}

impl std::error::Error for AuthHeaderError {}

#[cfg(test)]
mod tests {
    use super::{AuthHeaderError, AuthHeaders, HEADER_SIGNATURE, HEADER_TIMESTAMP};
    use std::collections::HashMap;

    fn sample() -> AuthHeaders {
        AuthHeaders {
            account_id: "alice".to_string(),
            timestamp: 1_700_000_000,
            nonce: "0011223344556677889900aabbccddee".to_string(),
            signature: "ff".repeat(64),
        }
    }

    #[test]
    fn pairs_round_trip_through_a_header_map() {
        let headers = sample();
        let map: HashMap<String, String> = headers
            .to_pairs()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        let parsed =
            AuthHeaders::from_lookup(|name| map.get(name).cloned()).expect("parse back");
        assert_eq!(parsed, headers, "auth headers did not round-trip");
    }

    #[test]
    fn missing_header_is_rejected() {
        let err = AuthHeaders::from_lookup(|_| None).expect_err("must reject empty lookup");
        assert!(matches!(err, AuthHeaderError::Missing { .. }));
    }

    #[test]
    fn empty_header_value_is_treated_as_missing() {
        let map: HashMap<String, String> = sample()
            .to_pairs()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        let err = AuthHeaders::from_lookup(|name| {
            if name == HEADER_SIGNATURE {
                Some(String::new())
            } else {
                map.get(name).cloned()
            }
        })
        .expect_err("empty signature must be rejected");
        assert_eq!(err, AuthHeaderError::Missing {
            header: HEADER_SIGNATURE
        });
    }

    #[test]
    fn non_numeric_timestamp_is_malformed() {
        let map: HashMap<String, String> = sample()
            .to_pairs()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        let err = AuthHeaders::from_lookup(|name| {
            if name == HEADER_TIMESTAMP {
                Some("not-a-number".to_string())
            } else {
                map.get(name).cloned()
            }
        })
        .expect_err("non-numeric timestamp must be rejected");
        assert_eq!(err, AuthHeaderError::Malformed {
            header: HEADER_TIMESTAMP
        });
    }
}
