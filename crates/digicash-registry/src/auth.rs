use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use digicash_core::{canonical_payload, IDENTITY_SIGNATURE_LEN};
use digicash_proto::{AuthHeaderError, AuthHeaders, ErrorResponse};

use crate::error::RegistryError;
use crate::registry::Registry;

const MAX_BODY_BYTES: usize = 1 << 20;
const MAX_TIMESTAMP_SKEW_SECS: u64 = 60;
const NONCE_TTL_SECS: u64 = 120;

/// The member bank whose registered Ed25519 key verified a request (production-spec v1.4
/// section 10, reusing the section 2 model). Handlers read it for the admin check.
#[derive(Debug, Clone)]
pub(crate) struct AuthenticatedBank(pub String);

/// Registry middleware enforcing the section 2 request-signing model: parse the auth headers,
/// look up the claiming bank's registered Ed25519 key, reject a stale timestamp, verify the
/// signature over the canonical payload, and reject a replayed nonce - before any handler.
pub(crate) async fn verify_signed_request(
    State(registry): State<Arc<Registry>>,
    request: Request,
    next: Next,
) -> Response {
    match authenticate(&registry, request).await {
        Ok(request) => next.run(request).await,
        Err(rejection) => rejection.into_response(),
    }
}

async fn authenticate(registry: &Registry, request: Request) -> Result<Request, AuthRejection> {
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| AuthRejection::bad_request("request body too large or unreadable"))?;

    let auth = AuthHeaders::from_lookup(|name| {
        parts
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    })
    .map_err(AuthRejection::headers)?;

    let pubkey = registry
        .member_pubkey(&auth.account_id)
        .await
        .map_err(AuthRejection::internal)?
        .ok_or_else(|| AuthRejection::unauthorized("bank is not a registered member"))?;

    let now = now_unix();
    if auth.timestamp.saturating_add(MAX_TIMESTAMP_SKEW_SECS) < now
        || auth.timestamp > now.saturating_add(MAX_TIMESTAMP_SKEW_SECS)
    {
        return Err(AuthRejection::unauthorized(
            "request timestamp outside the accepted window",
        ));
    }

    let signature = decode_signature(&auth.signature)?;
    let payload = canonical_payload(
        parts.method.as_str(),
        parts.uri.path(),
        &bytes,
        auth.timestamp,
        &auth.nonce,
    );
    pubkey
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| AuthRejection::unauthorized("signature verification failed"))?;

    let fresh = registry
        .check_and_record_nonce(&auth.nonce, now, NONCE_TTL_SECS)
        .await
        .map_err(AuthRejection::internal)?;
    if !fresh {
        return Err(AuthRejection::unauthorized("nonce already used (replay)"));
    }

    let mut request = Request::from_parts(parts, Body::from(bytes));
    request
        .extensions_mut()
        .insert(AuthenticatedBank(auth.account_id));
    Ok(request)
}

fn decode_signature(hex_signature: &str) -> Result<[u8; IDENTITY_SIGNATURE_LEN], AuthRejection> {
    let bytes = hex::decode(hex_signature)
        .map_err(|_| AuthRejection::unauthorized("signature is not valid hex"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthRejection::unauthorized("signature is not 64 bytes"))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct AuthRejection {
    status: StatusCode,
    message: String,
}

impl AuthRejection {
    fn unauthorized(message: &str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.to_string(),
        }
    }

    fn bad_request(message: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.to_string(),
        }
    }

    fn headers(error: AuthHeaderError) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: error.to_string(),
        }
    }

    fn internal(error: RegistryError) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}
