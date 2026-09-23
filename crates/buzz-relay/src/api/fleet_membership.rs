//! Fleet relay-membership HTTP API.
//!
//! Host-local bearer-token surface for admitting and removing `role=member`
//! rows. Completely separate from `RELAY_OPERATOR_PUBKEYS`, owner/admin
//! Nostr identities, and NIP-98. Routes are mounted only when
//! `BUZZ_FLEET_MEMBERSHIP_TOKEN` is configured.
//!
//! Membership DB state and the authoritative kind:13534 roster snapshot are
//! separate facts. Mutating handlers return 200 only when the requested
//! membership state is correct *and* the snapshot is confirmed current.
//! A successful DB write followed by a publication or confirmation failure
//! returns 503 with `roster_published=false` — unlike invite/NIP-43 claim,
//! which warns and still returns success.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Json,
};
use nostr::ToBech32;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::FleetMembershipToken;
use crate::handlers::side_effects::publish_nip43_membership_list;
use crate::state::AppState;
use crate::tenant::bind_deployment_community;

use super::{api_error, internal_error};

const FLEET_ADDED_BY: &str = "fleet-admission";
const FLEET_ROLE: &str = "member";
const PRIVATE_MATERIAL_KEYS: &[&str] = &[
    "nsec",
    "nsec_hex",
    "secret",
    "secret_key",
    "private_key",
    "privkey",
    "sk",
];

#[cfg(test)]
static FORCE_ROSTER_PUBLISH_FAILURE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Test-only guard that forces the next roster publication to fail.
///
/// Drop restores the previous behavior so one test cannot leak the hook
/// into another.
#[cfg(test)]
pub(crate) struct ForceRosterPublishFailure;

#[cfg(test)]
impl ForceRosterPublishFailure {
    fn arm() -> Self {
        FORCE_ROSTER_PUBLISH_FAILURE.store(true, std::sync::atomic::Ordering::SeqCst);
        Self
    }
}

#[cfg(test)]
impl Drop for ForceRosterPublishFailure {
    fn drop(&mut self) {
        FORCE_ROSTER_PUBLISH_FAILURE.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// JSON identity presented with every Fleet membership request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayMemberIdentity {
    npub: String,
    public_key_hex: String,
}

#[derive(Debug, Clone)]
struct VerifiedIdentity {
    public_key_hex: String,
    npub: String,
}

/// `PUT /v1/relay-members/{public_key_hex}` — admit `role=member` only.
pub async fn put_member(
    State(state): State<Arc<AppState>>,
    Path(public_key_hex): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let identity = authorize_and_verify(&state, &headers, &public_key_hex, &body)?;
    let tenant = deployment_tenant(&state).await?;

    match state
        .db
        .get_relay_member(tenant.community(), &identity.public_key_hex)
        .await
    {
        Ok(Some(existing)) if existing.role == FLEET_ROLE => {}
        Ok(Some(_)) => {
            return Err(api_error(
                StatusCode::CONFLICT,
                "cannot admit owner or admin through the fleet membership API",
            ));
        }
        Ok(None) => {
            state
                .db
                .add_relay_member(
                    tenant.community(),
                    &identity.public_key_hex,
                    FLEET_ROLE,
                    Some(FLEET_ADDED_BY),
                )
                .await
                .map_err(|e| {
                    tracing::error!("fleet membership insert failed: {e}");
                    internal_error("fleet membership persistence failed")
                })?;
        }
        Err(e) => {
            tracing::error!("fleet membership lookup failed: {e}");
            return Err(internal_error("fleet membership lookup failed"));
        }
    }

    finish_mutation(&state, &tenant, &identity, true, Some(FLEET_ROLE)).await
}

/// `GET /v1/relay-members/{public_key_hex}` — observational membership + roster flags.
pub async fn get_member(
    State(state): State<Arc<AppState>>,
    Path(public_key_hex): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let identity = authorize_and_verify(&state, &headers, &public_key_hex, &body)?;
    let tenant = deployment_tenant(&state).await?;

    let member = state
        .db
        .get_relay_member(tenant.community(), &identity.public_key_hex)
        .await
        .map_err(|e| {
            tracing::error!("fleet membership lookup failed: {e}");
            internal_error("fleet membership lookup failed")
        })?;

    let roster_published = roster_is_current(&state, &tenant).await?;
    let (present, role) = match member {
        Some(row) => (true, Some(row.role)),
        None => (false, None),
    };

    Ok(Json(member_body(
        &identity,
        role.as_deref(),
        present,
        roster_published,
    )))
}

/// `DELETE /v1/relay-members/{public_key_hex}` — remove a non-owner member.
///
/// Missing members are idempotent success. Owner removal is refused by the
/// existing atomic `DELETE … WHERE role <> 'owner'` protection.
pub async fn delete_member(
    State(state): State<Arc<AppState>>,
    Path(public_key_hex): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let identity = authorize_and_verify(&state, &headers, &public_key_hex, &body)?;
    let tenant = deployment_tenant(&state).await?;

    match state
        .db
        .remove_relay_member(tenant.community(), &identity.public_key_hex)
        .await
    {
        Ok(buzz_db::relay_members::RemoveResult::Removed)
        | Ok(buzz_db::relay_members::RemoveResult::NotFound) => {}
        Ok(buzz_db::relay_members::RemoveResult::IsOwner) => {
            return Err(api_error(StatusCode::CONFLICT, "cannot remove relay owner"));
        }
        Ok(buzz_db::relay_members::RemoveResult::RoleMismatch) => {
            return Err(api_error(
                StatusCode::CONFLICT,
                "cannot remove relay member: role mismatch",
            ));
        }
        Err(e) => {
            tracing::error!("fleet membership delete failed: {e}");
            return Err(internal_error("fleet membership persistence failed"));
        }
    }

    finish_mutation(&state, &tenant, &identity, false, None).await
}

async fn finish_mutation(
    state: &Arc<AppState>,
    tenant: &buzz_core::TenantContext,
    identity: &VerifiedIdentity,
    present: bool,
    role: Option<&str>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if roster_is_current(state, tenant).await? {
        return Ok(Json(member_body(identity, role, present, true)));
    }

    if !publish_roster(state, tenant).await {
        return Err(unavailable(identity, present, role));
    }

    if roster_is_current(state, tenant).await? {
        Ok(Json(member_body(identity, role, present, true)))
    } else {
        Err(unavailable(identity, present, role))
    }
}

async fn publish_roster(state: &Arc<AppState>, tenant: &buzz_core::TenantContext) -> bool {
    #[cfg(test)]
    if FORCE_ROSTER_PUBLISH_FAILURE.load(std::sync::atomic::Ordering::SeqCst) {
        tracing::warn!("fleet membership roster publication forced to fail");
        return false;
    }

    match publish_nip43_membership_list(tenant, state).await {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(%error, "fleet membership roster publication failed");
            false
        }
    }
}

async fn roster_is_current(
    state: &AppState,
    tenant: &buzz_core::TenantContext,
) -> Result<bool, (StatusCode, Json<Value>)> {
    let needs = state
        .db
        .nip43_membership_snapshot_needs_reconciliation_for_maintenance(
            tenant.community(),
            &state.relay_keypair.public_key(),
        )
        .await
        .map_err(|e| {
            tracing::error!("fleet membership roster confirmation failed: {e}");
            internal_error("fleet membership roster confirmation failed")
        })?;
    Ok(!needs)
}

async fn deployment_tenant(
    state: &AppState,
) -> Result<buzz_core::TenantContext, (StatusCode, Json<Value>)> {
    bind_deployment_community(&state.db, &state.config.relay_url)
        .await
        .map_err(|_| {
            tracing::error!("fleet membership tenant bind failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "deployment community is unavailable" })),
            )
        })
}

fn authorize_and_verify(
    state: &AppState,
    headers: &HeaderMap,
    path_hex: &str,
    body: &Bytes,
) -> Result<VerifiedIdentity, (StatusCode, Json<Value>)> {
    let token = state
        .config
        .fleet_membership_token
        .as_ref()
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "not found"))?;
    authorize_fleet(headers, token)?;
    parse_identity(path_hex, body)
}

/// Validate the bearer credential.
///
/// The presented and configured values are hashed with SHA-256 and compared
/// with [`ConstantTimeEq`]. Neither the token nor any hash of it is logged
/// or returned.
fn authorize_fleet(
    headers: &HeaderMap,
    configured: &FleetMembershipToken,
) -> Result<(), (StatusCode, Json<Value>)> {
    let presented = unique_authorization(headers).ok_or_else(unauthorized)?;
    let Some(presented) = presented.strip_prefix("Bearer ") else {
        return Err(unauthorized());
    };
    if presented.is_empty() {
        return Err(unauthorized());
    }

    let expected = Sha256::digest(configured.as_str().as_bytes());
    let provided = Sha256::digest(presented.as_bytes());
    if expected.ct_eq(provided.as_slice()).into() {
        Ok(())
    } else {
        Err(unauthorized())
    }
}

fn unique_authorization(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(axum::http::header::AUTHORIZATION).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return None;
    };
    value.to_str().ok()
}

fn parse_identity(
    path_hex: &str,
    body: &Bytes,
) -> Result<VerifiedIdentity, (StatusCode, Json<Value>)> {
    let value: Value = serde_json::from_slice(body).map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "malformed identity: request body must be JSON",
        )
    })?;
    reject_private_material(&value)?;

    let identity: RelayMemberIdentity = serde_json::from_value(value).map_err(|e| {
        if e.to_string().contains("unknown field") {
            api_error(StatusCode::BAD_REQUEST, "malformed identity: unknown field")
        } else {
            api_error(StatusCode::BAD_REQUEST, "malformed identity")
        }
    })?;

    if looks_like_private_material(path_hex)
        || looks_like_private_material(&identity.npub)
        || looks_like_private_material(&identity.public_key_hex)
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "malformed identity: private material is not accepted",
        ));
    }

    if !is_lowercase_pubkey_hex(path_hex) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "malformed identity: public_key_hex path must be 64 lowercase hex characters",
        ));
    }
    if identity.public_key_hex != path_hex {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "malformed identity: public_key_hex does not match path",
        ));
    }
    if !identity.npub.starts_with("npub1") {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "malformed identity: npub is required",
        ));
    }

    let from_hex = nostr::PublicKey::from_hex(path_hex).map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "malformed identity: public_key_hex is not a valid pubkey",
        )
    })?;
    let from_npub = nostr::PublicKey::parse(&identity.npub).map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "malformed identity: npub is not a valid pubkey",
        )
    })?;
    if from_hex != from_npub {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "npub and public_key_hex do not match",
        ));
    }

    let canonical_npub = from_hex.to_bech32().map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "malformed identity: failed to encode npub",
        )
    })?;

    Ok(VerifiedIdentity {
        public_key_hex: from_hex.to_hex(),
        npub: canonical_npub,
    })
}

fn reject_private_material(value: &Value) -> Result<(), (StatusCode, Json<Value>)> {
    let Some(object) = value.as_object() else {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "malformed identity: request body must be a JSON object",
        ));
    };
    if object
        .keys()
        .any(|key| PRIVATE_MATERIAL_KEYS.contains(&key.as_str()))
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "malformed identity: private material is not accepted",
        ));
    }
    Ok(())
}

fn looks_like_private_material(value: &str) -> bool {
    value.starts_with("nsec1") || value.starts_with("nsec")
}

fn is_lowercase_pubkey_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn member_body(
    identity: &VerifiedIdentity,
    role: Option<&str>,
    present: bool,
    roster_published: bool,
) -> Value {
    json!({
        "public_key_hex": identity.public_key_hex,
        "npub": identity.npub,
        "role": role,
        "present": present,
        "roster_published": roster_published,
    })
}

fn unavailable(
    identity: &VerifiedIdentity,
    present: bool,
    role: Option<&str>,
) -> (StatusCode, Json<Value>) {
    let mut body = member_body(identity, role, present, false);
    body["error"] = json!("roster publication failed");
    (StatusCode::SERVICE_UNAVAILABLE, Json(body))
}

fn unauthorized() -> (StatusCode, Json<Value>) {
    api_error(StatusCode::UNAUTHORIZED, "unauthorized")
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{Keys, ToBech32};
    use serde_json::json;

    fn identity_for(keys: &Keys) -> (String, Value) {
        let hex = keys.public_key().to_hex();
        let npub = keys.public_key().to_bech32().expect("npub");
        (
            hex.clone(),
            json!({
                "npub": npub,
                "public_key_hex": hex,
            }),
        )
    }

    #[test]
    fn identity_accepts_matching_npub_and_hex() {
        let keys = Keys::generate();
        let (hex, body) = identity_for(&keys);
        let verified =
            parse_identity(&hex, &Bytes::from(body.to_string())).expect("valid identity");
        assert_eq!(verified.public_key_hex, hex);
        assert_eq!(verified.npub, keys.public_key().to_bech32().expect("npub"));
    }

    #[test]
    fn identity_rejects_invalid_hex() {
        let keys = Keys::generate();
        let npub = keys.public_key().to_bech32().expect("npub");
        let body = json!({
            "npub": npub,
            "public_key_hex": "not-a-hex-key",
        });
        let err = parse_identity("not-a-hex-key", &Bytes::from(body.to_string())).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err
            .1
            .get("error")
            .and_then(Value::as_str)
            .unwrap()
            .contains("malformed identity"));
    }

    #[test]
    fn identity_rejects_uppercase_hex() {
        let keys = Keys::generate();
        let hex = keys.public_key().to_hex();
        let upper = hex.to_ascii_uppercase();
        let body = json!({
            "npub": keys.public_key().to_bech32().expect("npub"),
            "public_key_hex": upper,
        });
        let err = parse_identity(&upper, &Bytes::from(body.to_string())).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn identity_rejects_npub_hex_mismatch() {
        let left = Keys::generate();
        let right = Keys::generate();
        let hex = left.public_key().to_hex();
        let body = json!({
            "npub": right.public_key().to_bech32().expect("npub"),
            "public_key_hex": hex,
        });
        let err = parse_identity(&hex, &Bytes::from(body.to_string())).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            err.1.get("error").and_then(Value::as_str),
            Some("npub and public_key_hex do not match")
        );
    }

    #[test]
    fn identity_rejects_unknown_and_private_fields() {
        let keys = Keys::generate();
        let (hex, mut body) = identity_for(&keys);
        body["role"] = json!("owner");
        let unknown = parse_identity(&hex, &Bytes::from(body.to_string())).unwrap_err();
        assert_eq!(unknown.0, StatusCode::BAD_REQUEST);
        assert!(unknown
            .1
            .get("error")
            .and_then(Value::as_str)
            .unwrap()
            .contains("unknown field"));

        let private = json!({
            "npub": keys.public_key().to_bech32().expect("npub"),
            "public_key_hex": hex,
            "nsec": keys.secret_key().to_bech32().expect("nsec"),
        });
        let err = parse_identity(&hex, &Bytes::from(private.to_string())).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err
            .1
            .get("error")
            .and_then(Value::as_str)
            .unwrap()
            .contains("private material"));
        assert!(
            !err.1.to_string().contains("nsec1"),
            "error must not echo private material"
        );
    }

    #[test]
    fn bearer_compare_is_constant_time_and_does_not_log() {
        let token = FleetMembershipToken::parse_env(Some("fleet-membership-test-token-32b!"))
            .expect("parse")
            .expect("present");

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer fleet-membership-test-token-32b!"
                .parse()
                .expect("header"),
        );
        authorize_fleet(&headers, &token).expect("matching bearer");

        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer totally-different-token-value-32b!"
                .parse()
                .expect("header"),
        );
        assert_eq!(
            authorize_fleet(&headers, &token).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );

        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Basic fleet-membership-test-token-32b!"
                .parse()
                .expect("header"),
        );
        assert_eq!(
            authorize_fleet(&headers, &token).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
    }
}

#[cfg(test)]
mod http_tests {
    use std::sync::Arc;

    use axum::{
        body::{to_bytes, Body},
        http::{header, Request, StatusCode},
    };
    use nostr::{Keys, ToBech32};
    use serde_json::{json, Value};
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::{ForceRosterPublishFailure, FLEET_ADDED_BY};
    use crate::config::FleetMembershipToken;
    use crate::router::build_router;
    use crate::state::AppState;

    const TEST_TOKEN: &str = "fleet-membership-test-token-32b!";
    const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz";

    fn parsed_token() -> FleetMembershipToken {
        FleetMembershipToken::parse_env(Some(TEST_TOKEN))
            .expect("valid test token")
            .expect("token present")
    }

    async fn router_state(token: Option<FleetMembershipToken>) -> Arc<AppState> {
        let mut config = crate::config::Config::from_env().expect("default config");
        config.redis_url = "redis://127.0.0.1:1".to_string();
        config.fleet_membership_token = token;
        config.require_relay_membership = true;
        let pool = sqlx::PgPool::connect_lazy(&config.database_url).expect("lazy pg pool");
        let db = buzz_db::Db::from_pool(pool.clone());
        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .expect("pubsub"),
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage = buzz_media::MediaStorage::new(&config.media).expect("media");
        let (state, _audit_shutdown) = AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth,
            search,
            workflow_engine,
            Keys::generate(),
            media_storage,
        );
        Arc::new(state)
    }

    async fn postgres_state(host: &str) -> Option<Arc<AppState>> {
        let mut config = crate::config::Config::from_env().ok()?;
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| TEST_DB_URL.to_string());
        config.database_url = database_url.clone();
        config.redis_url = "redis://127.0.0.1:1".to_string();
        config.relay_url = format!("wss://{host}");
        config.require_relay_membership = true;
        config.fleet_membership_token = Some(parsed_token());

        let pool = sqlx::PgPool::connect(&database_url).await.ok()?;
        let db = buzz_db::Db::from_pool(pool.clone());
        db.migrate().await.ok()?;
        db.ensure_configured_community(host).await.ok()?;

        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .ok()?;
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .ok()?,
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage = buzz_media::MediaStorage::new(&config.media).ok()?;
        let (state, _audit_shutdown) = AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth,
            search,
            workflow_engine,
            Keys::generate(),
            media_storage,
        );
        Some(Arc::new(state))
    }

    fn member_body(keys: &Keys) -> (String, String) {
        let hex = keys.public_key().to_hex();
        let npub = keys.public_key().to_bech32().expect("npub");
        (
            hex.clone(),
            json!({ "npub": npub, "public_key_hex": hex }).to_string(),
        )
    }

    async fn call(
        state: Arc<AppState>,
        method: &str,
        hex: &str,
        token: Option<&str>,
        body: String,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("/v1/relay-members/{hex}"))
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = build_router(state)
            .oneshot(builder.body(Body::from(body)).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body");
        let json = if bytes.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }))
        };
        (status, json)
    }

    async fn bootstrap_owner(state: &AppState, host: &str, owner: &Keys) {
        let community = state
            .db
            .lookup_community_by_host(host)
            .await
            .expect("lookup")
            .expect("community")
            .id;
        state
            .db
            .bootstrap_owner(community, &owner.public_key().to_hex())
            .await
            .expect("bootstrap owner");
    }

    #[tokio::test]
    async fn routes_are_absent_when_token_unset() {
        let state = router_state(None).await;
        let keys = Keys::generate();
        let (hex, body) = member_body(&keys);
        let (status, json) = call(state.clone(), "PUT", &hex, Some(TEST_TOKEN), body).await;
        let unknown = build_router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/definitely-not-a-route")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response")
            .status();
        assert_eq!(
            status, unknown,
            "unset token must leave fleet routes absent, matching any unknown path ({json})"
        );
        assert!(
            json.get("roster_published").is_none(),
            "unmounted fleet routes must not emit the membership envelope: {json}"
        );
        assert_ne!(
            json.get("error").and_then(Value::as_str),
            Some("unauthorized"),
            "unmounted fleet routes must not run bearer auth: {json}"
        );
    }

    #[tokio::test]
    async fn unauthorized_requests_are_rejected() {
        let state = router_state(Some(parsed_token())).await;
        let keys = Keys::generate();
        let (hex, body) = member_body(&keys);

        let (missing, json) = call(state.clone(), "PUT", &hex, None, body.clone()).await;
        assert_eq!(missing, StatusCode::UNAUTHORIZED);
        assert_eq!(json["error"], "unauthorized");

        let (wrong, _) = call(
            state.clone(),
            "GET",
            &hex,
            Some("wrong-token-value-that-is-long-enough!!"),
            body.clone(),
        )
        .await;
        assert_eq!(wrong, StatusCode::UNAUTHORIZED);

        let (empty_bearer, _) = call(state, "DELETE", &hex, Some(""), body).await;
        assert_eq!(empty_bearer, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_hex_and_mismatch_are_rejected_before_persistence() {
        let state = router_state(Some(parsed_token())).await;
        let keys = Keys::generate();
        let other = Keys::generate();
        let hex = keys.public_key().to_hex();
        let mismatch = json!({
            "npub": other.public_key().to_bech32().expect("npub"),
            "public_key_hex": hex,
        })
        .to_string();
        let (status, json) = call(state.clone(), "PUT", &hex, Some(TEST_TOKEN), mismatch).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"], "npub and public_key_hex do not match");

        let (bad_hex, json) = call(
            state,
            "PUT",
            "zzzz",
            Some(TEST_TOKEN),
            json!({
                "npub": keys.public_key().to_bech32().expect("npub"),
                "public_key_hex": "zzzz",
            })
            .to_string(),
        )
        .await;
        assert_eq!(bad_hex, StatusCode::BAD_REQUEST);
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("malformed identity"));
    }

    #[tokio::test]
    async fn unknown_and_private_fields_are_rejected() {
        let state = router_state(Some(parsed_token())).await;
        let keys = Keys::generate();
        let hex = keys.public_key().to_hex();
        let npub = keys.public_key().to_bech32().expect("npub");

        let (unknown, json) = call(
            state.clone(),
            "PUT",
            &hex,
            Some(TEST_TOKEN),
            json!({
                "npub": npub,
                "public_key_hex": hex,
                "role": "admin",
            })
            .to_string(),
        )
        .await;
        assert_eq!(unknown, StatusCode::BAD_REQUEST);
        assert!(json["error"].as_str().unwrap().contains("unknown field"));

        let nsec = keys.secret_key().to_bech32().expect("nsec");
        let (private, json) = call(
            state,
            "PUT",
            &hex,
            Some(TEST_TOKEN),
            json!({
                "npub": npub,
                "public_key_hex": hex,
                "nsec": nsec,
            })
            .to_string(),
        )
        .await;
        assert_eq!(private, StatusCode::BAD_REQUEST);
        assert!(json["error"].as_str().unwrap().contains("private material"));
        assert!(
            !json.to_string().contains(&nsec),
            "response must not echo private material"
        );
    }

    #[tokio::test]
    async fn config_and_logs_never_expose_the_token_or_hash() {
        use std::sync::{Arc, Mutex};

        use sha2::Digest;

        let token = parsed_token();
        let mut config = crate::config::Config::from_env().expect("default config");
        config.fleet_membership_token = Some(token.clone());
        let config_debug = format!("{config:?}");
        assert!(config_debug.contains("[REDACTED]"));
        assert!(!config_debug.contains(TEST_TOKEN));
        assert_eq!(format!("{token:?}"), "[REDACTED]");

        #[derive(Clone)]
        struct CapturingMakeWriter {
            buf: Arc<Mutex<Vec<u8>>>,
        }
        struct CapturingWriter {
            buf: Arc<Mutex<Vec<u8>>>,
        }
        impl std::io::Write for CapturingWriter {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.buf.lock().unwrap().extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturingMakeWriter {
            type Writer = CapturingWriter;
            fn make_writer(&'a self) -> Self::Writer {
                CapturingWriter {
                    buf: Arc::clone(&self.buf),
                }
            }
        }

        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(CapturingMakeWriter {
                buf: Arc::clone(&buf),
            })
            .with_ansi(false)
            .finish();
        let presented = "wrong-token-value-that-is-long-enough!!";
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {presented}").parse().expect("header"),
        );
        tracing::subscriber::with_default(subscriber, || {
            let denied = super::authorize_fleet(&headers, &token);
            assert_eq!(denied.unwrap_err().0, StatusCode::UNAUTHORIZED);
            tracing::info!("fleet membership authorization denied");
        });
        let logs = String::from_utf8(buf.lock().unwrap().clone()).unwrap_or_default();
        assert!(
            !logs.contains(TEST_TOKEN),
            "configured token must never appear in logs"
        );
        assert!(
            !logs.contains(presented),
            "presented token must never appear in logs"
        );
        let expected_hash = sha2::Sha256::digest(TEST_TOKEN.as_bytes());
        let hash_hex = hex::encode(expected_hash);
        assert!(
            !logs.contains(&hash_hex),
            "token hash must never appear in logs"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn add_new_member_publishes_roster() {
        let host = format!("fleet-add-{}.example", Uuid::new_v4().simple());
        let state = postgres_state(&host)
            .await
            .expect("requires reachable Postgres");
        let owner = Keys::generate();
        bootstrap_owner(&state, &host, &owner).await;
        let member = Keys::generate();
        let (hex, body) = member_body(&member);

        let (status, json) = call(state.clone(), "PUT", &hex, Some(TEST_TOKEN), body).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["present"], true);
        assert_eq!(json["role"], "member");
        assert_eq!(json["roster_published"], true);
        assert_eq!(json["public_key_hex"], hex);

        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community")
            .id;
        let row = state
            .db
            .get_relay_member(community, &hex)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(row.role, "member");
        assert_eq!(row.added_by.as_deref(), Some(FLEET_ADDED_BY));
        assert!(!state
            .db
            .nip43_membership_snapshot_needs_reconciliation_for_maintenance(
                community,
                &state.relay_keypair.public_key(),
            )
            .await
            .expect("snapshot"));
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn add_existing_member_is_idempotent() {
        let host = format!("fleet-existing-{}.example", Uuid::new_v4().simple());
        let state = postgres_state(&host)
            .await
            .expect("requires reachable Postgres");
        let owner = Keys::generate();
        bootstrap_owner(&state, &host, &owner).await;
        let member = Keys::generate();
        let (hex, body) = member_body(&member);

        let (first, _) = call(state.clone(), "PUT", &hex, Some(TEST_TOKEN), body.clone()).await;
        assert_eq!(first, StatusCode::OK);
        let (second, json) = call(state.clone(), "PUT", &hex, Some(TEST_TOKEN), body).await;
        assert_eq!(second, StatusCode::OK);
        assert_eq!(json["present"], true);
        assert_eq!(json["roster_published"], true);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn remove_member_and_remove_already_absent() {
        let host = format!("fleet-del-{}.example", Uuid::new_v4().simple());
        let state = postgres_state(&host)
            .await
            .expect("requires reachable Postgres");
        let owner = Keys::generate();
        bootstrap_owner(&state, &host, &owner).await;
        let member = Keys::generate();
        let (hex, body) = member_body(&member);

        let (put, _) = call(state.clone(), "PUT", &hex, Some(TEST_TOKEN), body.clone()).await;
        assert_eq!(put, StatusCode::OK);
        let (deleted, json) = call(
            state.clone(),
            "DELETE",
            &hex,
            Some(TEST_TOKEN),
            body.clone(),
        )
        .await;
        assert_eq!(deleted, StatusCode::OK, "{json}");
        assert_eq!(json["present"], false);
        assert_eq!(json["roster_published"], true);

        let (absent, json) = call(
            state.clone(),
            "DELETE",
            &hex,
            Some(TEST_TOKEN),
            body.clone(),
        )
        .await;
        assert_eq!(absent, StatusCode::OK);
        assert_eq!(json["present"], false);
        assert_eq!(json["roster_published"], true);

        let (get, json) = call(state, "GET", &hex, Some(TEST_TOKEN), body).await;
        assert_eq!(get, StatusCode::OK);
        assert_eq!(json["present"], false);
        assert_eq!(json["roster_published"], true);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn owner_and_admin_are_refused() {
        let host = format!("fleet-owner-{}.example", Uuid::new_v4().simple());
        let state = postgres_state(&host)
            .await
            .expect("requires reachable Postgres");
        let owner = Keys::generate();
        bootstrap_owner(&state, &host, &owner).await;
        let (owner_hex, owner_body) = member_body(&owner);

        let (put_owner, json) = call(
            state.clone(),
            "PUT",
            &owner_hex,
            Some(TEST_TOKEN),
            owner_body.clone(),
        )
        .await;
        assert_eq!(put_owner, StatusCode::CONFLICT, "{json}");
        let (del_owner, json) = call(
            state.clone(),
            "DELETE",
            &owner_hex,
            Some(TEST_TOKEN),
            owner_body,
        )
        .await;
        assert_eq!(del_owner, StatusCode::CONFLICT, "{json}");
        assert_eq!(json["error"], "cannot remove relay owner");

        let admin = Keys::generate();
        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community")
            .id;
        state
            .db
            .add_relay_member(community, &admin.public_key().to_hex(), "admin", None)
            .await
            .expect("add admin");
        let (admin_hex, admin_body) = member_body(&admin);
        let (put_admin, json) = call(state, "PUT", &admin_hex, Some(TEST_TOKEN), admin_body).await;
        assert_eq!(put_admin, StatusCode::CONFLICT, "{json}");
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("cannot admit owner or admin"));
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn publication_failure_after_db_mutation_returns_503() {
        let host = format!("fleet-pubfail-{}.example", Uuid::new_v4().simple());
        let state = postgres_state(&host)
            .await
            .expect("requires reachable Postgres");
        let owner = Keys::generate();
        bootstrap_owner(&state, &host, &owner).await;
        let member = Keys::generate();
        let (hex, body) = member_body(&member);
        let _guard = ForceRosterPublishFailure::arm();

        let (status, json) = call(state.clone(), "PUT", &hex, Some(TEST_TOKEN), body).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{json}");
        assert_eq!(json["roster_published"], false);
        assert_eq!(json["present"], true);
        assert_eq!(json["role"], "member");

        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community")
            .id;
        assert!(
            state
                .db
                .is_relay_member(community, &hex)
                .await
                .expect("member row persisted"),
            "DB mutation must succeed even when roster publication fails"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn concurrent_membership_mutations_leave_roster_correct() {
        let host = format!("fleet-conc-{}.example", Uuid::new_v4().simple());
        let state = postgres_state(&host)
            .await
            .expect("requires reachable Postgres");
        let owner = Keys::generate();
        bootstrap_owner(&state, &host, &owner).await;

        let members: Vec<Keys> = (0..8).map(|_| Keys::generate()).collect();
        let mut tasks = Vec::new();
        for keys in &members {
            let (hex, body) = member_body(keys);
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                call(state, "PUT", &hex, Some(TEST_TOKEN), body).await
            }));
        }
        let mut statuses = Vec::new();
        for task in tasks {
            statuses.push(task.await.expect("join"));
        }

        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup")
            .expect("community")
            .id;
        let listed = state
            .db
            .list_relay_members(community)
            .await
            .expect("list members");
        for keys in &members {
            let hex = keys.public_key().to_hex();
            assert!(
                listed
                    .iter()
                    .any(|row| row.pubkey == hex && row.role == "member"),
                "missing member {hex}"
            );
        }

        let stale = state
            .db
            .nip43_membership_snapshot_needs_reconciliation_for_maintenance(
                community,
                &state.relay_keypair.public_key(),
            )
            .await
            .expect("snapshot compare");
        assert!(
            !stale,
            "authoritative kind:13534 snapshot must match membership after concurrent mutations; statuses={statuses:?}"
        );
    }
}
