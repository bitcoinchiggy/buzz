//! Read `users.agent_owner_pubkey` for one public key.
//!
//! Kind 0 profile JSON is not this column. A published `auth` tag is not
//! proof of the recorded owner. The response is built only from
//! `get_agent_channel_policy`.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde_json::json;

#[cfg(test)]
use serde_json::Value;

use buzz_auth::NipFiMode;

use crate::nip_fi_http::admit_nip_fi_http_on_state;
use crate::state::AppState;

use super::relay_members::{attested_owner, extract_auth_tag_header, extract_nip_oa_owner};
use super::{api_error, db_read_error};

const POLICIES: &[&str] = &["anyone", "owner_only", "nobody"];

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RecordedOwnerRead {
    Visible {
        pubkey: String,
        agent_owner_pubkey: Option<String>,
        channel_add_policy: String,
    },
    /// Caller is neither the subject nor the recorded owner. The owner
    /// pubkey is not part of this variant.
    Hidden,
    Unreadable,
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Decide whether `caller_hex` may see the subject's recorded owner.
///
/// `owner` is the column value. `None` is SQL NULL, not a missing row and
/// not a kind 0 tag. A caller who is the subject may see a null owner.
pub(crate) fn decide_recorded_owner_read(
    caller_hex: &str,
    subject_hex: &str,
    policy: &str,
    owner: Option<&[u8]>,
) -> RecordedOwnerRead {
    if !is_hex64(caller_hex) || !is_hex64(subject_hex) || !POLICIES.contains(&policy) {
        return RecordedOwnerRead::Unreadable;
    }
    let owner_hex = match owner {
        None => None,
        Some(bytes) if bytes.len() == 32 => Some(hex::encode(bytes)),
        Some(_) => return RecordedOwnerRead::Unreadable,
    };
    let allowed = caller_hex == subject_hex || owner_hex.as_deref() == Some(caller_hex);
    if !allowed {
        return RecordedOwnerRead::Hidden;
    }
    RecordedOwnerRead::Visible {
        pubkey: subject_hex.to_owned(),
        agent_owner_pubkey: owner_hex,
        channel_add_policy: policy.to_owned(),
    }
}

#[cfg(test)]
fn visible_json(view: &RecordedOwnerRead) -> Option<Value> {
    let RecordedOwnerRead::Visible {
        pubkey,
        agent_owner_pubkey,
        channel_add_policy,
    } = view
    else {
        return None;
    };
    Some(json!({
        "pubkey": pubkey,
        "agent_owner_pubkey": agent_owner_pubkey,
        "channel_add_policy": channel_add_policy,
    }))
}

/// `GET /v1/users/{pubkey}/recorded-owner`
///
/// NIP-98 authenticates the caller. When that request also carries one
/// verified `x-auth-tag`, the owner is materialized before the column is
/// read. The body is the column afterward, including a null owner.
pub async fn get_recorded_owner(
    State(state): State<Arc<AppState>>,
    Path(subject_hex): Path<String>,
    headers: HeaderMap,
) -> Response {
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let tenant = match crate::tenant::bind_community(&state.db, raw_host).await {
        Ok(tenant) => tenant,
        Err(_) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "relay: no community is configured for this host",
            )
            .into_response();
        }
    };
    let path = format!("/v1/users/{subject_hex}/recorded-owner");
    let url = super::bridge::nip98_expected_url(&state.config.relay_url, &tenant, &path);
    let nip_fi_active = !matches!(state.config.nip_fi.mode, NipFiMode::Off);
    let require_auth = state.config.require_auth_token || nip_fi_active;
    let admission = match admit_nip_fi_http_on_state(
        &state,
        &headers,
        super::bridge::make_nip98_closure_for_admission(
            headers.clone(),
            "GET",
            url,
            None,
            require_auth,
            false,
        ),
    ) {
        Ok(admission) => admission,
        Err(response) => return response,
    };
    let caller = *admission.proven_pubkey();
    let (event_id_bytes, signed_created_at) = admission.into_extra();
    if let Err(error) = super::bridge::check_nip98_replay(&state, &tenant, event_id_bytes).await {
        return error.into_response();
    }
    if !is_hex64(&subject_hex) || !subject_hex.bytes().all(|byte| !byte.is_ascii_uppercase()) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "pubkey must be 64 lowercase hex characters",
        )
        .into_response();
    }
    let subject = match nostr::PublicKey::from_hex(&subject_hex) {
        Ok(subject) => subject,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "pubkey must be 64 lowercase hex characters",
            )
            .into_response();
        }
    };
    let auth_tag = extract_auth_tag_header(&headers);
    let membership_owner = match super::relay_members::enforce_relay_membership(
        &state,
        tenant.community(),
        caller.as_bytes(),
        auth_tag,
        signed_created_at,
    )
    .await
    {
        Ok(owner) => owner,
        Err(error) => return error.into_response(),
    };
    let presented = extract_nip_oa_owner(caller.as_bytes(), auth_tag, signed_created_at);
    if let Some(owner) = attested_owner(membership_owner, presented) {
        super::relay_members::materialize_nip_oa_owner(&state, &tenant, &caller, &owner).await;
    }
    let row = match state
        .db
        .get_agent_channel_policy(tenant.community(), subject.as_bytes())
        .await
    {
        Ok(row) => row,
        Err(error) => return db_read_error("recorded owner", &error).into_response(),
    };
    let Some((policy, owner)) = row else {
        return api_error(StatusCode::NOT_FOUND, "recorded owner is not available").into_response();
    };
    match decide_recorded_owner_read(&caller.to_hex(), &subject_hex, &policy, owner.as_deref()) {
        RecordedOwnerRead::Visible {
            pubkey,
            agent_owner_pubkey,
            channel_add_policy,
        } => Json(json!({
            "pubkey": pubkey,
            "agent_owner_pubkey": agent_owner_pubkey,
            "channel_add_policy": channel_add_policy,
        }))
        .into_response(),
        RecordedOwnerRead::Hidden => {
            api_error(StatusCode::FORBIDDEN, "recorded owner is not readable").into_response()
        }
        RecordedOwnerRead::Unreadable => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "recorded owner is not readable",
        )
        .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner_bytes() -> Vec<u8> {
        vec![0x11; 32]
    }

    #[test]
    fn subject_can_read_a_null_owner() {
        let subject = "ab".repeat(32);
        let view = decide_recorded_owner_read(&subject, &subject, "owner_only", None);
        match view {
            RecordedOwnerRead::Visible {
                agent_owner_pubkey,
                channel_add_policy,
                ..
            } => {
                assert_eq!(agent_owner_pubkey, None);
                assert_eq!(channel_add_policy, "owner_only");
            }
            other => panic!("expected the column, got {other:?}"),
        }
    }

    #[test]
    fn recorded_owner_can_read_the_column() {
        let subject = "aa".repeat(32);
        let owner = hex::encode(owner_bytes());
        let view =
            decide_recorded_owner_read(&owner, &subject, "anyone", Some(owner_bytes().as_slice()));
        assert_eq!(
            view,
            RecordedOwnerRead::Visible {
                pubkey: subject,
                agent_owner_pubkey: Some(owner),
                channel_add_policy: "anyone".to_owned(),
            }
        );
    }

    #[test]
    fn stranger_does_not_receive_the_owner() {
        let subject = "aa".repeat(32);
        let owner = hex::encode(owner_bytes());
        let stranger = "bb".repeat(32);
        assert_ne!(stranger, owner);
        let view = decide_recorded_owner_read(
            &stranger,
            &subject,
            "owner_only",
            Some(owner_bytes().as_slice()),
        );
        assert_eq!(view, RecordedOwnerRead::Hidden);
        let rendered = format!("{view:?}");
        assert!(!rendered.contains(&owner));
    }

    #[test]
    fn a_short_owner_column_is_unreadable_rather_than_null() {
        let subject = "aa".repeat(32);
        let view = decide_recorded_owner_read(&subject, &subject, "nobody", Some(&[1, 2, 3]));
        assert_eq!(view, RecordedOwnerRead::Unreadable);
    }

    #[test]
    fn visible_json_has_no_event_fields() {
        let subject = "cd".repeat(32);
        let view = decide_recorded_owner_read(&subject, &subject, "anyone", None);
        let body = visible_json(&view).expect("visible");
        assert!(body.get("kind").is_none());
        assert!(body.get("tags").is_none());
        assert!(body.get("sig").is_none());
        assert!(body.get("content").is_none());
        assert!(body.get("agent_owner_pubkey").unwrap().is_null());
    }
}
