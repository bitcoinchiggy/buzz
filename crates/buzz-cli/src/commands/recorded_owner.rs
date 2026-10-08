//! `buzz users recorded-owner` — read `users.agent_owner_pubkey`.
//!
//! The command rejects a kind 0 event. A published `auth` tag is not the
//! recorded owner.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::BuzzClient;
use crate::error::CliError;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RecordedOwnerView {
    pub pubkey: String,
    pub agent_owner_pubkey: Option<String>,
    pub channel_add_policy: String,
}

/// Parse a recorded-owner body. Extra fields, event fields, and a mismatched
/// subject are rejected so a kind 0 document cannot pass as the column.
pub fn parse_recorded_owner_body(
    body: &str,
    expected_subject: &str,
) -> Result<RecordedOwnerView, CliError> {
    let value: Value = serde_json::from_str(body)
        .map_err(|_| CliError::Other("recorded owner response is not readable".into()))?;
    let Some(object) = value.as_object() else {
        return Err(CliError::Other(
            "recorded owner response is not readable".into(),
        ));
    };
    if object.contains_key("kind")
        || object.contains_key("tags")
        || object.contains_key("sig")
        || object.contains_key("content")
        || object.contains_key("id")
    {
        return Err(CliError::Other(
            "recorded owner response is not the users column".into(),
        ));
    }
    if object.len() != 3 {
        return Err(CliError::Other(
            "recorded owner response is not readable".into(),
        ));
    }
    let view: RecordedOwnerView = serde_json::from_value(value)
        .map_err(|_| CliError::Other("recorded owner response is not readable".into()))?;
    if view.pubkey != expected_subject
        || !is_hex64(&view.pubkey)
        || !matches!(
            view.channel_add_policy.as_str(),
            "anyone" | "owner_only" | "nobody"
        )
        || view
            .agent_owner_pubkey
            .as_deref()
            .is_some_and(|owner| !is_hex64(owner))
    {
        return Err(CliError::Other(
            "recorded owner response is not readable".into(),
        ));
    }
    Ok(view)
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub async fn cmd_recorded_owner(client: &BuzzClient, pubkey: Option<&str>) -> Result<(), CliError> {
    let subject = match pubkey {
        Some(value) => {
            let hex = value.trim().to_ascii_lowercase();
            if !is_hex64(&hex) {
                return Err(CliError::Usage(
                    "pubkey must be 64 lowercase hex characters".into(),
                ));
            }
            hex
        }
        None => client.signer_public_hex(),
    };
    let path = format!("/v1/users/{subject}/recorded-owner");
    let body = client.get_authed(&path).await?;
    let view = parse_recorded_owner_body(&body, &subject)?;
    println!(
        "{}",
        serde_json::to_string(&view).map_err(|error| {
            CliError::Other(format!("recorded owner response is not readable: {error}"))
        })?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn subject() -> String {
        "ab".repeat(32)
    }

    #[test]
    fn null_owner_is_a_column_value() {
        let body = json!({
            "pubkey": subject(),
            "agent_owner_pubkey": null,
            "channel_add_policy": "owner_only",
        })
        .to_string();
        let view = parse_recorded_owner_body(&body, &subject()).expect("column");
        assert_eq!(view.agent_owner_pubkey, None);
        assert_eq!(view.channel_add_policy, "owner_only");
    }

    #[test]
    fn kind0_auth_tag_is_not_the_recorded_owner() {
        let body = json!({
            "id": "cc".repeat(32),
            "pubkey": subject(),
            "kind": 0,
            "content": "{}",
            "tags": [["auth", "dd".repeat(32), "", "ee".repeat(64)]],
            "sig": "ff".repeat(64),
            "created_at": 1,
        })
        .to_string();
        let error = parse_recorded_owner_body(&body, &subject()).expect_err("event");
        assert!(error.to_string().contains("not the users column"));
    }

    #[test]
    fn mismatched_subject_is_unreadable() {
        let body = json!({
            "pubkey": "11".repeat(32),
            "agent_owner_pubkey": null,
            "channel_add_policy": "anyone",
        })
        .to_string();
        assert!(parse_recorded_owner_body(&body, &subject()).is_err());
    }
}
