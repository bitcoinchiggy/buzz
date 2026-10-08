//! `buzz auth-tag compute` — local NIP-OA attestation.
//!
//! The signing key never leaves this process. The command does not open a
//! relay connection and does not print the private key.

use nostr::{Keys, PublicKey};

use crate::error::CliError;

/// Print one JSON auth tag for `agent_hex`, signed by `owner`.
///
/// Conditions are empty so the tag can be presented on the agent's first
/// authenticated request. Self-attestation is rejected by `compute_auth_tag`.
pub fn cmd_compute(owner: &Keys, agent_hex: &str) -> Result<(), CliError> {
    let agent = PublicKey::from_hex(agent_hex.trim())
        .map_err(|_| CliError::Usage("agent pubkey must be 64 hex characters".into()))?;
    let tag = buzz_sdk::nip_oa::compute_auth_tag(owner, &agent, "")
        .map_err(|error| CliError::Usage(format!("cannot compute an auth tag: {error}")))?;
    if tag.contains("nsec") || tag.contains(&owner.secret_key().to_secret_hex()) {
        return Err(CliError::Other(
            "refusing to print an auth tag that contains key material".into(),
        ));
    }
    println!("{tag}");
    Ok(())
}

/// Check a tag locally. No private key and no relay connection.
///
/// The tag must verify for `agent_hex`, and its owner must be
/// `provisioner_hex`. Success prints only those two public keys.
pub fn cmd_verify(agent_hex: &str, provisioner_hex: &str, tag_json: &str) -> Result<(), CliError> {
    let agent = PublicKey::from_hex(agent_hex.trim())
        .map_err(|_| CliError::Usage("agent pubkey must be 64 hex characters".into()))?;
    let provisioner = PublicKey::from_hex(provisioner_hex.trim())
        .map_err(|_| CliError::Usage("provisioner pubkey must be 64 hex characters".into()))?;
    if agent == provisioner {
        return Err(CliError::Usage(
            "owner and agent pubkeys must differ".into(),
        ));
    }
    let text = tag_json.trim();
    if text.is_empty()
        || text.contains("nsec")
        || text.len() > 512
        || text.contains('\n')
        || text.contains('\r')
    {
        return Err(CliError::Other("auth tag is not valid".into()));
    }
    let owner = buzz_sdk::nip_oa::verify_auth_tag(text, &agent)
        .map_err(|_| CliError::Other("auth tag is not valid".into()))?;
    if owner != provisioner {
        return Err(CliError::Other("auth tag is not valid".into()));
    }
    let body = serde_json::json!({
        "verified": true,
        "pubkey": agent.to_hex(),
        "agent_owner_pubkey": provisioner.to_hex(),
    });
    let line = serde_json::to_string(&body)
        .map_err(|_| CliError::Other("auth tag is not valid".into()))?;
    if line.contains(text) || line.contains("nsec") {
        return Err(CliError::Other("auth tag is not valid".into()));
    }
    println!("{line}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_sdk::nip_oa::verify_auth_tag;

    #[test]
    fn compute_signs_the_agent_and_does_not_print_the_secret() {
        let owner = Keys::generate();
        let agent = Keys::generate();
        let tag = buzz_sdk::nip_oa::compute_auth_tag(&owner, &agent.public_key(), "")
            .expect("distinct keys");
        let secret = owner.secret_key().to_secret_hex();
        assert!(!tag.contains(&secret));
        assert!(!tag.contains("nsec"));
        verify_auth_tag(&tag, &agent.public_key()).expect("tag verifies");
        let parsed: serde_json::Value = serde_json::from_str(&tag).expect("json");
        assert_eq!(parsed[0], "auth");
        assert_eq!(parsed[1], owner.public_key().to_hex());
        assert_eq!(parsed[2], "");
    }

    #[test]
    fn verify_accepts_only_the_named_worker_and_provisioner() {
        let owner = Keys::generate();
        let agent = Keys::generate();
        let other = Keys::generate();
        let tag = buzz_sdk::nip_oa::compute_auth_tag(&owner, &agent.public_key(), "")
            .expect("distinct keys");
        let error = cmd_verify(
            &other.public_key().to_hex(),
            &owner.public_key().to_hex(),
            &tag,
        )
        .expect_err("different agent");
        assert!(error.to_string().contains("not valid"));
        assert!(!error.to_string().contains(&tag));
        let error = cmd_verify(
            &agent.public_key().to_hex(),
            &other.public_key().to_hex(),
            &tag,
        )
        .expect_err("different provisioner");
        assert!(error.to_string().contains("not valid"));
        cmd_verify(
            &agent.public_key().to_hex(),
            &owner.public_key().to_hex(),
            &tag,
        )
        .expect("matching tag");
    }

    #[test]
    fn self_attestation_is_rejected() {
        let owner = Keys::generate();
        let error = cmd_compute(&owner, &owner.public_key().to_hex()).expect_err("same key");
        let rendered = error.to_string();
        assert!(rendered.contains("cannot compute"));
        assert!(!rendered.contains(&owner.secret_key().to_secret_hex()));
    }
}
