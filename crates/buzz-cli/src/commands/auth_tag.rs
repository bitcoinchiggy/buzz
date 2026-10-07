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
    fn self_attestation_is_rejected() {
        let owner = Keys::generate();
        let error = cmd_compute(&owner, &owner.public_key().to_hex()).expect_err("same key");
        let rendered = error.to_string();
        assert!(rendered.contains("cannot compute"));
        assert!(!rendered.contains(&owner.secret_key().to_secret_hex()));
    }
}
