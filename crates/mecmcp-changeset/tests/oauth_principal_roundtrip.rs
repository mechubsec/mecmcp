//! `Principal::OAuth` persistence and self-approval identity (mecmcp#498).

use mecmcp_changeset::approver::ApproverIdentity;
use mecmcp_changeset::records::{PersistedAttribution, PersistedPrincipal};

#[test]
fn an_oauth_principal_survives_a_json_round_trip_as_a_tagged_variant() {
    let principal = PersistedPrincipal::OAuth {
        issuer: "https://idp.example".into(),
        subject: "alice".into(),
        client_id: Some("odysseus".into()),
    };
    let json = serde_json::to_value(&principal).expect("serialise");
    assert_eq!(
        json,
        serde_json::json!({
            "type": "oauth",
            "value": {"issuer": "https://idp.example", "subject": "alice", "client_id": "odysseus"}
        })
    );
    let back: PersistedPrincipal = serde_json::from_value(json).expect("deserialise");
    assert_eq!(back, principal);
}

fn oauth_attribution(issuer: &str, subject: &str) -> mecmcp_audit::Attribution {
    mecmcp_audit::Attribution {
        principal: mecmcp_audit::Principal::OAuth {
            issuer: issuer.into(),
            subject: subject.into(),
            client_id: None,
        },
        ..mecmcp_audit::Attribution::stdio()
    }
}

#[test]
fn an_oauth_attribution_persists_as_oauth_not_as_a_token() {
    let persisted = PersistedAttribution::from(&oauth_attribution("https://idp.example", "alice"));
    assert!(matches!(
        persisted.principal,
        PersistedPrincipal::OAuth { .. }
    ));
}

#[test]
fn approver_identity_keys_on_issuer_and_subject_not_the_display_string() {
    let owner = ApproverIdentity::from_attribution(&oauth_attribution("https://a", "alice"));
    let same = ApproverIdentity::from_attribution(&oauth_attribution("https://a", "alice"));
    let other_issuer = ApproverIdentity::from_attribution(&oauth_attribution("https://b", "alice"));
    assert_eq!(owner.principal(), same.principal());
    assert_ne!(owner.principal(), other_issuer.principal());
}
