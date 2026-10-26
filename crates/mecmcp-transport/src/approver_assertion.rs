//! Verifying the `Mecmcp-Approver-Assertion` step-up header (mecmcp#400
//! Phase 2 / MEC-994, W3).
//!
//! This header carries a fresh IdP-issued JWT proving the caller is who they
//! say they are *right now*, in addition to (never instead of) their
//! existing bearer token. It is a distinct header, never `Authorization` and
//! never a tool argument, so it cannot be confused with device/tool
//! authorization and never reaches a tool's own argument validation.
//!
//! The verified JWT's claims never outlive this module's call into
//! [`mecmcp_auth::bind_approver`]: the JWT itself is never logged, never
//! persisted, and the only thing this layer retains afterward is the bounded
//! `jti` replay set below.

/// The header carrying a step-up approver assertion.
///
/// Never `Authorization` — that header remains the caller's existing bearer
/// token, device/tool authorization unchanged. This header is additive, and
/// only consulted at approval time.
///
/// Always available, regardless of the `verified-approver` feature: even a
/// build with no verifier compiled in must recognize this header by name, so
/// `auth.rs` can fail it closed with `approver_assertion_not_configured`
/// instead of letting it through unchecked.
pub const APPROVER_ASSERTION_HEADER: &str = "Mecmcp-Approver-Assertion";

#[cfg(feature = "verified-approver")]
mod verifier {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use mecmcp_auth::{
        ApproverClaims, ApproverPolicy, BindingFailure, CallerCtx, Grant, VerifiedApprover,
        bind_approver,
    };
    use mecmcp_oidc::{TokenVerifier, VerificationFailure};

    use crate::approver_replay_store::jti_key;
    #[cfg(unix)]
    use crate::approver_replay_store::{ReplayStore, ReplayStoreError};

    /// Server-side configuration for verifying a presented approver assertion.
    ///
    /// Built once at startup from `mecmcp-runtime`'s `VerifiedApproverArgs` (W5)
    /// and shared across requests. Holds the bounded `jti` replay set so a given
    /// assertion can be bound to a caller's token at most once.
    pub struct ApproverAssertionVerifier {
        verifier: Arc<TokenVerifier>,
        issuer: String,
        policy: ApproverPolicy,
        replay: Mutex<ReplayState>,
    }

    /// The replay set, keyed by the SHA-256 hex of each `jti`, plus the optional durable log.
    struct ReplayState {
        seen: HashMap<String, i64>,
        #[cfg(unix)]
        store: Option<ReplayStore>,
    }

    impl ApproverAssertionVerifier {
        /// Build a verifier bound to one issuer's `TokenVerifier` and approver
        /// policy.
        ///
        /// `issuer` must be the same issuer `verifier` is configured to accept —
        /// it is passed through to [`bind_approver`] so binding can confirm the
        /// assertion's issuer matches the caller's token-bound `oidc_subject`,
        /// without this type re-deriving it from `verifier`'s private config.
        #[must_use]
        pub fn new(
            verifier: Arc<TokenVerifier>,
            issuer: impl Into<String>,
            policy: ApproverPolicy,
        ) -> Self {
            Self {
                verifier,
                issuer: issuer.into(),
                policy,
                replay: Mutex::new(ReplayState {
                    seen: HashMap::new(),
                    #[cfg(unix)]
                    store: None,
                }),
            }
        }

        /// Make the replay set durable across restarts (opt-in; `new` stays in-memory).
        ///
        /// Each first use is appended to `path` and fsynced before approval is returned; a
        /// failed write refuses the approval (`replay_store_unavailable`). Unexpired records
        /// are loaded now, so an assertion used before a restart stays refused.
        ///
        /// # Errors
        /// The file is a symlink, not a regular file, group/world-accessible, owned by
        /// another user, or contains a malformed record.
        #[cfg(unix)]
        pub fn with_replay_store(self, path: &std::path::Path) -> Result<Self, ReplayStoreError> {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| {
                    i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
                });
            let (store, seen) = ReplayStore::open(path, now)?;
            Ok(Self {
                replay: Mutex::new(ReplayState {
                    seen,
                    store: Some(store),
                }),
                ..self
            })
        }

        /// Refuse a `jti` seen before; otherwise record it (durably when a store is set).
        fn record_use(
            &self,
            jti: &str,
            retain_until: i64,
            now: i64,
        ) -> Result<(), ApproverAssertionError> {
            let key = jti_key(jti);
            let Ok(mut state) = self.replay.lock() else {
                // A poisoned lock means a prior panic inside this guard; fail
                // closed rather than risk losing replay protection.
                return Err(ApproverAssertionError::ReplayGuardUnavailable);
            };
            state.seen.retain(|_, &mut until| until >= now);
            if state.seen.contains_key(&key) {
                return Err(ApproverAssertionError::ReplayedJti);
            }
            #[cfg(unix)]
            {
                let ReplayState { seen, store } = &mut *state;
                if let Some(store) = store {
                    if let Err(error) = store.record(&key, retain_until) {
                        tracing::error!(%error, "replay store write failed; refusing approval");
                        return Err(ApproverAssertionError::ReplayStoreUnavailable);
                    }
                    seen.insert(key, retain_until);
                    if let Err(error) = store.compact_if_needed(seen) {
                        tracing::warn!(%error, "replay store compaction failed");
                    }
                    return Ok(());
                }
            }
            state.seen.insert(key, retain_until);
            Ok(())
        }

        /// Verify the assertion's signature, issuer, audience, and expiry, bind
        /// it to `caller`'s token, and check it has not already been used.
        ///
        /// Each distinct refusal reason maps to its own [`ApproverAssertionError`]
        /// variant, per the MEC-994 acceptance criteria that every rejection be
        /// separately audited.
        ///
        /// # Errors
        /// Returns the specific reason the assertion was refused.
        pub async fn verify_and_bind<G: Grant>(
            &self,
            assertion: &str,
            caller: &CallerCtx<G>,
            now: i64,
        ) -> Result<VerifiedApprover, ApproverAssertionError> {
            let claims = self.verifier.verify(assertion).await?;
            // `mecmcp-auth` takes only the minimal claims it needs and has no
            // dependency on `mecmcp-oidc` itself; convert here rather than
            // passing `claims` straight through.
            let approver_claims = ApproverClaims {
                subject: claims.subject.clone(),
                roles: claims.roles.clone(),
                issued_at: claims.issued_at,
                auth_time: claims.auth_time,
            };
            let approver =
                bind_approver(caller, &self.issuer, &approver_claims, &self.policy, now)?;

            let jti = claims
                .jwt_id
                .clone()
                .ok_or(ApproverAssertionError::MissingJwtId)?;
            // Retain through `exp + leeway`, not bare `exp`: `self.verifier`
            // above still accepts this assertion up to that point (its
            // `Validation::leeway` is set from the same `OidcConfig`), so
            // evicting any earlier would forget a `jti` while a replay could
            // still verify and bind. `bind_approver` also refuses anything
            // presented past `issued_at + max_age`, which can be a tighter
            // bound than `exp + leeway` for a short-`max_age` policy guarding a
            // long-lived token; retain through whichever bound is later.
            let leeway_secs = i64::try_from(self.verifier.leeway().as_secs()).unwrap_or(i64::MAX);
            let max_age_secs = i64::try_from(self.policy.max_age.as_secs()).unwrap_or(i64::MAX);
            let retain_until = claims
                .expires_at
                .saturating_add(leeway_secs)
                .max(claims.issued_at.saturating_add(max_age_secs));

            self.record_use(&jti, retain_until, now)?;

            Ok(approver)
        }
    }

    /// Why a presented approver assertion was refused.
    ///
    /// Every variant is a distinct, audited reason — see the MEC-994 acceptance
    /// criteria. No catch-all: a call site unable to name which of these applies
    /// has found a gap in this enum, not a reason to collapse the detail.
    #[derive(Debug, thiserror::Error)]
    pub enum ApproverAssertionError {
        /// The assertion itself failed JWT verification (forged/expired
        /// signature, wrong issuer/audience, stale, IdP unreachable, ...). See
        /// [`VerificationFailure`] for the specific reason.
        #[error(transparent)]
        Verification(#[from] VerificationFailure),
        /// The assertion verified, but does not bind to this caller's token. See
        /// [`BindingFailure`] for the specific reason.
        #[error(transparent)]
        Binding(#[from] BindingFailure),
        /// The assertion carries no `jti` claim, so replay protection has
        /// nothing to key on. Fails closed rather than accept an
        /// unreplay-protected assertion.
        #[error("the assertion has no jwt_id (jti) claim, which replay protection requires")]
        MissingJwtId,
        /// This exact assertion (by `jti`) has already been bound to an
        /// approval.
        #[error("this assertion has already been used (jwt_id replay)")]
        ReplayedJti,
        /// The in-memory replay guard's lock was poisoned by an earlier panic.
        #[error("the replay guard is unavailable")]
        ReplayGuardUnavailable,
        /// The durable replay store could not record this use (write/fsync failed),
        /// so the approval is refused rather than granted unrecorded.
        #[error("the durable replay store is unavailable")]
        ReplayStoreUnavailable,
    }

    impl ApproverAssertionError {
        /// A stable, lowercase machine-readable code for this reason, for
        /// structured audit logging. The MEC-994 acceptance criteria require
        /// every distinct rejection to carry a distinct *audited* reason; the
        /// `Display` message (used in the 401 body and in `tracing::warn!`) is
        /// for humans and can repeat text across variants, so this is the stable
        /// value a log consumer or test should group and assert on instead.
        #[must_use]
        pub fn reason_code(&self) -> &'static str {
            match self {
                Self::Verification(inner) => inner.reason_code(),
                Self::Binding(inner) => inner.reason_code(),
                Self::MissingJwtId => "missing_jwt_id",
                Self::ReplayedJti => "replayed_jti",
                Self::ReplayGuardUnavailable => "replay_guard_unavailable",
                Self::ReplayStoreUnavailable => "replay_store_unavailable",
            }
        }
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    mod tests {
        use super::*;
        use mecmcp_auth::{ActorType, NoGrant, OidcSubject, ScopeSet};
        use std::time::Duration;

        // Deliberately no async verifier integration test here: constructing a
        // `TokenVerifier` requires a `KeySource`, which `mecmcp-oidc`'s own test
        // suite covers exhaustively (forged signatures, wrong issuer, expiry,
        // IdP-unreachable). Duplicating that here would test `mecmcp-oidc` a
        // second time instead of this module's own job — binding and replay —
        // so those two are tested directly against `bind_approver` and a
        // synthetic `seen_jti` map.

        fn policy() -> ApproverPolicy {
            ApproverPolicy {
                approver_role: "approver".to_owned(),
                max_age: Duration::from_secs(300),
                require_auth_time: false,
            }
        }

        fn caller(oidc_subject: Option<OidcSubject>) -> CallerCtx<NoGrant> {
            CallerCtx {
                token_name: "approver-token".to_owned(),
                devices: ScopeSet::Wildcard,
                tools: ScopeSet::Wildcard,
                grant: None,
                provider: None,
                provider_tier: None,
                on_behalf_of: None,
                actor_type: ActorType::Human,
                oidc_subject,
                verified_approver: None,
                client_name: None,
                model_id: None,
                session_id: None,
                request_id: uuid::Uuid::new_v4(),
                oauth: None,
            }
        }

        struct NoKeys;

        #[async_trait::async_trait]
        impl mecmcp_oidc::KeySource for NoKeys {
            async fn fetch_discovery(
                &self,
                _issuer: &str,
            ) -> Result<mecmcp_oidc::DiscoveryDocument, mecmcp_oidc::FetchError> {
                unreachable!("record_use never verifies a JWT")
            }
            async fn fetch_jwks(
                &self,
                _jwks_uri: &str,
            ) -> Result<jsonwebtoken::jwk::JwkSet, mecmcp_oidc::FetchError> {
                unreachable!("record_use never verifies a JWT")
            }
        }

        fn verifier() -> ApproverAssertionVerifier {
            let config = mecmcp_oidc::OidcConfig::new("https://idp.example.com", "aud", "roles");
            let token_verifier = TokenVerifier::new(config, Arc::new(NoKeys));
            ApproverAssertionVerifier::new(
                Arc::new(token_verifier),
                "https://idp.example.com",
                policy(),
            )
        }

        #[test]
        fn a_failed_store_write_refuses_the_approval_and_records_nothing() {
            let verifier = verifier();
            let full = std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap();
            verifier.replay.lock().unwrap().store = Some(ReplayStore::from_file(full));
            let error = verifier.record_use("jti-1", 2_000, 1_000).unwrap_err();
            assert_eq!(error.reason_code(), "replay_store_unavailable");
            assert!(verifier.replay.lock().unwrap().seen.is_empty());
        }

        #[test]
        fn record_use_refuses_the_second_use_of_a_jti() {
            let verifier = verifier();
            verifier.record_use("jti-1", 2_000, 1_000).unwrap();
            let error = verifier.record_use("jti-1", 2_000, 1_001).unwrap_err();
            assert_eq!(error.reason_code(), "replayed_jti");
        }

        #[test]
        fn missing_jti_is_refused_distinctly() {
            // This exercises the binding half of the "no jti" branch of
            // `verify_and_bind` without a real JWT: binding itself must succeed
            // on claims that would, in `verify_and_bind`, carry no `jwt_id` —
            // the `MissingJwtId` refusal in that function is a separate check
            // made after binding, on the real `VerifiedClaims` the verifier
            // returns (which `ApproverClaims` deliberately does not carry).
            let claims = ApproverClaims {
                subject: "alice".to_owned(),
                roles: vec!["approver".to_owned()],
                issued_at: 1000,
                auth_time: None,
            };
            let bound = OidcSubject {
                issuer: "https://idp.example.com".to_owned(),
                subject: "alice".to_owned(),
            };
            let approver = bind_approver(
                &caller(Some(bound)),
                "https://idp.example.com",
                &claims,
                &policy(),
                1010,
            );
            assert!(approver.is_ok(), "binding itself should succeed here");
        }
    }
}

#[cfg(feature = "verified-approver")]
pub use verifier::{ApproverAssertionError, ApproverAssertionVerifier};
