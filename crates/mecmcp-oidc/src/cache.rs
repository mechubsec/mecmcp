//! Bounded caching of the discovery document and JWKS.
//!
//! Three separate durations, each guarding a different failure mode:
//!
//! - `refresh_interval` — how long a successful fetch is trusted before the
//!   next verification triggers a refresh. Bounds request volume against a
//!   healthy IdP and is what lets JWKS rotation (old `kid` retired, new `kid`
//!   added) show up without a server restart.
//! - `retry_backoff` — the minimum gap between refresh *attempts* after a
//!   failure. Without this, every verification against a down IdP would
//!   retry the network call, which is the unbounded-retry failure mode the
//!   acceptance criteria call out by name.
//! - `max_key_age` — the hard ceiling on how long a stale cached key set may
//!   still be served while the IdP is unreachable. Past this age the cache
//!   reports [`VerificationFailure::KeysUnavailable`] rather than keep
//!   verifying against keys nobody can vouch for any more — the **fail
//!   closed** lens applies to the cache, not just to an individual claim
//!   check.
//!
//! This cache only ever affects OIDC verification. An IdP outage cannot
//! touch `tokens.json`-based bearer auth, because nothing in that path calls
//! into this crate — additive, not a chokepoint, by construction rather than
//! by convention.

use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::jwk::JwkSet;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::error::VerificationFailure;
use crate::fetch::KeySource;

/// Cache tuning. See the module docs for what each field bounds.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// How long a successful fetch is trusted before the next refresh.
    pub refresh_interval: Duration,
    /// Minimum gap between refresh attempts after a failure.
    pub retry_backoff: Duration,
    /// Oldest a cached key set may be while still served during an outage.
    pub max_key_age: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            refresh_interval: Duration::from_secs(300),
            retry_backoff: Duration::from_secs(30),
            max_key_age: Duration::from_secs(3600),
        }
    }
}

#[derive(Default)]
struct CacheState {
    jwks_uri: Option<String>,
    keys: Option<JwkSet>,
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
}

/// Caches the discovery document (specifically, its `jwks_uri`) and the JWKS
/// fetched from it, refreshing on the schedule described in the module docs.
pub struct KeyCache {
    source: Arc<dyn KeySource>,
    issuer: String,
    config: CacheConfig,
    state: Mutex<CacheState>,
}

impl KeyCache {
    /// Build a cache for `issuer`, fetching through `source`.
    #[must_use]
    pub fn new(source: Arc<dyn KeySource>, issuer: impl Into<String>, config: CacheConfig) -> Self {
        Self {
            source,
            issuer: issuer.into(),
            config,
            state: Mutex::new(CacheState::default()),
        }
    }

    /// Return a usable key set, refreshing it if the cache is stale enough to
    /// warrant it.
    ///
    /// # Errors
    /// Returns [`VerificationFailure::KeysUnavailable`] if no fetch has ever
    /// succeeded, or if the last known-good key set is older than
    /// `max_key_age` and a refresh attempt is not due to be retried yet (or
    /// was just retried and failed).
    pub async fn keys(&self) -> Result<JwkSet, VerificationFailure> {
        let mut state = self.state.lock().await;
        let now = Instant::now();

        let is_fresh = state.fetched_at.is_some_and(|fetched_at| {
            now.duration_since(fetched_at) < self.config.refresh_interval
        });
        if is_fresh {
            // `is_fresh` implies a successful fetch populated `keys`.
            if let Some(keys) = &state.keys {
                return Ok(keys.clone());
            }
        }

        let backed_off = state.last_attempt.is_some_and(|attempted_at| {
            now.duration_since(attempted_at) < self.config.retry_backoff
        });
        if backed_off {
            return self.serve_stale_or_fail(&state, now);
        }

        state.last_attempt = Some(now);
        match self.refresh(&mut state).await {
            Ok(()) => {
                let keys = state
                    .keys
                    .clone()
                    .expect("refresh only returns Ok after populating keys");
                Ok(keys)
            }
            Err(error) => {
                tracing::warn!(
                    issuer = %self.issuer,
                    error = %error,
                    "OIDC key refresh failed; falling back to cached keys within max_key_age if any"
                );
                self.serve_stale_or_fail(&state, now)
            }
        }
    }

    fn serve_stale_or_fail(
        &self,
        state: &CacheState,
        now: Instant,
    ) -> Result<JwkSet, VerificationFailure> {
        let usable_stale = state.keys.as_ref().filter(|_| {
            state
                .fetched_at
                .is_some_and(|fetched_at| now.duration_since(fetched_at) < self.config.max_key_age)
        });

        match usable_stale {
            Some(keys) => Ok(keys.clone()),
            None => Err(VerificationFailure::KeysUnavailable {
                issuer: self.issuer.clone(),
            }),
        }
    }

    async fn refresh(&self, state: &mut CacheState) -> Result<(), crate::error::FetchError> {
        if state.jwks_uri.is_none() {
            let discovery = self.source.fetch_discovery(&self.issuer).await?;
            if discovery.issuer != self.issuer {
                return Err(crate::error::FetchError::IssuerMismatch {
                    configured: self.issuer.clone(),
                    discovered: discovery.issuer,
                });
            }
            state.jwks_uri = Some(discovery.jwks_uri);
        }
        // Safe: the branch above guarantees `Some` on every path that reaches here.
        let jwks_uri = state.jwks_uri.clone().unwrap_or_default();
        let keys = self.source.fetch_jwks(&jwks_uri).await?;

        state.keys = Some(keys);
        state.fetched_at = Some(Instant::now());
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::discovery::DiscoveryDocument;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::{advance, pause};

    struct CountingSource {
        discovery_calls: AtomicUsize,
        jwks_calls: AtomicUsize,
        fail_jwks: std::sync::atomic::AtomicBool,
    }

    impl CountingSource {
        fn new() -> Self {
            Self {
                discovery_calls: AtomicUsize::new(0),
                jwks_calls: AtomicUsize::new(0),
                fail_jwks: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    #[async_trait::async_trait]
    impl KeySource for CountingSource {
        async fn fetch_discovery(
            &self,
            issuer: &str,
        ) -> Result<DiscoveryDocument, crate::error::FetchError> {
            self.discovery_calls.fetch_add(1, Ordering::SeqCst);
            Ok(DiscoveryDocument {
                issuer: issuer.to_owned(),
                jwks_uri: format!("{issuer}/jwks"),
                authorization_endpoint: None,
                token_endpoint: None,
                end_session_endpoint: None,
                code_challenge_methods_supported: vec![],
                id_token_signing_alg_values_supported: vec![],
            })
        }

        async fn fetch_jwks(&self, _jwks_uri: &str) -> Result<JwkSet, crate::error::FetchError> {
            self.jwks_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_jwks.load(Ordering::SeqCst) {
                return Err(crate::error::FetchError::HttpStatus {
                    what: "JWKS",
                    status: 503,
                });
            }
            Ok(JwkSet { keys: Vec::new() })
        }
    }

    fn config(refresh: Duration, backoff: Duration, max_age: Duration) -> CacheConfig {
        CacheConfig {
            refresh_interval: refresh,
            retry_backoff: backoff,
            max_key_age: max_age,
        }
    }

    #[tokio::test]
    async fn discovery_is_fetched_once_and_jwks_refetched_on_schedule() {
        pause();
        let source = Arc::new(CountingSource::new());
        let cache = KeyCache::new(
            source.clone(),
            "https://idp.example.com",
            config(
                Duration::from_secs(10),
                Duration::from_secs(5),
                Duration::from_secs(60),
            ),
        );

        cache.keys().await.unwrap();
        cache.keys().await.unwrap();
        assert_eq!(
            source.discovery_calls.load(Ordering::SeqCst),
            1,
            "jwks_uri is learned once and cached indefinitely"
        );
        assert_eq!(
            source.jwks_calls.load(Ordering::SeqCst),
            1,
            "second call within refresh_interval must not refetch"
        );

        advance(Duration::from_secs(11)).await;
        cache.keys().await.unwrap();
        assert_eq!(
            source.jwks_calls.load(Ordering::SeqCst),
            2,
            "call after refresh_interval elapsed must refetch"
        );
    }

    #[tokio::test]
    async fn failed_refresh_does_not_retry_within_backoff() {
        pause();
        let source = Arc::new(CountingSource::new());
        source.fail_jwks.store(true, Ordering::SeqCst);
        let cache = KeyCache::new(
            source.clone(),
            "https://idp.example.com",
            config(
                Duration::from_secs(10),
                Duration::from_secs(30),
                Duration::from_secs(60),
            ),
        );

        let first = cache.keys().await;
        assert!(matches!(
            first,
            Err(VerificationFailure::KeysUnavailable { .. })
        ));
        assert_eq!(source.jwks_calls.load(Ordering::SeqCst), 1);

        // Still within retry_backoff: must not call the network again.
        advance(Duration::from_secs(5)).await;
        let second = cache.keys().await;
        assert!(matches!(
            second,
            Err(VerificationFailure::KeysUnavailable { .. })
        ));
        assert_eq!(
            source.jwks_calls.load(Ordering::SeqCst),
            1,
            "a down IdP must not be retried before retry_backoff elapses"
        );

        // Past retry_backoff: one more attempt is allowed.
        advance(Duration::from_secs(30)).await;
        let _ = cache.keys().await;
        assert_eq!(source.jwks_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn stale_keys_are_served_within_max_key_age_after_a_failed_refresh() {
        pause();
        let source = Arc::new(CountingSource::new());
        let cache = KeyCache::new(
            source.clone(),
            "https://idp.example.com",
            config(
                Duration::from_secs(10),
                Duration::from_secs(5),
                Duration::from_secs(120),
            ),
        );

        // Prime the cache with a successful fetch.
        cache.keys().await.unwrap();

        // Now the IdP goes down, but we are still well within max_key_age.
        source.fail_jwks.store(true, Ordering::SeqCst);
        advance(Duration::from_secs(20)).await;
        let result = cache.keys().await;
        assert!(
            result.is_ok(),
            "a briefly unreachable IdP must not break verification for callers using stale-but-fresh-enough keys"
        );
    }

    #[tokio::test]
    async fn keys_older_than_max_key_age_fail_closed() {
        pause();
        let source = Arc::new(CountingSource::new());
        let cache = KeyCache::new(
            source.clone(),
            "https://idp.example.com",
            config(
                Duration::from_secs(10),
                Duration::from_secs(5),
                Duration::from_secs(60),
            ),
        );

        cache.keys().await.unwrap();

        source.fail_jwks.store(true, Ordering::SeqCst);
        advance(Duration::from_secs(120)).await;
        let result = cache.keys().await;
        assert!(
            matches!(result, Err(VerificationFailure::KeysUnavailable { .. })),
            "keys older than max_key_age must fail closed rather than be served indefinitely"
        );
    }

    struct MismatchedIssuerSource;

    #[async_trait::async_trait]
    impl KeySource for MismatchedIssuerSource {
        async fn fetch_discovery(
            &self,
            _issuer: &str,
        ) -> Result<DiscoveryDocument, crate::error::FetchError> {
            Ok(DiscoveryDocument {
                issuer: "https://evil.example.org".to_owned(),
                jwks_uri: "https://elsewhere.example.net/jwks".to_owned(),
                authorization_endpoint: None,
                token_endpoint: None,
                end_session_endpoint: None,
                code_challenge_methods_supported: vec![],
                id_token_signing_alg_values_supported: vec![],
            })
        }

        async fn fetch_jwks(&self, _jwks_uri: &str) -> Result<JwkSet, crate::error::FetchError> {
            unreachable!("issuer mismatch must be caught before the JWKS is ever fetched")
        }
    }

    #[tokio::test]
    async fn discovery_document_issuer_mismatch_fails_closed() {
        pause();
        let cache = KeyCache::new(
            Arc::new(MismatchedIssuerSource),
            "https://idp.example.com",
            config(
                Duration::from_secs(10),
                Duration::from_secs(5),
                Duration::from_secs(60),
            ),
        );

        let result = cache.keys().await;
        assert!(
            matches!(result, Err(VerificationFailure::KeysUnavailable { .. })),
            "a discovery document claiming a different issuer must fail closed, not be trusted"
        );
    }

    #[tokio::test]
    async fn never_fetched_and_unreachable_fails_closed_with_named_issuer() {
        pause();
        let source = Arc::new(CountingSource::new());
        source.fail_jwks.store(true, Ordering::SeqCst);
        let cache = KeyCache::new(
            source,
            "https://idp.example.com",
            config(
                Duration::from_secs(10),
                Duration::from_secs(5),
                Duration::from_secs(60),
            ),
        );

        match cache.keys().await {
            Err(VerificationFailure::KeysUnavailable { issuer }) => {
                assert_eq!(issuer, "https://idp.example.com");
            }
            other => panic!("expected KeysUnavailable, got {other:?}"),
        }
    }
}
