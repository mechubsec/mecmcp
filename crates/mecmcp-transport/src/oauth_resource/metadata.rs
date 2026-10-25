//! RFC 9728 OAuth 2.0 Protected Resource Metadata.

use super::OAuthResourceConfig;
use axum::{Json, Router, http::header, routing::get};
use mecmcp_oidc::ROOT_METADATA_PATH;
use serde_json::{Value, json};
use std::sync::Arc;

/// The metadata document for `config`: resource, authorization server, bearer method, and
/// the scope names the map defines. Nothing that identifies a tool, device, or client.
#[must_use]
pub fn metadata_document(config: &OAuthResourceConfig) -> Value {
    let mut document = json!({
        "resource": config.resource().as_str(),
        "authorization_servers": [config.issuer()],
        "bearer_methods_supported": ["header"],
    });
    let supported = config.scope_map().scopes_supported();
    if !supported.is_empty() {
        document["scopes_supported"] = json!(supported);
    }
    document
}

/// A router serving the document, unauthenticated, at the RFC 9728 path-inserted URL for
/// the resource and at the root well-known URL. Merge it **outside** the bearer boundary.
pub fn metadata_router(config: &OAuthResourceConfig) -> Router {
    let document = Arc::new(metadata_document(config));
    let handler = move || {
        let document = Arc::clone(&document);
        async move {
            (
                [(header::CACHE_CONTROL, "public, max-age=300")],
                Json((*document).clone()),
            )
        }
    };
    let specific = config.resource().metadata_path();
    let router = Router::new().route(&specific, get(handler.clone()));
    if specific == ROOT_METADATA_PATH {
        return router;
    }
    router.route(ROOT_METADATA_PATH, get(handler))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::oauth_resource::OAuthScopeMap;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt as _;

    fn config(resource: &str) -> OAuthResourceConfig {
        let map = OAuthScopeMap::from_json(
            br#"{"version":1,"scopes":{"junos:read":{"tools":["get_junos_config"],"devices":["srx-secret-name"]}}}"#,
        )
        .unwrap();
        OAuthResourceConfig::new("https://idp.example/realms/lab", resource, map).unwrap()
    }

    async fn get(
        router: axum::Router,
        method: &str,
        path: &str,
    ) -> (StatusCode, String, Option<String>) {
        let response = router
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let cache = response
            .headers()
            .get(header::CACHE_CONTROL)
            .map(|value| value.to_str().unwrap().to_owned());
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap(), cache)
    }

    #[tokio::test]
    async fn serves_the_rfc_9728_document_at_the_path_inserted_and_root_urls() {
        let router = metadata_router(&config("https://junos.example/mcp"));
        for path in [
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/oauth-protected-resource",
        ] {
            let (status, body, cache) = get(router.clone(), "GET", path).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert_eq!(cache.as_deref(), Some("public, max-age=300"));
            let document: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(
                document,
                serde_json::json!({
                    "resource": "https://junos.example/mcp",
                    "authorization_servers": ["https://idp.example/realms/lab"],
                    "bearer_methods_supported": ["header"],
                    "scopes_supported": ["junos:read"],
                })
            );
        }
    }

    #[tokio::test]
    async fn a_resource_without_a_path_registers_the_root_route_once() {
        // axum panics on a duplicate route; this test is the guard.
        let router = metadata_router(&config("https://junos.example/"));
        let (status, _, _) = get(router, "GET", "/.well-known/oauth-protected-resource").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_document_discloses_no_tool_or_device_names() {
        let router = metadata_router(&config("https://junos.example/mcp"));
        let (_, body, _) = get(router, "GET", "/.well-known/oauth-protected-resource").await;
        assert!(!body.contains("srx-secret-name"), "{body}");
        assert!(!body.contains("get_junos_config"), "{body}");
    }

    #[tokio::test]
    async fn only_get_is_allowed_and_other_paths_are_not_served() {
        let router = metadata_router(&config("https://junos.example/mcp"));
        let (status, _, _) = get(
            router.clone(),
            "POST",
            "/.well-known/oauth-protected-resource",
        )
        .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        let (status, _, _) =
            get(router, "GET", "/.well-known/oauth-protected-resource/other").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn scopes_supported_is_omitted_when_the_map_has_only_roles() {
        let map = OAuthScopeMap::from_json(
            br#"{"version":1,"roles":{"netops":{"tools":["t"],"devices":["d"]}}}"#,
        )
        .unwrap();
        let config =
            OAuthResourceConfig::new("https://idp.example", "https://junos.example/mcp", map)
                .unwrap();
        assert!(metadata_document(&config).get("scopes_supported").is_none());
    }
}
