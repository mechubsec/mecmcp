//! OIDC login: authorization code + PKCE on a loopback redirect by default
//! (RFC 8252), with RFC 8628 device authorization available opt-in only.
//!
//! The thing both flows produce is an `id_token` -- a fresh, short-lived,
//! IdP-signed JWT. That JWT, forwarded verbatim, *is* the
//! `Mecmcp-Approver-Assertion` the server verifies (see
//! `mecmcp-transport::approver_assertion` and `mecmcp-oidc::claims`): this
//! crate does no JWT signing of its own, because the "assertion" is nothing
//! more than a normal OIDC ID token obtained freshly enough to prove the
//! human is here right now. Building a second, client-signed assertion
//! format would be new protocol surface this spec never asked for.

use std::time::Duration;

use oauth2::{
    AuthUrl, AuthorizationCode, Client as OAuth2Client, ClientId, ClientSecret, CsrfToken,
    DeviceAuthorizationUrl, EndpointNotSet, EndpointSet, ExtraTokenFields, PkceCodeChallenge,
    RedirectUrl, Scope, StandardDeviceAuthorizationResponse, StandardErrorResponse,
    StandardRevocableToken, StandardTokenResponse, TokenResponse, TokenUrl,
    basic::{
        BasicErrorResponseType, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenType,
    },
};
use serde::{Deserialize, Serialize};

use crate::error::ApproveError;
use crate::http_bridge;
use crate::loopback::LoopbackListener;

/// The one OIDC extra claim this CLI cares about pulling out of the token
/// response: `id_token`. Every other extension field a real IdP returns
/// (and there can be many) is dropped rather than retained, per the
/// JWT-held-only-in-memory / never-logged requirement.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OidcExtraFields {
    pub id_token: Option<String>,
}

impl ExtraTokenFields for OidcExtraFields {}

type OidcTokenResponse = StandardTokenResponse<OidcExtraFields, BasicTokenType>;
type OidcErrorResponse = StandardErrorResponse<BasicErrorResponseType>;

/// An `oauth2::Client` specialized with [`OidcTokenResponse`] so the token
/// response carries `id_token`, the same specialization pattern
/// `oauth2::basic::BasicClient` uses for `EmptyExtraTokenFields`.
type OidcClient<
    HasAuthUrl = EndpointNotSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasTokenUrl = EndpointNotSet,
> = OAuth2Client<
    OidcErrorResponse,
    OidcTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
>;

/// The subset of `/.well-known/openid-configuration` this CLI needs.
///
/// Deliberately separate from `mecmcp_oidc::DiscoveryDocument`: that type is
/// the resource-server's view (keyed on `jwks_uri`, used to verify tokens)
/// and has no `device_authorization_endpoint`. This CLI is a relying party,
/// never a verifier -- it never checks the assertion's signature itself,
/// the server does -- so it needs a different, client-shaped subset.
#[derive(Debug, Clone, Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: Option<String>,
    token_endpoint: String,
    device_authorization_endpoint: Option<String>,
}

async fn discover(
    client: &reqwest::Client,
    issuer: &str,
) -> Result<DiscoveryDocument, ApproveError> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|source| ApproveError::Discovery {
            issuer: issuer.to_owned(),
            source,
        })?
        .error_for_status()
        .map_err(|source| ApproveError::Discovery {
            issuer: issuer.to_owned(),
            source,
        })?;
    let document: DiscoveryDocument =
        response
            .json()
            .await
            .map_err(|source| ApproveError::Discovery {
                issuer: issuer.to_owned(),
                source,
            })?;

    // OIDC Discovery §4.3: the returned `issuer` must be identical to the
    // URL this document was fetched from. A mismatch means either a
    // misconfigured IdP or an authorization-server mix-up attack -- fail
    // closed either way rather than trusting whatever `issuer` says.
    if document.issuer != issuer {
        return Err(ApproveError::IssuerMismatch {
            configured: issuer.to_owned(),
            reported: document.issuer,
            origin: "discovery document",
        });
    }

    Ok(document)
}

/// What a completed login produced.
pub struct LoginResult {
    /// The fresh ID token: the `Mecmcp-Approver-Assertion` header value.
    pub id_token: String,
    /// The access token, usable as the request's bearer token when the
    /// caller did not supply a separate static one.
    pub access_token: String,
}

/// Configuration shared by both login flows.
pub struct LoginConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub redirect_port: u16,
    pub login_timeout: Duration,
}

fn extract_id_token(token: &OidcTokenResponse) -> Result<String, ApproveError> {
    token
        .extra_fields()
        .id_token
        .clone()
        .ok_or(ApproveError::MissingIdToken)
}

/// Authorization code + PKCE, redirecting to a loopback listener (RFC 8252
/// §7.3). This is the default flow -- the CLI's `--device-code` flag is the
/// only way to reach [`login_device_code`] instead.
pub async fn login_pkce(
    http: &reqwest::Client,
    config: &LoginConfig,
) -> Result<LoginResult, ApproveError> {
    login_pkce_inner(http, config, |authorize_url, redirect_uri| {
        println!("Open this URL in your browser to approve as yourself:\n\n  {authorize_url}\n");
        println!("Waiting for the redirect on {redirect_uri} ...");
    })
    .await
}

/// [`login_pkce`]'s actual implementation, taking a hook invoked with the
/// authorize URL and redirect URI once both are known and the loopback
/// listener is already bound, but before this process waits on it.
///
/// Split out so tests can drive the "browser" step themselves (hitting a
/// mock IdP's authorize endpoint, which redirects back to `redirect_uri`)
/// instead of the production hook, which only prints for a human to act on.
async fn login_pkce_inner(
    http: &reqwest::Client,
    config: &LoginConfig,
    on_ready: impl FnOnce(&str, &str),
) -> Result<LoginResult, ApproveError> {
    let discovery = discover(http, &config.issuer).await?;
    let auth_endpoint = discovery
        .authorization_endpoint
        .ok_or(ApproveError::DiscoveryField {
            issuer: config.issuer.clone(),
            field: "authorization_endpoint",
        })?;

    let listener = LoopbackListener::bind(config.redirect_port).await?;
    let redirect_uri = listener.redirect_uri();

    let client = build_client(
        config,
        &auth_endpoint,
        &discovery.token_endpoint,
        None,
        &redirect_uri,
    )?;

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (authorize_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(config.scopes.iter().cloned().map(Scope::new))
        .set_pkce_challenge(pkce_challenge)
        .url();

    on_ready(authorize_url.as_str(), &redirect_uri);

    let callback = listener.accept_once(config.login_timeout).await?;

    if callback.state != csrf_token.secret().as_str() {
        return Err(ApproveError::CsrfMismatch);
    }

    // RFC 9207: when the authorization server includes `iss` in the
    // redirect, it must match the configured issuer -- another mix-up
    // defense, this time against a second authorization server racing the
    // real one for the same loopback redirect. Not every IdP sends it, so
    // its absence is not itself an error.
    if let Some(reported) = &callback.issuer
        && reported != &config.issuer
    {
        return Err(ApproveError::IssuerMismatch {
            configured: config.issuer.clone(),
            reported: reported.clone(),
            origin: "authorization redirect",
        });
    }

    let token = client
        .exchange_code(AuthorizationCode::new(callback.code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(&|request| http_bridge::send(http, request))
        .await
        .map_err(|err| ApproveError::CodeExchange(err.to_string()))?;

    let id_token = extract_id_token(&token)?;
    Ok(LoginResult {
        id_token,
        access_token: token.access_token().secret().clone(),
    })
}

/// RFC 8628 device authorization grant. Opt-in only (`--device-code`): never
/// invoked unless the operator explicitly asked for it, per the Storm-2372
/// device-code-phishing concern and the many tenants that block the flow by
/// conditional access.
pub async fn login_device_code(
    http: &reqwest::Client,
    config: &LoginConfig,
) -> Result<LoginResult, ApproveError> {
    let discovery = discover(http, &config.issuer).await?;
    let device_endpoint = discovery
        .device_authorization_endpoint
        .ok_or(ApproveError::DeviceAuthUnsupported)?;

    // Device flow has no redirect, but the generic `OidcClient` constructor
    // below still wants a `RedirectUrl` to build; it is never dereferenced
    // by the device-code request path.
    let client = build_client(
        config,
        discovery
            .authorization_endpoint
            .as_deref()
            .unwrap_or(&device_endpoint),
        &discovery.token_endpoint,
        Some(&device_endpoint),
        "urn:ietf:wg:oauth:2.0:oob",
    )?;

    let details: StandardDeviceAuthorizationResponse = client
        .exchange_device_code()
        .add_scopes(config.scopes.iter().cloned().map(Scope::new))
        .request_async(&|request| http_bridge::send(http, request))
        .await
        .map_err(|err| ApproveError::DeviceCodeExchange(err.to_string()))?;

    // RFC 8628 requires displaying the verification URI and user code to the
    // operator so they can complete the login out-of-band; the oauth2 crate
    // wraps both in `Secret` defensively, but printing them to the operator's
    // own terminal is the documented, intended use (see e.g. the crate's
    // `google_devicecode`/`microsoft_devicecode_*` examples, which do the same).
    match details.verification_uri_complete() {
        Some(complete) => println!(
            // codeql[rust/cleartext-logging]: RFC 8628 verification URI, not a secret.
            "Open this URL in your browser to approve as yourself:\n\n  {}\n",
            complete.secret()
        ),
        None => println!(
            // codeql[rust/cleartext-logging]: RFC 8628 verification URI/user code, not secrets.
            "Open this URL in your browser to approve as yourself:\n\n  {}\n\nAnd enter this code: {}\n",
            details.verification_uri().as_str(),
            details.user_code().secret()
        ),
    }
    println!("Waiting for you to complete the device login...");

    let token: OidcTokenResponse = client
        .exchange_device_access_token(&details)
        .request_async(
            &|request| http_bridge::send(http, request),
            tokio::time::sleep,
            Some(config.login_timeout),
        )
        .await
        .map_err(|err| ApproveError::DeviceCodeExchange(err.to_string()))?;

    let id_token = extract_id_token(&token)?;
    Ok(LoginResult {
        id_token,
        access_token: token.access_token().secret().clone(),
    })
}

#[allow(clippy::type_complexity)]
fn build_client(
    config: &LoginConfig,
    auth_endpoint: &str,
    token_endpoint: &str,
    device_endpoint: Option<&str>,
    redirect_uri: &str,
) -> Result<
    OidcClient<EndpointSet, EndpointSet, EndpointNotSet, EndpointNotSet, EndpointSet>,
    ApproveError,
> {
    let mut client = OidcClient::new(ClientId::new(config.client_id.clone()))
        .set_auth_uri(
            AuthUrl::new(auth_endpoint.to_owned())
                .map_err(|e| ApproveError::OidcConfig(e.to_string()))?,
        )
        .set_token_uri(
            TokenUrl::new(token_endpoint.to_owned())
                .map_err(|e| ApproveError::OidcConfig(e.to_string()))?,
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_uri.to_owned())
                .map_err(|e| ApproveError::OidcConfig(e.to_string()))?,
        );
    if let Some(secret) = &config.client_secret {
        client = client.set_client_secret(ClientSecret::new(secret.clone()));
    }
    let client = if let Some(device_endpoint) = device_endpoint {
        client.set_device_authorization_url(
            DeviceAuthorizationUrl::new(device_endpoint.to_owned())
                .map_err(|e| ApproveError::OidcConfig(e.to_string()))?,
        )
    } else {
        // `set_device_authorization_url` is the only way to move
        // `HasDeviceAuthUrl` from `EndpointNotSet`, but the type signature
        // above commits to it regardless of whether this call site needed
        // it; the PKCE path's return value simply never calls
        // `exchange_device_code`. Threading two different return types
        // through one function would cost more clarity than it buys.
        client.set_device_authorization_url(
            DeviceAuthorizationUrl::new(token_endpoint.to_owned())
                .map_err(|e| ApproveError::OidcConfig(e.to_string()))?,
        )
    };
    Ok(client)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    struct MockRequest {
        path: String,
        headers: HashMap<String, String>,
    }

    /// Reads one minimal HTTP/1.1 request off `stream`: request line,
    /// headers, and (if `content-length` says so) the body -- just enough
    /// to drive the assertions below, mirroring `loopback.rs`'s own
    /// hand-rolled parsing rather than pulling in a test-only HTTP server
    /// crate for a handful of fixed exchanges.
    async fn read_request(stream: &mut TcpStream) -> MockRequest {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let path = line.split_whitespace().nth(1).unwrap().to_owned();

        let mut headers = HashMap::new();
        loop {
            let mut header_line = String::new();
            reader.read_line(&mut header_line).await.unwrap();
            let header_line = header_line.trim_end();
            if header_line.is_empty() {
                break;
            }
            if let Some((key, value)) = header_line.split_once(':') {
                headers.insert(key.trim().to_lowercase(), value.trim().to_owned());
            }
        }

        let content_length: usize = headers
            .get("content-length")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        if content_length > 0 {
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).await.unwrap();
        }

        MockRequest { path, headers }
    }

    async fn write_response(
        stream: &mut TcpStream,
        status: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) {
        let mut response = format!("HTTP/1.1 {status}\r\n");
        for (key, value) in headers {
            response.push_str(&format!("{key}: {value}\r\n"));
        }
        response.push_str(&format!(
            "content-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        ));
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        let _ = stream.shutdown().await;
    }

    /// Pulls one query parameter out of a `path?query` request path, the
    /// same base-URL trick `loopback.rs::parse_request_line` uses.
    fn query_param(path: &str, key: &str) -> Option<String> {
        let url = url::Url::parse(&format!("http://127.0.0.1{path}")).ok()?;
        url.query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    }

    /// End to end: a real OIDC authorization-code + PKCE login against a
    /// hand-rolled mock IdP (discovery, authorize, token), followed by a
    /// real MCP `tools/call` approve request carrying both the bearer
    /// token and the login's `id_token` as the `Mecmcp-Approver-Assertion`
    /// header -- covering MEC-996's acceptance criterion that this CLI
    /// performs a real PKCE login and successfully approves a change set
    /// requiring a verified approver.
    #[tokio::test]
    async fn pkce_login_then_approve_end_to_end() {
        // `run()` does this before building any `reqwest::Client`; this
        // test calls straight into the internals it would normally gate,
        // so it must install the provider itself.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let idp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!(
            "http://127.0.0.1:{}",
            idp_listener.local_addr().unwrap().port()
        );

        let idp_issuer = issuer.clone();
        let idp_task = tokio::spawn(async move {
            // Exactly the three requests one PKCE login makes: discovery,
            // the "browser" visiting authorize, and the code exchange.
            for _ in 0..3u8 {
                let (mut stream, _) = idp_listener.accept().await.unwrap();
                let request = read_request(&mut stream).await;
                if request
                    .path
                    .starts_with("/.well-known/openid-configuration")
                {
                    let body = serde_json::json!({
                        "issuer": idp_issuer,
                        "authorization_endpoint": format!("{idp_issuer}/authorize"),
                        "token_endpoint": format!("{idp_issuer}/token"),
                    })
                    .to_string();
                    write_response(
                        &mut stream,
                        "200 OK",
                        &[("content-type", "application/json")],
                        body.as_bytes(),
                    )
                    .await;
                } else if request.path.starts_with("/authorize") {
                    let redirect_uri = query_param(&request.path, "redirect_uri").unwrap();
                    let state = query_param(&request.path, "state").unwrap();
                    let location = format!("{redirect_uri}?code=test-auth-code&state={state}");
                    write_response(&mut stream, "302 Found", &[("location", &location)], b"").await;
                } else if request.path.starts_with("/token") {
                    let body = serde_json::json!({
                        "access_token": "test-access-token",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "id_token": "test-id-token",
                    })
                    .to_string();
                    write_response(
                        &mut stream,
                        "200 OK",
                        &[("content-type", "application/json")],
                        body.as_bytes(),
                    )
                    .await;
                } else {
                    write_response(&mut stream, "404 Not Found", &[], b"").await;
                }
            }
        });

        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let config = LoginConfig {
            issuer: issuer.clone(),
            client_id: "test-client".to_owned(),
            client_secret: None,
            scopes: vec!["openid".to_owned()],
            redirect_port: 0,
            login_timeout: Duration::from_secs(5),
        };

        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        // `login_pkce_inner`'s future is not `Send` (a known rustc/oauth2
        // HRTB limitation around `request_async`'s closure-based
        // `AsyncHttpClient`), so it cannot be `tokio::spawn`ed -- join it
        // concurrently with the "browser" step on this same task instead.
        let login_fut = login_pkce_inner(&http, &config, |authorize_url, _redirect_uri| {
            let _ = ready_tx.send(authorize_url.to_owned());
        });
        let browser_fut = async {
            // Act as the browser: visit the authorize URL (the mock IdP
            // redirects straight to the loopback listener with code+state),
            // then follow that redirect ourselves exactly as a browser would.
            let authorize_url = ready_rx.await.unwrap();
            let redirect = http.get(&authorize_url).send().await.unwrap();
            assert_eq!(redirect.status(), reqwest::StatusCode::FOUND);
            let location = redirect
                .headers()
                .get("location")
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            http.get(&location).send().await.unwrap();
        };

        let (login, ()) = tokio::join!(login_fut, browser_fut);
        let login = login.unwrap();
        idp_task.await.unwrap();
        assert_eq!(login.id_token, "test-id-token");
        assert_eq!(login.access_token, "test-access-token");

        // Now spend that login on a real approve `tools/call`.
        let mcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mcp_addr = format!(
            "http://127.0.0.1:{}",
            mcp_listener.local_addr().unwrap().port()
        );
        let mcp_task = tokio::spawn(async move {
            let (mut stream, _) = mcp_listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            assert_eq!(
                request.headers.get("authorization").map(String::as_str),
                Some("Bearer test-access-token"),
                "approve call must carry the login's access token as the bearer"
            );
            assert_eq!(
                request
                    .headers
                    .get(&mecmcp_transport::APPROVER_ASSERTION_HEADER.to_lowercase()),
                Some(&"test-id-token".to_owned()),
                "approve call must carry the login's id_token as the approver assertion"
            );

            let result =
                rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(
                    "approved",
                )]);
            let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string();
            write_response(
                &mut stream,
                "200 OK",
                &[("content-type", "application/json")],
                body.as_bytes(),
            )
            .await;
        });

        let mut arguments = serde_json::Map::new();
        arguments.insert(
            "change_set_id".to_owned(),
            serde_json::Value::String("cs-1".to_owned()),
        );
        let result = crate::mcp::call_tool(
            &http,
            &mcp_addr,
            &login.access_token,
            Some(&login.id_token),
            "approve_change_set",
            arguments,
        )
        .await
        .unwrap();

        mcp_task.await.unwrap();
        assert_eq!(crate::mcp::render_text(&result), "approved");
    }
}
