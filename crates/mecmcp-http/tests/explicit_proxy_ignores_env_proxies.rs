//! `HttpClientConfig::explicit_proxy` routes through the named proxy, and the
//! proxy environment variables never steer the client, with or without one
//! (#589).
//!
//! The environment must be set before the client is built, and the workspace
//! forbids `unsafe_code` — which `std::env::set_var` requires on this edition.
//! So, like `private_ca_pin_replaces_platform_roots.rs`, this test re-execs
//! itself as a child with the variables set through `Command::env`. The parent
//! runs a TLS origin, a CONNECT proxy that records what it is asked, and a
//! decoy proxy that the environment points at and that must never be dialled.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, reason = "test code")]

use mecmcp_http::{HttpClient, HttpClientConfig, HttpRequest, Method, ProxyUrl};
use mecmcp_openapi::expand_path;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Set only in the child process this test re-execs itself as.
const CHILD_ENV: &str = "MECMCP_HTTP_PROXY_TEST_CHILD";
/// Port of the TLS origin the child requests.
const ORIGIN_PORT_ENV: &str = "MECMCP_HTTP_PROXY_TEST_ORIGIN_PORT";
/// Present only for the explicit-proxy leg: the proxy URL to configure.
const EXPLICIT_PROXY_ENV: &str = "MECMCP_HTTP_PROXY_TEST_EXPLICIT";
/// PEM of the origin's self-signed certificate.
const ORIGIN_CA_ENV: &str = "MECMCP_HTTP_PROXY_TEST_ORIGIN_CA_PEM";

/// Base64 of the `proxyuser:PASSWORD` placeholder userinfo.
const ENCODED_PROXY_USERINFO: &str = "cHJveHl1c2VyOlBBU1NXT1JE"; // gitleaks:allow -- base64 of the test placeholder proxyuser:PASSWORD

#[test]
fn explicit_proxy_is_used_and_env_proxies_are_ignored() {
    if std::env::var_os(CHILD_ENV).is_some() {
        run_child();
        return;
    }
    run_parent();
}

fn run_parent() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (origin_ca_pem, server_config) = tls_material();
        let (origin, origin_port) = bind_local().await;
        serve_origin(origin, server_config);

        let decoy_dials = Arc::new(AtomicUsize::new(0));
        let (decoy, decoy_port) = bind_local().await;
        count_dials(decoy, Arc::clone(&decoy_dials));

        let proxy_heads = Arc::new(Mutex::new(Vec::new()));
        let (proxy, proxy_port) = bind_local().await;
        serve_connect_proxy(proxy, Arc::clone(&proxy_heads));

        let decoy_url = format!("http://127.0.0.1:{decoy_port}");

        // Leg 1: no explicit proxy, environment points at the decoy.
        let direct = spawn_child(&decoy_url, origin_port, &origin_ca_pem, None);
        assert_child_ok("direct leg", &direct);

        // Leg 2: explicit credentialed proxy; the environment still points at
        // the decoy, and NO_PROXY would exempt the origin if it were honoured.
        let explicit = format!("http://proxyuser:PASSWORD@127.0.0.1:{proxy_port}");
        let proxied = spawn_child(&decoy_url, origin_port, &origin_ca_pem, Some(&explicit));
        assert_child_ok("explicit-proxy leg", &proxied);

        assert_eq!(
            decoy_dials.load(Ordering::SeqCst),
            0,
            "an env proxy was dialled"
        );
        let heads = proxy_heads.lock().unwrap().clone();
        assert_eq!(heads.len(), 1, "the explicit proxy saw {heads:?}");
        assert!(
            heads[0].starts_with(&format!("CONNECT localhost:{origin_port} HTTP/1.1\r\n")),
            "not a CONNECT to the origin: {:?}",
            heads[0]
        );
        assert!(
            heads[0].contains(&format!("Basic {ENCODED_PROXY_USERINFO}")),
            "userinfo did not become Proxy-Authorization: {:?}",
            heads[0]
        );
    });
}

fn assert_child_ok(leg: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{leg} failed\n--- child stdout ---\n{}\n--- child stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn spawn_child(
    env_proxy: &str,
    origin_port: u16,
    origin_ca_pem: &str,
    explicit_proxy: Option<&str>,
) -> Output {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .env(CHILD_ENV, "1")
        .env(ORIGIN_PORT_ENV, origin_port.to_string())
        .env(ORIGIN_CA_ENV, origin_ca_pem)
        .env("HTTPS_PROXY", env_proxy)
        .env("https_proxy", env_proxy)
        .env("HTTP_PROXY", env_proxy)
        .env("http_proxy", env_proxy)
        .env("ALL_PROXY", env_proxy)
        .env("all_proxy", env_proxy);
    // NO_PROXY=* only with an explicit proxy: in the direct leg it would
    // exempt the origin from the env proxy and hide a lost `.no_proxy()`.
    match explicit_proxy {
        Some(url) => command
            .env(EXPLICIT_PROXY_ENV, url)
            .env("NO_PROXY", "*")
            .env("no_proxy", "*"),
        None => command
            .env_remove(EXPLICIT_PROXY_ENV)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy"),
    };
    command.output().unwrap()
}

/// Build one client and make one request; a panic is the failure signal.
fn run_child() {
    let origin_port: u16 = std::env::var(ORIGIN_PORT_ENV).unwrap().parse().unwrap();
    let origin_ca_pem = std::env::var(ORIGIN_CA_ENV).unwrap();
    let explicit_proxy = std::env::var(EXPLICIT_PROXY_ENV)
        .ok()
        .map(|raw| ProxyUrl::parse(&raw).unwrap());

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let client = HttpClient::new(HttpClientConfig {
            extra_root_certificates: vec![origin_ca_pem],
            explicit_proxy,
            request_timeout: std::time::Duration::from_secs(10),
            ..Default::default()
        })
        .unwrap();
        let path = expand_path("/", &[]).unwrap();
        let request = HttpRequest::with_base_and_path(
            Method::Get,
            &format!("https://localhost:{origin_port}"),
            &path,
        )
        .unwrap();
        let response = client.send(request).await.unwrap();
        assert_eq!(response.status(), 200);
    });
}

/// Self-signed `localhost` certificate PEM and a server config presenting it.
///
/// The provider is named explicitly: under `cargo test --workspace` more than
/// one rustls provider is enabled and auto-detection panics.
fn tls_material() -> (String, rustls::ServerConfig) {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key_der)
        .unwrap();
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    (cert.pem(), server_config)
}

async fn bind_local() -> (tokio::net::TcpListener, u16) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

/// Read a request head off a stream, up to and including the blank line.
async fn read_head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut seen = Vec::new();
    let mut byte = [0u8; 1];
    while stream.read_exact(&mut byte).await.is_ok() {
        seen.push(byte[0]);
        if seen.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&seen).into_owned()
}

/// Answer every TLS request with an empty `200 OK`.
fn serve_origin(listener: tokio::net::TcpListener, server_config: rustls::ServerConfig) {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                read_head(&mut tls).await;
                let _ = tls
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = tls.flush().await;
            });
        }
    });
}

/// Count connections and never answer them.
fn count_dials(listener: tokio::net::TcpListener, dials: Arc<AtomicUsize>) {
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            dials.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
}

/// A minimal CONNECT proxy: record the request head, then tunnel to the
/// `host:port` it names.
fn serve_connect_proxy(listener: tokio::net::TcpListener, heads: Arc<Mutex<Vec<String>>>) {
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let heads = Arc::clone(&heads);
            tokio::spawn(async move {
                let head = read_head(&mut client).await;
                heads.lock().unwrap().push(head.clone());
                let Some(target) = head
                    .strip_prefix("CONNECT ")
                    .and_then(|rest| rest.split(' ').next())
                else {
                    return;
                };
                let Ok(mut upstream) = tokio::net::TcpStream::connect(target).await else {
                    return;
                };
                let _ = client
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
}
