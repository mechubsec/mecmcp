//! A real TLS handshake through `serve_router`'s axum-server listener.
//!
//! The other integration tests pass `tls: None`, and the `tls` module's own
//! tests handshake against a bare `TlsAcceptor`, so nothing else would notice
//! a dependency bump breaking the `Some(config)` path of the listener.

use std::sync::Arc;

use mecmcp_auth::NoGrant;
use mecmcp_transport::test_harness::{ServedPlan, serve_on_loopback_tls};
use mecmcp_transport::{
    HostOriginPolicy, HttpTransportConfig, LimitsConfig, NoAuthAcknowledgement, TransportIdentity,
    build_streamable_http_router, load_tls,
};
use rmcp::ServerHandler;
use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct TestServer;

impl ServerHandler for TestServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("test-server", "0.1"))
    }
}

/// The TLS listener completes a handshake and serves HTTP over it.
#[tokio::test]
async fn tls_listener_completes_handshake_and_serves_http() {
    let issued =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("self signed");
    let directory = tempfile::tempdir().expect("tempdir");
    let cert_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    std::fs::write(&cert_path, issued.cert.pem()).expect("cert");
    std::fs::write(&key_path, issued.signing_key.serialize_pem()).expect("key");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).expect("mode");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = load_tls(&cert_path, &key_path, provider).expect("TLS config");

    let shutdown = CancellationToken::new();
    let config = HttpTransportConfig::<NoGrant>::unauthenticated(
        TransportIdentity::new("testmcp", "test", "test", ["device"]),
        LimitsConfig::default(),
        HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
        shutdown.clone(),
        NoAuthAcknowledgement::operator_allowed_no_auth(),
    );
    let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(TestServer), config)
        .expect("router build failed");

    // Keep the bound listener: re-binding a released port races other tests.
    let ServedPlan { address, serving } = serve_on_loopback_tls(plan, server_config).await;

    let mut roots = rustls::RootCertStore::empty();
    roots.add(issued.cert.der().clone()).expect("trust anchor");
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .expect("TLS handshake through the axum-server listener");

    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    let mut response = Vec::new();
    // A missing close_notify makes read_to_end error; the status line is enough.
    let _ = tls.read_to_end(&mut response).await;
    assert!(
        response.starts_with(b"HTTP/1.1 "),
        "expected an HTTP response over TLS, got {:?}",
        String::from_utf8_lossy(&response)
    );

    shutdown.cancel();
    serving
        .await
        .expect("serving task failed")
        .expect("serve_router failed");
}
