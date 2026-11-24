//! A raw TLS stub MCP server that records every request, plus TLS material.
#![allow(dead_code, clippy::unwrap_used)] // test support

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use mecmcp_client::{BearerToken, ClientConfig};
use mecmcp_secret::OutboundSecret;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub const TOKEN: &str = "fake-test-token-0123456789"; // gitleaks:allow

/// One request as the stub saw it.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Value,
}

impl Seen {
    pub fn rpc_method(&self) -> &str {
        self.body["method"].as_str().unwrap_or("")
    }
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

/// What the stub does with a request.
pub enum Reply {
    Json(Value),
    Sse(Value),
    /// Extra response header line (`name: value`) then a JSON body.
    JsonWith(String, Value),
    Status(u16, Vec<(&'static str, String)>),
    /// Sleep, then reply.
    Delayed(Duration, Box<Reply>),
    /// Never-ending single SSE event (no blank line), `chunks` of 64 KiB.
    Flood {
        chunks: usize,
    },
    /// Hold the reply until the gate is notified (bounded at 5s), then send it.
    Gated(Arc<tokio::sync::Notify>, Box<Reply>),
}

pub type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

pub struct Stub {
    pub port: u16,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    /// Bytes the stub managed to write during `Reply::Flood`.
    pub flooded: Arc<AtomicUsize>,
    /// Notified (one stored permit) when a write during `Reply::Flood` fails,
    /// i.e. the server actually observed the client closing the connection.
    pub flood_write_failed: Arc<tokio::sync::Notify>,
    pub cert_pem: String,
}

impl Stub {
    pub fn url(&self) -> String {
        format!("https://localhost:{}/mcp", self.port)
    }
    pub fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
    pub fn calls(&self) -> Vec<Seen> {
        self.requests()
            .into_iter()
            .filter(|r| r.rpc_method() == "tools/call")
            .collect()
    }
}

pub fn install_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

pub fn tls_material() -> (String, Arc<rustls::ServerConfig>) {
    install_provider();
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key_der)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    (cert.pem(), Arc::new(config))
}

pub fn config_for(url: &str, cert_pem: &str) -> ClientConfig {
    install_provider();
    let token = BearerToken::from_secret(OutboundSecret::new_unchecked(TOKEN.to_owned()));
    let mut config = ClientConfig::new(url, token).unwrap();
    config.ca_pem = vec![cert_pem.to_owned()];
    config
}

pub async fn spawn(handler: Handler) -> Stub {
    let (cert_pem, server_config) = tls_material();
    spawn_with(handler, cert_pem, server_config).await
}

/// Spawn on a fresh port reusing TLS material (for the redirect target).
pub async fn spawn_with(
    handler: Handler,
    cert_pem: String,
    server_config: Arc<rustls::ServerConfig>,
) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let flooded = Arc::new(AtomicUsize::new(0));
    let flood_write_failed = Arc::new(tokio::sync::Notify::new());
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
    let (seen_task, flooded_task, failed_task) =
        (seen.clone(), flooded.clone(), flood_write_failed.clone());
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let (acceptor, handler, seen, flooded, failed) = (
                acceptor.clone(),
                handler.clone(),
                seen_task.clone(),
                flooded_task.clone(),
                failed_task.clone(),
            );
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(socket).await else {
                    return;
                };
                serve_one(&mut tls, handler, seen, flooded, failed).await;
            });
        }
    });
    Stub {
        port,
        seen,
        flooded,
        flood_write_failed,
        cert_pem,
    }
}

async fn serve_one<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    tls: &mut S,
    handler: Handler,
    seen: Arc<Mutex<Vec<Seen>>>,
    flooded: Arc<AtomicUsize>,
    write_failed: Arc<tokio::sync::Notify>,
) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        let Ok(read) = tls.read(&mut chunk).await else {
            return;
        };
        if read == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..read]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.lines();
    let method = lines
        .next()
        .unwrap_or("")
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_owned();
    let headers: HashMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + length {
        let Ok(read) = tls.read(&mut chunk).await else {
            return;
        };
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    let body: Value = serde_json::from_slice(&buf[head_end..]).unwrap_or(Value::Null);
    let request = Seen {
        method,
        headers,
        body,
    };
    seen.lock().unwrap().push(request.clone());
    let reply = handler(&request);
    write_reply(tls, reply, &flooded, &write_failed).await;
    let _ = tls.shutdown().await;
}

async fn write_reply<S: AsyncWriteExt + Unpin>(
    tls: &mut S,
    reply: Reply,
    flooded: &AtomicUsize,
    write_failed: &tokio::sync::Notify,
) {
    let reply = match reply {
        Reply::Gated(gate, inner) => {
            // Fail closed: if the gate never opens, drop the connection so the
            // held call errors and the test fails, rather than replying anyway.
            if tokio::time::timeout(Duration::from_secs(5), gate.notified())
                .await
                .is_err()
            {
                return;
            }
            *inner
        }
        Reply::Delayed(delay, inner) => {
            tokio::time::sleep(delay).await;
            *inner
        }
        other => other,
    };
    let raw = match reply {
        Reply::Json(value) => response(
            "200 OK",
            &["content-type: application/json"],
            &value.to_string(),
        ),
        Reply::JsonWith(extra, value) => response(
            "200 OK",
            &["content-type: application/json", extra.as_str()],
            &value.to_string(),
        ),
        Reply::Sse(value) => response(
            "200 OK",
            &["content-type: text/event-stream"],
            &format!("event: message\ndata: {value}\n\n"),
        ),
        Reply::Status(code, extra) => {
            let lines: Vec<String> = extra.iter().map(|(k, v)| format!("{k}: {v}")).collect();
            let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
            response(&format!("{code} Stub"), &refs, "")
        }
        Reply::Flood { chunks } => {
            let head = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n";
            if tls.write_all(head.as_bytes()).await.is_err() {
                return;
            }
            let payload = format!("data: {}", "a".repeat(64 * 1024 - 6));
            let framed = format!("{:x}\r\n{payload}\r\n", payload.len());
            for _ in 0..chunks {
                if tls.write_all(framed.as_bytes()).await.is_err() || tls.flush().await.is_err() {
                    write_failed.notify_one();
                    return;
                }
                flooded.fetch_add(payload.len(), Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            return;
        }
        Reply::Delayed(..) | Reply::Gated(..) => return,
    };
    let _ = tls.write_all(&raw).await;
}

fn response(status: &str, headers: &[&str], body: &str) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\n");
    for header in headers {
        out.push_str(header);
        out.push_str("\r\n");
    }
    out.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    ));
    out.into_bytes()
}

/// JSON-RPC result envelope for the request's id.
pub fn result_for(request: &Seen, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":request.body["id"],"result":result})
}

pub fn echo_result(text: &str) -> Value {
    json!({"content":[{"type":"text","text":text}],"structuredContent":{"echo":text},"isError":false})
}

/// A well-behaved 2026-07-28 stateless server: discover, list, echo.
pub fn modern_handler(sse: bool) -> Handler {
    Arc::new(move |request: &Seen| {
        if let Some(reply) = non_rpc(request) {
            return reply;
        }
        let wrap = |value: Value| {
            if sse {
                Reply::Sse(value)
            } else {
                Reply::Json(value)
            }
        };
        match request.rpc_method() {
            "server/discover" => wrap(result_for(
                request,
                json!({
                "resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},
                "ttlMs":0,"cacheScope":"private",
                "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"stub","version":"0"}}}),
            )),
            "tools/call" => wrap(result_for(request, echo_result("hi"))),
            _ => wrap(
                json!({"jsonrpc":"2.0","id":request.body["id"],"error":{"code":-32601,"message":"nope"}}),
            ),
        }
    })
}

/// GET stream, DELETE and id-less notifications: the answers every stub shares.
pub fn non_rpc(request: &Seen) -> Option<Reply> {
    match request.method.as_str() {
        "GET" => Some(Reply::Status(405, vec![])),
        "DELETE" => Some(Reply::Status(200, vec![])),
        _ if request.body.get("id").is_none() => Some(Reply::Status(202, vec![])),
        _ => None,
    }
}
