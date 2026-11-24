//! The reqwest client and the per-call assertion wrapper around it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures::stream::{BoxStream, StreamExt};
use http::{HeaderName, HeaderValue};
use mecmcp_secret::OutboundSecret;
use rmcp::model::ClientJsonRpcMessage;
use rmcp::transport::streamable_http_client::{
    StreamableHttpClient, StreamableHttpError, StreamableHttpPostResponse,
};
use serde_json::Value;
use sse_stream::{Error as SseError, Sse};

use crate::{ClientConfig, ClientError};

/// Name of the header that carries the approver assertion. Duplicated from
/// `mecmcp-transport` on purpose (the client must not link it); `mecmcp-approve`
/// pins the two together.
pub const APPROVER_ASSERTION_HEADER: &str = "Mecmcp-Approver-Assertion";

/// Private `_meta` key marking which `tools/call` owns an assertion. It selects
/// a slot in [`AssertionClient`] and is stripped before the request is sent.
pub(crate) const ASSERTION_SLOT_KEY: &str = "mecmcp-client/assertion-slot";

/// Build the HTTP client: https only, no redirects, no proxy, HTTP/1.1; a
/// non-empty `ca_pem` replaces the root store (mirrors `mecmcp-http`).
pub(crate) fn build_reqwest_client(config: &ClientConfig) -> Result<reqwest::Client, ClientError> {
    // reqwest panics without a provider; report it instead.
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        return Err(ClientError::Tls(
            "no rustls CryptoProvider installed; call CryptoProvider::install_default() first"
                .to_owned(),
        ));
    }
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .http1_only()
        .no_proxy()
        .connect_timeout(config.connect_timeout);
    let mut roots = Vec::new();
    for pem in &config.ca_pem {
        let certs = reqwest::Certificate::from_pem_bundle(pem.as_bytes())
            .map_err(|_| ClientError::Tls("invalid ca_pem entry".to_owned()))?;
        if certs.is_empty() {
            return Err(ClientError::Tls(
                "ca_pem entry has no certificate".to_owned(),
            ));
        }
        roots.extend(certs);
    }
    if !roots.is_empty() {
        // `tls_certs_only`: a private CA pins the client, it does not add to the public roots.
        builder = builder.tls_certs_only(roots);
    }
    builder
        .build()
        .map_err(|_| ClientError::Tls("client build failed".to_owned()))
}

/// `reqwest::Client` plus a table of per-call assertions.
///
/// Concurrency: a call that carries an assertion puts a unique slot id in its
/// own `params._meta`; only a POST whose body holds a registered id gets the
/// header, and the id is removed from the body. Plain calls carry no id, so no
/// ordering between concurrent calls can move the header to the wrong request,
/// and `initialize`/`discover`/`tools/list` never carry one.
#[derive(Clone)]
pub(crate) struct AssertionClient {
    inner: reqwest::Client,
    slots: Arc<Mutex<HashMap<String, HeaderValue>>>,
    next_slot: Arc<AtomicU64>,
    /// Count of SSE events refused for exceeding the size cap.
    oversize_events: Arc<AtomicU64>,
}

impl AssertionClient {
    pub(crate) fn new(inner: reqwest::Client) -> Self {
        Self {
            inner,
            slots: Arc::default(),
            next_slot: Arc::default(),
            oversize_events: Arc::default(),
        }
    }

    /// Register `assertion`; returns the slot id to put in the request `_meta`.
    pub(crate) fn register(&self, assertion: &OutboundSecret) -> Result<String, ClientError> {
        let mut value = HeaderValue::from_str(assertion.expose())
            .map_err(|_| ClientError::Config { field: "assertion" })?;
        value.set_sensitive(true);
        let slot = self.next_slot.fetch_add(1, Ordering::Relaxed).to_string();
        self.lock().insert(slot.clone(), value);
        Ok(slot)
    }

    /// Drop a slot once its call has finished (success, error or timeout).
    pub(crate) fn release(&self, slot: &str) {
        self.lock().remove(slot);
    }

    /// How many oversize SSE events have been refused so far.
    pub(crate) fn oversize_events(&self) -> u64 {
        self.oversize_events.load(Ordering::Relaxed)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, HeaderValue>> {
        self.slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Strip the slot marker from `message` and add the header it selects.
    fn apply_slot(
        &self,
        message: ClientJsonRpcMessage,
        headers: &mut HashMap<HeaderName, HeaderValue>,
    ) -> ClientJsonRpcMessage {
        let Ok(mut json) = serde_json::to_value(&message) else {
            return message;
        };
        let Some(meta) = json
            .pointer_mut("/params/_meta")
            .and_then(Value::as_object_mut)
        else {
            return message;
        };
        let Some(Value::String(slot)) = meta.remove(ASSERTION_SLOT_KEY) else {
            return message;
        };
        let value = self.lock().get(&slot).cloned();
        if let Some(value) = value {
            headers.insert(HeaderName::from_static("mecmcp-approver-assertion"), value);
        }
        serde_json::from_value(json).unwrap_or(message)
    }

    fn watch(&self, response: StreamableHttpPostResponse) -> StreamableHttpPostResponse {
        let StreamableHttpPostResponse::Sse(stream, session) = response else {
            return response;
        };
        let counter = self.oversize_events.clone();
        let stream = stream
            .inspect(move |item| {
                if let Err(error) = item
                    && error.to_string().contains("maximum size of")
                {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            })
            .boxed();
        StreamableHttpPostResponse::Sse(stream, session)
    }
}

impl StreamableHttpClient for AssertionClient {
    type Error = reqwest::Error;

    async fn post_message(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        mut custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let message = self.apply_slot(message, &mut custom_headers);
        let response = self
            .inner
            .post_message(uri, message, session_id, auth_header, custom_headers)
            .await?;
        Ok(self.watch(response))
    }

    async fn post_message_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        mut custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let message = self.apply_slot(message, &mut custom_headers);
        let response = self
            .inner
            .post_message_with_max_sse_event_size(
                uri,
                message,
                session_id,
                auth_header,
                custom_headers,
                max_sse_event_size,
            )
            .await?;
        Ok(self.watch(response))
    }

    async fn delete_session(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), StreamableHttpError<Self::Error>> {
        self.inner
            .delete_session(uri, session_id, auth_header, custom_headers)
            .await
    }

    async fn get_stream(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, StreamableHttpError<Self::Error>> {
        self.inner
            .get_stream(uri, session_id, last_event_id, auth_header, custom_headers)
            .await
    }

    async fn get_stream_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, StreamableHttpError<Self::Error>> {
        self.inner
            .get_stream_with_max_sse_event_size(
                uri,
                session_id,
                last_event_id,
                auth_header,
                custom_headers,
                max_sse_event_size,
            )
            .await
    }
}
