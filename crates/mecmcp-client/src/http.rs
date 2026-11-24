//! The reqwest client and the per-call assertion wrapper around it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

/// Private `_meta` key naming the per-call slot a `tools/call` owns. It selects
/// a slot in [`AssertionClient`] (assertion header and oversize flag) and is
/// stripped before the request is sent.
pub(crate) const CALL_SLOT_KEY: &str = "mecmcp-client/call-slot";

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

/// One in-flight `tools/call`: its optional assertion and its oversize flag.
struct Slot {
    header: Option<HeaderValue>,
    oversize: Arc<AtomicBool>,
}

/// Handle to a registered slot. Dropping it frees the slot, however the call ends.
pub(crate) struct SlotGuard {
    client: AssertionClient,
    id: String,
    oversize: Arc<AtomicBool>,
}

impl SlotGuard {
    /// The id to place in the request's `params._meta`.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Whether rmcp refused an oversize SSE event for *this* call's request.
    pub(crate) fn saw_oversize(&self) -> bool {
        self.oversize.load(Ordering::Relaxed)
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.client.lock().remove(&self.id);
    }
}

/// Whether `error` is rmcp's "SSE event exceeded the maximum size" refusal.
/// rmcp keeps the error type private, so this matches its message; a unit test
/// pins the wording.
pub(crate) fn is_oversize_error(error: &SseError) -> bool {
    error.to_string().contains("exceeded the maximum size of")
}

fn slot_error() -> StreamableHttpError<reqwest::Error> {
    StreamableHttpError::Io(std::io::Error::other(
        "cannot attach per-call state to request",
    ))
}

/// `reqwest::Client` plus a table of per-call slots.
///
/// Every `tools/call` registers a slot and puts its unique id in its own
/// `params._meta`. The wrapper finds the id in the POST body, strips it, attaches
/// the slot's assertion header (if any) to that request only, and watches that
/// request's SSE stream so an oversize event is recorded on that slot alone.
/// Because the id travels with the request body, no ordering between concurrent
/// calls can move the header or the oversize verdict to another call, and
/// `initialize`/`discover`/`tools/list` never carry an id.
#[derive(Clone)]
pub(crate) struct AssertionClient {
    inner: reqwest::Client,
    slots: Arc<Mutex<HashMap<String, Slot>>>,
    next_slot: Arc<AtomicU64>,
}

impl AssertionClient {
    pub(crate) fn new(inner: reqwest::Client) -> Self {
        Self {
            inner,
            slots: Arc::default(),
            next_slot: Arc::default(),
        }
    }

    /// Register a call, optionally with an approver assertion.
    pub(crate) fn register(
        &self,
        assertion: Option<&OutboundSecret>,
    ) -> Result<SlotGuard, ClientError> {
        let header = assertion
            .map(|secret| {
                let mut value = HeaderValue::from_str(secret.expose())
                    .map_err(|_| ClientError::Config { field: "assertion" })?;
                value.set_sensitive(true);
                Ok(value)
            })
            .transpose()?;
        let id = self.next_slot.fetch_add(1, Ordering::Relaxed).to_string();
        let oversize = Arc::new(AtomicBool::new(false));
        self.lock().insert(
            id.clone(),
            Slot {
                header,
                oversize: oversize.clone(),
            },
        );
        Ok(SlotGuard {
            client: self.clone(),
            id,
            oversize,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Slot>> {
        self.slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Strip the slot marker from `message`, add that slot's header, and return
    /// the slot's oversize flag. A message without a marker passes untouched.
    #[allow(clippy::type_complexity)] // (rebuilt message, the slot's oversize flag); both POST paths destructure it
    fn apply_slot(
        &self,
        message: ClientJsonRpcMessage,
        headers: &mut HashMap<HeaderName, HeaderValue>,
    ) -> Result<(ClientJsonRpcMessage, Option<Arc<AtomicBool>>), StreamableHttpError<reqwest::Error>>
    {
        let mut json = serde_json::to_value(&message).map_err(|_| slot_error())?;
        let Some(meta) = json
            .pointer_mut("/params/_meta")
            .and_then(Value::as_object_mut)
        else {
            return Ok((message, None));
        };
        let Some(Value::String(id)) = meta.remove(CALL_SLOT_KEY) else {
            return Ok((message, None));
        };
        let (header, oversize) = {
            let slots = self.lock();
            let slot = slots.get(&id);
            (
                slot.and_then(|slot| slot.header.clone()),
                slot.map(|slot| slot.oversize.clone()),
            )
        };
        if let Some(header) = header {
            headers.insert(HeaderName::from_static("mecmcp-approver-assertion"), header);
        }
        // The marker must never leave the process: if the stripped body cannot
        // be rebuilt, fail the request rather than send it as it was.
        let rebuilt = serde_json::from_value(json).map_err(|_| slot_error())?;
        Ok((rebuilt, oversize))
    }
}

fn watch(
    response: StreamableHttpPostResponse,
    oversize: Option<Arc<AtomicBool>>,
) -> StreamableHttpPostResponse {
    match (response, oversize) {
        (StreamableHttpPostResponse::Sse(stream, session), Some(flag)) => {
            let stream = stream
                .inspect(move |item| {
                    if let Err(error) = item
                        && is_oversize_error(error)
                    {
                        flag.store(true, Ordering::Relaxed);
                    }
                })
                .boxed();
            StreamableHttpPostResponse::Sse(stream, session)
        }
        (response, _) => response,
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
        let (message, oversize) = self.apply_slot(message, &mut custom_headers)?;
        let response = self
            .inner
            .post_message(uri, message, session_id, auth_header, custom_headers)
            .await?;
        Ok(watch(response, oversize))
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
        let (message, oversize) = self.apply_slot(message, &mut custom_headers)?;
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
        Ok(watch(response, oversize))
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

#[cfg(test)]
#[allow(clippy::unwrap_used)] // tests
mod tests {
    use super::*;

    /// rmcp 3.10 words its oversize refusal exactly like this
    /// (`BoundedSseStreamError::EventTooLarge`); if a bump changes it, this and
    /// the `response_over_cap_is_rejected_while_streaming` integration test fail.
    #[test]
    fn recognises_rmcps_oversize_wording() {
        let error = SseError::Body(Box::new(std::io::Error::other(
            "SSE event exceeded the maximum size of 16 bytes",
        )));
        assert!(is_oversize_error(&error));
        let other = SseError::Body(Box::new(std::io::Error::other("connection reset")));
        assert!(!is_oversize_error(&other));
    }

    #[tokio::test]
    async fn oversize_is_attributed_to_the_slot_whose_stream_failed() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client = AssertionClient::new(reqwest::Client::new());
        let (first, second) = (
            client.register(None).unwrap(),
            client.register(None).unwrap(),
        );
        let failing = futures::stream::iter(vec![Err(SseError::Body(Box::new(
            std::io::Error::other("SSE event exceeded the maximum size of 16 bytes"),
        )))])
        .boxed();
        let flag = first.oversize.clone();
        let StreamableHttpPostResponse::Sse(mut stream, _) =
            watch(StreamableHttpPostResponse::Sse(failing, None), Some(flag))
        else {
            panic!("watch must keep an SSE response an SSE response");
        };
        while stream.next().await.is_some() {}
        assert!(first.saw_oversize());
        assert!(
            !second.saw_oversize(),
            "oversize leaked onto an unrelated call"
        );
    }
}
