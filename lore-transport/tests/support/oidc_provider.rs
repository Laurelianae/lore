// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT

//! A stub OIDC provider for the discovery tests.
//!
//! Lives under `tests/support/` so cargo does not build it as a test target of its own; each
//! test binary pulls it in with `#[path]`.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use axum::Router;
use axum::http::StatusCode;
use axum::http::header;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tokio::net::TcpListener;
use tokio::sync::watch;

/// A provider on a loopback port. `respond` gets the issuer URL and the number of the
/// request, counted from zero, and answers every path.
pub struct Provider {
    pub issuer: String,
    pub requests: Arc<AtomicUsize>,
    /// Requests the provider is still answering. A request leaves when its response is sent
    /// or its client disconnects.
    pub in_flight: Arc<AtomicUsize>,
}

/// Counts a request in flight until dropped.
struct InFlight(Arc<AtomicUsize>);

impl InFlight {
    fn enter(count: &Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self(count.clone())
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub async fn spawn_provider(
    respond: impl Fn(&str, usize) -> Response + Clone + Send + Sync + 'static,
) -> Provider {
    spawn_gated_provider(watch::channel(true).1, respond).await
}

/// A provider that holds every response until `gate` turns true.
pub async fn spawn_gated_provider(
    gate: watch::Receiver<bool>,
    respond: impl Fn(&str, usize) -> Response + Clone + Send + Sync + 'static,
) -> Provider {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback port");
    let issuer = format!("http://{}", listener.local_addr().expect("local address"));
    let requests = Arc::new(AtomicUsize::new(0));
    let in_flight = Arc::new(AtomicUsize::new(0));

    let handler = {
        let issuer = issuer.clone();
        let requests = requests.clone();
        let in_flight = in_flight.clone();
        move || {
            let issuer = issuer.clone();
            let request = requests.fetch_add(1, Ordering::SeqCst);
            let respond = respond.clone();
            let mut gate = gate.clone();
            let in_flight = InFlight::enter(&in_flight);
            async move {
                let _in_flight = in_flight;
                gate.wait_for(|open| *open)
                    .await
                    .expect("gate sender alive");
                respond(&issuer, request)
            }
        }
    };
    let app = Router::new().fallback(get(handler));
    #[allow(clippy::disallowed_methods)] // Test-local server task.
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("serve the provider");
    });

    Provider {
        issuer,
        requests,
        in_flight,
    }
}

pub fn document(issuer: &str, endpoint_base: &str) -> serde_json::Value {
    serde_json::json!({
        "issuer": issuer,
        "token_endpoint": format!("{endpoint_base}/token"),
        "jwks_uri": format!("{endpoint_base}/jwks"),
        "device_authorization_endpoint": format!("{endpoint_base}/device"),
        "revocation_endpoint": format!("{endpoint_base}/revoke"),
        "end_session_endpoint": format!("{endpoint_base}/logout"),
    })
}

pub fn json(value: &serde_json::Value) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        value.to_string(),
    )
        .into_response()
}

pub fn conforming(issuer: &str, _request: usize) -> Response {
    json(&document(issuer, issuer))
}

pub async fn wait_until(condition: impl Fn() -> bool, what: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting: {what}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

pub async fn wait_for_requests(provider: &Provider, count: usize) {
    wait_until(
        || provider.requests.load(Ordering::SeqCst) >= count,
        "the provider to see the requests",
    )
    .await;
}

// ---------------------------------------------------------------------------
// A stateful fake: device codes, minted JWTs and one-time refresh tokens.
// ---------------------------------------------------------------------------

/// What a device session answers its polls with, until changed.
#[derive(Default)]
struct DeviceSession {
    device_code: String,
    /// `None`: pending. `Some(Ok(()))`: approved. `Some(Err(code))`: the
    /// RFC 8628 §3.5 error code the next polls answer with.
    verdict: Option<Result<(), &'static str>>,
    /// Pending `slow_down` answers, consumed one per poll.
    slow_downs: u32,
}

/// The state the fake token provider carries between requests.
pub struct FakeIdpState {
    device: DeviceSession,
    device_counter: u32,
    /// Live refresh tokens, consumed on use; a used one is gone.
    refresh_tokens: HashSet<String>,
    refresh_counter: u32,
    /// The most recent refresh token minted.
    last_refresh: Option<String>,
    /// Claims merged over the defaults of every minted access token.
    claims: serde_json::Value,
    /// Whether the token endpoint answers with an opaque access token.
    opaque_access_token: bool,
    /// Request params of the last token-exchange grant, for assertions.
    last_exchange: BTreeMap<String, String>,
    /// Request params of the last revocation request, for assertions.
    last_revocation: BTreeMap<String, String>,
    /// Whether discovery advertises the revocation endpoint.
    advertise_revocation: bool,
    /// Whether the revocation endpoint answers with a failure.
    fail_revocation: bool,
    /// Hits per endpoint path.
    hits: BTreeMap<String, usize>,
}

impl Default for FakeIdpState {
    fn default() -> Self {
        Self {
            device: DeviceSession::default(),
            device_counter: 0,
            refresh_tokens: HashSet::new(),
            refresh_counter: 0,
            last_refresh: None,
            claims: serde_json::Value::Null,
            opaque_access_token: false,
            last_exchange: BTreeMap::new(),
            last_revocation: BTreeMap::new(),
            // The conforming default: discovery advertises revocation.
            advertise_revocation: true,
            fail_revocation: false,
            hits: BTreeMap::new(),
        }
    }
}

impl FakeIdpState {
    fn hit(&mut self, path: &str) {
        *self.hits.entry(path.to_string()).or_default() += 1;
    }
}

/// A fake provider with the full grant surface the client exercises:
/// discovery, the device grant, minted JWTs and one-time refresh.
pub struct TokenProvider {
    pub provider: Provider,
    pub state: Arc<Mutex<FakeIdpState>>,
}

impl TokenProvider {
    pub fn issuer(&self) -> &str {
        &self.provider.issuer
    }

    /// Merges `claims` into every access token minted from now on, over the
    /// defaults (`iss`, `sub`, `name`, `exp`, `aud`). A claim set to
    /// `serde_json::Value::Null` overrides the default with null, which the
    /// client then reads as absent.
    pub fn set_claims(&self, claims: serde_json::Value) {
        self.state.lock().expect("state").claims = claims;
    }

    pub fn approve_device(&self) {
        self.state.lock().expect("state").device.verdict = Some(Ok(()));
    }

    /// The next `count` device polls answer `slow_down` before the verdict.
    pub fn slow_down_device(&self, count: u32) {
        self.state.lock().expect("state").device.slow_downs = count;
    }

    pub fn expire_device(&self) {
        self.state.lock().expect("state").device.verdict = Some(Err("expired_token"));
    }

    pub fn deny_device(&self) {
        self.state.lock().expect("state").device.verdict = Some(Err("access_denied"));
    }

    /// Makes the token endpoint hand out an opaque access token instead of
    /// a JWT.
    pub fn answer_opaque_tokens(&self) {
        self.state.lock().expect("state").opaque_access_token = true;
    }

    /// The refresh token the fake last minted.
    pub fn last_refresh_token(&self) -> Option<String> {
        self.state.lock().expect("state").last_refresh.clone()
    }

    /// How many requests hit the endpoint whose path ends with `suffix`.
    pub fn hits(&self, suffix: &str) -> usize {
        self.state
            .lock()
            .expect("state")
            .hits
            .iter()
            .filter(|(path, _)| path.ends_with(suffix))
            .map(|(_, count)| *count)
            .sum()
    }

    /// The form parameters of the last token-exchange grant.
    pub fn last_exchange(&self) -> BTreeMap<String, String> {
        self.state.lock().expect("state").last_exchange.clone()
    }

    /// The form parameters of the last revocation request.
    pub fn last_revocation(&self) -> BTreeMap<String, String> {
        self.state.lock().expect("state").last_revocation.clone()
    }

    /// Stops advertising `revocation_endpoint` in discovery.
    pub fn omit_revocation_endpoint(&self) {
        self.state.lock().expect("state").advertise_revocation = false;
    }

    /// Makes the revocation endpoint answer with a server failure.
    pub fn fail_revocation(&self) {
        self.state.lock().expect("state").fail_revocation = true;
    }
}

/// Spawns the stateful fake. Its discovery document is the conforming one:
/// token at `<issuer>/token`, device authorization at `<issuer>/device`.
pub async fn spawn_token_provider() -> TokenProvider {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback port");
    let issuer = format!("http://{}", listener.local_addr().expect("local address"));
    let requests = Arc::new(AtomicUsize::new(0));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let state = Arc::new(Mutex::new(FakeIdpState::default()));

    let handler_state = state.clone();
    let handler_issuer = issuer.clone();
    let handler_requests = requests.clone();
    let handler_in_flight = in_flight.clone();
    let app = Router::new().fallback(move |request: axum::extract::Request| {
        let state = handler_state.clone();
        let issuer = handler_issuer.clone();
        let requests = handler_requests.clone();
        let in_flight = handler_in_flight.clone();
        async move {
            let requests = requests.clone();
            let in_flight = in_flight.clone();
            requests.fetch_add(1, Ordering::SeqCst);
            let _in_flight = InFlight::enter(&in_flight);
            let (parts, body) = request.into_parts();
            let bytes = axum::body::to_bytes(body, 1024 * 1024)
                .await
                .unwrap_or_default();
            handle_token_request(&issuer, parts.uri.path(), &bytes, &state)
        }
    });
    #[allow(clippy::disallowed_methods)] // Test-local server task.
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("serve the token provider");
    });

    TokenProvider {
        provider: Provider {
            issuer,
            requests,
            in_flight,
        },
        state,
    }
}

fn handle_token_request(
    issuer: &str,
    path: &str,
    body: &[u8],
    state: &Arc<Mutex<FakeIdpState>>,
) -> Response {
    let mut state = state.lock().expect("state");
    match path {
        "/.well-known/openid-configuration" => {
            let mut document = document(issuer, issuer);
            if !state.advertise_revocation {
                document
                    .as_object_mut()
                    .expect("a discovery document is an object")
                    .remove("revocation_endpoint");
            }
            json(&document)
        }
        "/device" => {
            state.device.device_code = format!("dev-{}", state.device_counter);
            state.device_counter += 1;
            state.device.verdict = None;
            state.hit(path);
            json(&serde_json::json!({
                "device_code": state.device.device_code,
                "user_code": "WDJB-MJHT",
                "verification_uri": format!("{issuer}/activate"),
                "verification_uri_complete": format!("{issuer}/activate?user_code=WDJB-MJHT"),
                "expires_in": 1800,
                "interval": 1,
            }))
        }
        "/token" => {
            let params: HashMap<String, String> = url::form_urlencoded::parse(body)
                .map(|(k, v)| (k.into(), v.into()))
                .collect();
            match params.get("grant_type").map(String::as_str) {
                Some("urn:ietf:params:oauth:grant-type:device_code") => {
                    state.hit(path);
                    let code = params.get("device_code").cloned().unwrap_or_default();
                    if code != state.device.device_code {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "unknown device code",
                        );
                    }
                    if state.device.slow_downs > 0 {
                        state.device.slow_downs -= 1;
                        return error_response(StatusCode::BAD_REQUEST, "slow_down", "");
                    }
                    match state.device.verdict {
                        None => error_response(
                            StatusCode::BAD_REQUEST,
                            "authorization_pending",
                            "the user has not approved the session yet",
                        ),
                        Some(Ok(())) => token_response(issuer, &mut state),
                        Some(Err(code)) => error_response(StatusCode::BAD_REQUEST, code, ""),
                    }
                }
                Some("refresh_token") => {
                    state.hit(path);
                    let presented = params.get("refresh_token").cloned().unwrap_or_default();
                    if !state.refresh_tokens.remove(&presented) {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "the refresh token is one-time and has been used or was never issued",
                        );
                    }
                    token_response(issuer, &mut state)
                }
                Some("urn:ietf:params:oauth:grant-type:token-exchange") => {
                    state.hit(path);
                    state.last_exchange = params.into_iter().collect();
                    token_response(issuer, &mut state)
                }
                _ => error_response(StatusCode::BAD_REQUEST, "unsupported_grant_type", ""),
            }
        }
        "/revoke" => {
            state.hit(path);
            if state.fail_revocation {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            // RFC 7009 §2.2: the answer is a bare 200 even for an unknown
            // token; the body is empty.
            let params: HashMap<String, String> = url::form_urlencoded::parse(body)
                .map(|(k, v)| (k.into(), v.into()))
                .collect();
            state.last_revocation = params.into_iter().collect();
            StatusCode::OK.into_response()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Mints an access token and a one-time refresh token, as the device,
/// refresh and exchange grants all answer.
fn token_response(issuer: &str, state: &mut FakeIdpState) -> Response {
    let access = if state.opaque_access_token {
        "an-opaque-access-token".to_string()
    } else {
        mint_access_token(issuer, &state.claims)
    };
    let refresh = format!("refresh-{}", state.refresh_counter);
    state.refresh_counter += 1;
    state.refresh_tokens.insert(refresh.clone());
    state.last_refresh = Some(refresh.clone());
    json(&serde_json::json!({
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid offline_access",
    }))
}

fn error_response(status: StatusCode, code: &str, description: &str) -> Response {
    let mut body = serde_json::json!({ "error": code });
    if !description.is_empty() {
        body["error_description"] = serde_json::json!(description);
    }
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// Mints a JWT whose payload is `claims` merged over the standard defaults.
/// The signature is arbitrary: the client reads claims without verifying.
pub fn mint_access_token(issuer: &str, extra: &serde_json::Value) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs();
    let mut claims = serde_json::json!({
        "iss": issuer,
        "sub": "user-1",
        "name": "Ada Lovelace",
        "exp": now + 3600,
        "aud": [issuer],
    });
    if let (Some(base), Some(extra)) = (claims.as_object_mut(), extra.as_object()) {
        for (name, value) in extra {
            base.insert(name.clone(), value.clone());
        }
    }
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims serialize"));
    let signature = URL_SAFE_NO_PAD.encode([0u8; 32]);
    format!("{header}.{payload}.{signature}")
}
