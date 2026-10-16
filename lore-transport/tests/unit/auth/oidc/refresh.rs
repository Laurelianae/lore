// SPDX-FileCopyrightText: 2026 Laurelianae
// SPDX-License-Identifier: MIT
//! The refresh grant: a one-time rotation the exchange wiring persists, and a spent
//! token's refusal.
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use lore_transport::Authentication;
use lore_transport::auth::oidc;
use lore_transport::auth::oidc::OidcAuthentication;
use lore_transport::types::AuthSessionPoll;
use lore_transport::types::Oidc;

use super::provider::*;

const CLIENT_ID: &str = "lore-client";

fn oidc(issuer: &str) -> Oidc {
    Oidc {
        issuer: issuer.to_owned(),
        client_id: CLIENT_ID.to_owned(),
        scopes: vec!["openid".to_owned()],
        ..Default::default()
    }
}

/// A provider whose token endpoint mints a fresh access token and a one-time refresh
/// token per grant, refusing any refresh token presented a second time. The device
/// grant and the refresh grant share the endpoint, so one counter spans both.
async fn rotating_provider() -> RecordingProvider {
    let counter = Arc::new(AtomicUsize::new(0));
    let used = Arc::new(Mutex::new(Vec::<String>::new()));
    spawn_recording_provider(move |issuer, request, _| {
        if request.path == "/token" {
            let form = request.form();
            let mut used = used.lock().unwrap();
            if let Some(refresh_token) = form.get("refresh_token") {
                // The token endpoint can only tell an already-presented refresh
                // token from a live one: the device grant minted the live set.
                if used.contains(refresh_token) {
                    return (
                        StatusCode::BAD_REQUEST,
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        serde_json::json!({"error": "invalid_grant"}).to_string(),
                    )
                        .into_response();
                }
            }
            if let Some(refresh_token) = form.get("refresh_token") {
                used.push(refresh_token.clone());
            }
            let refresh = format!("refresh-{}", counter.fetch_add(1, Ordering::SeqCst));
            return json(&serde_json::json!({
                "access_token": access_token(issuer, "user-1", "User One"),
                "token_type": "Bearer",
                "expires_in": 300,
                "refresh_token": refresh,
                "scope": "openid offline_access",
            }));
        }
        if request.path == "/device" {
            return json(&serde_json::json!({
                "device_code": "device-code-1",
                "user_code": "WDJB-MJHT",
                "verification_uri": format!("{issuer}/activate"),
                "expires_in": 600,
                "interval": 7,
                "verification_uri_complete": format!("{issuer}/activate?user_code=WDJB-MJHT"),
            }));
        }
        conforming(issuer, 0)
    })
    .await
}

/// A completed device grant, whose refresh token the store has not yet seen.
async fn login(provider: &RecordingProvider) -> String {
    let endpoint = oidc::endpoint(&provider.issuer);
    let backend = OidcAuthentication::new(oidc(&provider.issuer));
    let session = backend
        .start_auth_session(&endpoint, "client-state", "corr")
        .await
        .expect("the session opens");
    let AuthSessionPoll::Complete(token) = backend
        .poll_auth_session(&endpoint, "client-state", &session.session_code, "corr")
        .await
        .expect("the approved session completes")
    else {
        panic!("an approved session must complete");
    };
    token
        .refresh_token
        .expect("the device grant issued a refresh token")
}

#[tokio::test]
async fn refresh_issues_a_new_token_and_rotates_the_refresh_token_once() {
    let provider = rotating_provider().await;
    let endpoint = oidc::endpoint(&provider.issuer);
    let backend = OidcAuthentication::new(oidc(&provider.issuer));
    let first_refresh = login(&provider).await;

    let refreshed = backend
        .refresh_authentication(&endpoint, &first_refresh, "corr")
        .await
        .expect("the refresh grant succeeds");
    assert_eq!(refreshed.user_id, "user-1");
    let rotated = refreshed
        .refresh_token
        .expect("the refresh grant rotates its token");
    assert_ne!(rotated, first_refresh, "the refresh token is one-time");

    // The old token is consumed: presenting it again is an invalid_grant.
    let error = backend
        .refresh_authentication(&endpoint, &first_refresh, "corr")
        .await
        .expect_err("a spent refresh token is refused");
    assert!(error.to_string().contains("invalid_grant"), "{error}");

    // The rotation itself is usable once.
    backend
        .refresh_authentication(&endpoint, &rotated, "corr")
        .await
        .expect("the rotated refresh token works once");
}

/// The refresh grant asks for the server's default scopes plus `offline_access`, so the
/// rotated token keeps the scopes the login asked for.
#[tokio::test]
async fn the_refresh_grant_carries_the_client_and_the_scopes() {
    let provider = rotating_provider().await;
    let endpoint = oidc::endpoint(&provider.issuer);
    let backend = OidcAuthentication::new(oidc(&provider.issuer));
    let first_refresh = login(&provider).await;

    backend
        .refresh_authentication(&endpoint, &first_refresh, "corr")
        .await
        .expect("the refresh grant succeeds");

    let requests = provider.requests_to("/token");
    let refreshes: Vec<&Received> = requests
        .iter()
        .filter(|request| request.form().contains_key("refresh_token"))
        .collect();
    assert_eq!(refreshes.len(), 1);
    let form = refreshes[0].form();
    assert_eq!(form.get("client_id").map(String::as_str), Some(CLIENT_ID));
    assert_eq!(
        form.get("scope").map(String::as_str),
        Some("openid offline_access"),
    );
}
