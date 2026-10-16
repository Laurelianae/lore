// SPDX-FileCopyrightText: 2026 Laurelianae
// SPDX-License-Identifier: MIT
//! RFC 7009 revocation at the provider: the advertised endpoint receives the
//! token and its hint, a provider without one makes revocation a no-op, and a
//! failing answer is a reportable error.
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use lore_transport::Authentication;
use lore_transport::auth::oidc::OidcAuthentication;
use lore_transport::types::Oidc;

use super::provider::*;

fn oidc(issuer: &str) -> Oidc {
    Oidc {
        issuer: issuer.to_owned(),
        client_id: "lore-client".to_owned(),
        scopes: vec!["openid".to_owned()],
        ..Default::default()
    }
}

fn discovery(issuer: &str, advertise_revocation: bool) -> Response {
    let mut document = serde_json::json!({
        "issuer": issuer,
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "device_authorization_endpoint": format!("{issuer}/device"),
    });
    if advertise_revocation {
        document["revocation_endpoint"] = format!("{issuer}/revoke").into();
    }
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        document.to_string(),
    )
        .into_response()
}

#[tokio::test]
async fn the_revocation_endpoint_receives_the_token_and_hint() {
    let provider = spawn_recording_provider(|issuer, request, _| match request.path.as_str() {
        "/.well-known/openid-configuration" => discovery(issuer, true),
        "/revoke" => StatusCode::OK.into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    })
    .await;
    let backend = OidcAuthentication::new(oidc(&provider.issuer));

    backend
        .revoke_token(&provider.issuer, "refresh-1", "refresh_token", "")
        .await
        .expect("the advertised revocation endpoint answers 200");

    let revocations = provider.requests_to("/revoke");
    assert_eq!(revocations.len(), 1, "exactly one revocation is posted");
    let form = revocations[0].form();
    assert_eq!(form.get("token").map(String::as_str), Some("refresh-1"));
    assert_eq!(
        form.get("token_type_hint").map(String::as_str),
        Some("refresh_token"),
    );
    assert_eq!(form.get("client_id").map(String::as_str), Some("lore-client"));
}

#[tokio::test]
async fn a_provider_without_a_revocation_endpoint_makes_revocation_a_no_op() {
    let provider = spawn_recording_provider(|issuer, request, _| match request.path.as_str() {
        "/.well-known/openid-configuration" => discovery(issuer, false),
        _ => StatusCode::NOT_FOUND.into_response(),
    })
    .await;
    let backend = OidcAuthentication::new(oidc(&provider.issuer));

    backend
        .revoke_token(&provider.issuer, "refresh-1", "refresh_token", "")
        .await
        .expect("nothing advertised, nothing to call");

    assert!(
        provider.requests_to("/revoke").is_empty(),
        "no revocation may be posted without an advertised endpoint"
    );
}

#[tokio::test]
async fn a_failing_revocation_answer_is_an_error() {
    let provider = spawn_recording_provider(|issuer, request, _| match request.path.as_str() {
        "/.well-known/openid-configuration" => discovery(issuer, true),
        "/revoke" => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    })
    .await;
    let backend = OidcAuthentication::new(oidc(&provider.issuer));

    let error = backend
        .revoke_token(&provider.issuer, "refresh-1", "refresh_token", "")
        .await
        .expect_err("a failing revocation is a reportable failure");
    assert!(error.to_string().contains("HTTP 503"), "{error}");
}
