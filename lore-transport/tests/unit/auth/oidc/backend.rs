// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use lore_transport::Authentication;
use lore_transport::auth::oidc::backend::OidcAuthentication;
use lore_transport::types::AuthSessionPoll;
use lore_transport::types::Oidc;
use provider::*;

use super::super::provider;

fn oidc(issuer: &str) -> Oidc {
    Oidc {
        issuer: issuer.to_string(),
        client_id: "lore-client".to_string(),
        scopes: vec!["openid".to_string()],
        ..Default::default()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_millis() as u64
}

#[tokio::test]
async fn the_device_grant_completes_and_maps_the_token() {
    let idp = spawn_token_provider().await;
    let backend = OidcAuthentication::new(oidc(idp.issuer()));

    let session = backend
        .start_auth_session(idp.issuer(), "client-state", "")
        .await
        .expect("the session starts");
    assert_eq!(session.user_code, "WDJB-MJHT");
    assert_eq!(
        session.login_url,
        format!("{}/activate?user_code=WDJB-MJHT", idp.issuer())
    );
    assert_eq!(session.expires_in, Duration::from_secs(1800));
    assert_eq!(session.interval, Duration::from_secs(1));
    assert!(!session.session_code.is_empty());

    // Unapproved: pending, at the RFC 8628 cadence.
    let poll = backend
        .poll_auth_session(idp.issuer(), "client-state", &session.session_code, "")
        .await
        .expect("the poll answers");
    assert!(matches!(poll, AuthSessionPoll::Pending));

    idp.approve_device();
    let AuthSessionPoll::Complete(token) = backend
        .poll_auth_session(idp.issuer(), "client-state", &session.session_code, "")
        .await
        .expect("the approved session completes")
    else {
        panic!("an approved session must complete");
    };
    assert_eq!(token.user_id, "user-1");
    assert_eq!(token.user_name, "Ada Lovelace");
    // exp is now + 3600s; the token's exp was minted moments ago.
    assert!(token.expires_ms > now_ms() + Duration::from_secs(3500).as_millis() as u64);
    // The fake's `aud` is its loopback issuer: an http URI contributes
    // nothing, so the derivation is empty until a claim says otherwise.
    assert!(token.acceptable_root_domains.is_empty());
    assert_eq!(token.refresh_token.as_deref(), Some("refresh-0"));
    assert_eq!(token.scope.as_deref(), Some("openid offline_access"));
}

#[tokio::test]
async fn a_slow_down_answer_widens_the_next_poll() {
    let idp = spawn_token_provider().await;
    let backend = OidcAuthentication::new(oidc(idp.issuer()));
    let session = backend
        .start_auth_session(idp.issuer(), "", "")
        .await
        .expect("the session starts");

    idp.slow_down_device(1);
    let poll = backend
        .poll_auth_session(idp.issuer(), "", &session.session_code, "")
        .await
        .expect("the poll answers");
    assert!(matches!(poll, AuthSessionPoll::SlowDown));

    // The slow_down was consumed; the next poll is pending again.
    let poll = backend
        .poll_auth_session(idp.issuer(), "", &session.session_code, "")
        .await
        .expect("the poll answers");
    assert!(matches!(poll, AuthSessionPoll::Pending));
}

#[tokio::test]
async fn an_expired_session_and_a_denied_login_name_what_happened() {
    let idp = spawn_token_provider().await;
    let backend = OidcAuthentication::new(oidc(idp.issuer()));
    let session = backend
        .start_auth_session(idp.issuer(), "", "")
        .await
        .expect("the session starts");

    idp.expire_device();
    let error = backend
        .poll_auth_session(idp.issuer(), "", &session.session_code, "")
        .await
        .expect_err("an expired session is an error");
    assert!(
        error.to_string().contains("login session expired"),
        "{error}"
    );

    idp.deny_device();
    let error = backend
        .poll_auth_session(idp.issuer(), "", &session.session_code, "")
        .await
        .expect_err("a denied login is an error");
    assert!(error.to_string().contains("login denied"), "{error}");
}

#[tokio::test]
async fn a_provider_without_a_device_endpoint_names_the_issuer() {
    let idp = spawn_provider(|issuer, _| {
        provider::json(&serde_json::json!({
            "issuer": issuer,
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
        }))
    })
    .await;
    let backend = OidcAuthentication::new(oidc(&idp.issuer));

    let error = backend
        .start_auth_session(&idp.issuer, "", "")
        .await
        .expect_err("a provider without a device endpoint cannot start a session");
    assert!(
        error.to_string().contains(&idp.issuer),
        "{error} must name the issuer"
    );
}

#[tokio::test]
async fn refresh_issues_a_new_token_and_rotates_the_refresh_token_once() {
    let idp = spawn_token_provider().await;
    let backend = OidcAuthentication::new(oidc(idp.issuer()));
    let session = backend
        .start_auth_session(idp.issuer(), "", "")
        .await
        .expect("the session starts");
    idp.approve_device();
    let AuthSessionPoll::Complete(token) = backend
        .poll_auth_session(idp.issuer(), "", &session.session_code, "")
        .await
        .expect("completes")
    else {
        panic!("an approved session must complete");
    };
    let first_refresh = token.refresh_token.expect("the device grant issued one");

    let refreshed = backend
        .refresh_authentication(idp.issuer(), &first_refresh, "")
        .await
        .expect("the refresh grant succeeds");
    assert_eq!(refreshed.user_id, "user-1");
    let rotated = refreshed
        .refresh_token
        .expect("the refresh grant rotates its token");
    assert_ne!(rotated, first_refresh, "the refresh token is one-time");

    // The old token is consumed: presenting it again is an invalid_grant.
    let error = backend
        .refresh_authentication(idp.issuer(), &first_refresh, "")
        .await
        .expect_err("a spent refresh token is refused");
    assert!(error.to_string().contains("invalid_grant"), "{error}");

    // The rotation itself is usable once.
    backend
        .refresh_authentication(idp.issuer(), &rotated, "")
        .await
        .expect("the rotated refresh token works once");
}

#[tokio::test]
async fn the_identity_claim_names_what_the_server_advertised() {
    let idp = spawn_token_provider().await;
    idp.set_claims(serde_json::json!({ "oid": "custom-id" }));
    let advertisement = Oidc {
        identity_claim: Some("oid".to_string()),
        ..oidc(idp.issuer())
    };
    let backend = OidcAuthentication::new(advertisement);

    let session = backend
        .start_auth_session(idp.issuer(), "", "")
        .await
        .expect("the session starts");
    idp.approve_device();
    let AuthSessionPoll::Complete(token) = backend
        .poll_auth_session(idp.issuer(), "", &session.session_code, "")
        .await
        .expect("completes")
    else {
        panic!("an approved session must complete");
    };
    assert_eq!(token.user_id, "custom-id");
}

#[tokio::test]
async fn an_access_token_without_the_identity_claim_fails_closed() {
    let idp = spawn_token_provider().await;
    idp.set_claims(serde_json::json!({ "sub": serde_json::Value::Null }));
    let backend = OidcAuthentication::new(oidc(idp.issuer()));

    let session = backend
        .start_auth_session(idp.issuer(), "", "")
        .await
        .expect("the session starts");
    idp.approve_device();
    let error = backend
        .poll_auth_session(idp.issuer(), "", &session.session_code, "")
        .await
        .expect_err("a token without the identity claim cannot log anyone in");
    assert!(error.to_string().contains("'sub'"), "{error}");
}

#[tokio::test]
async fn an_opaque_access_token_is_refused_with_a_naming_error() {
    let idp = spawn_token_provider().await;
    idp.answer_opaque_tokens();
    let backend = OidcAuthentication::new(oidc(idp.issuer()));

    let session = backend
        .start_auth_session(idp.issuer(), "", "")
        .await
        .expect("the session starts");
    idp.approve_device();
    let error = backend
        .poll_auth_session(idp.issuer(), "", &session.session_code, "")
        .await
        .expect_err("an opaque token carries no claims to read");
    assert!(
        error.to_string().contains(idp.issuer()),
        "{error} must name the issuer"
    );
}

#[tokio::test]
async fn the_tier_1_exchange_hands_the_authentication_token_on() {
    let idp = spawn_token_provider().await;
    let backend = OidcAuthentication::new(oidc(idp.issuer()));
    let session = backend
        .start_auth_session(idp.issuer(), "", "")
        .await
        .expect("the session starts");
    idp.approve_device();
    let AuthSessionPoll::Complete(token) = backend
        .poll_auth_session(idp.issuer(), "", &session.session_code, "")
        .await
        .expect("completes")
    else {
        panic!("an approved session must complete");
    };

    let exchanged = backend
        .exchange_for_repository(idp.issuer(), &token.token, Default::default(), "")
        .await
        .expect("the Tier 1 exchange is a passthrough");
    assert_eq!(exchanged.token, token.token);
    assert_eq!(exchanged.expires_ms, token.expires_ms);

    let exchanged = backend
        .exchange_for_custom_resource(idp.issuer(), &token.token, "some-resource", "")
        .await
        .expect("the Tier 1 exchange is a passthrough");
    assert_eq!(exchanged.token, token.token);
}

#[tokio::test]
async fn root_domains_come_from_the_claim_or_shaped_aud_entries() {
    let idp = spawn_token_provider().await;
    idp.set_claims(serde_json::json!({
        "root_domains": [".granted.example.com"],
        "aud": ["https://lore.example.com", "lore-api"],
    }));
    let backend = OidcAuthentication::new(oidc(idp.issuer()));

    let session = backend
        .start_auth_session(idp.issuer(), "", "")
        .await
        .expect("the session starts");
    idp.approve_device();
    let AuthSessionPoll::Complete(token) = backend
        .poll_auth_session(idp.issuer(), "", &session.session_code, "")
        .await
        .expect("completes")
    else {
        panic!("an approved session must complete");
    };
    // The claim wins over the aud entries (D5 tries its sources in order).
    assert_eq!(token.acceptable_root_domains, vec![".granted.example.com"]);
}

#[tokio::test]
async fn a_missing_exp_falls_back_to_the_response_expires_in() {
    let idp = spawn_token_provider().await;
    idp.set_claims(serde_json::json!({ "exp": serde_json::Value::Null }));
    let backend = OidcAuthentication::new(oidc(idp.issuer()));

    let session = backend
        .start_auth_session(idp.issuer(), "", "")
        .await
        .expect("the session starts");
    idp.approve_device();
    let AuthSessionPoll::Complete(token) = backend
        .poll_auth_session(idp.issuer(), "", &session.session_code, "")
        .await
        .expect("completes")
    else {
        panic!("an approved session must complete");
    };
    let before = now_ms();
    let after = now_ms() + Duration::from_secs(3600).as_millis() as u64 + 5_000;
    assert!(
        token.expires_ms > before && token.expires_ms < after,
        "expires_ms {} is now + the response's expires_in",
        token.expires_ms
    );
}

/// The Tier 2 exchange sends the RFC 8693 grant to the exchange issuer,
/// naming the partition as an RFC 8707 resource substituted into the
/// template, and maps the minted token's claims onto the authorization.
#[tokio::test]
async fn the_tier_2_exchange_mints_a_resource_scoped_token() {
    let idp = spawn_token_provider().await;
    idp.set_claims(serde_json::json!({ "root_domains": [".example.com"] }));
    let advertisement = Oidc {
        token_exchange_issuer: Some(idp.issuer().to_string()),
        resource_template: Some("https://lore.example.com/partitions/{id}".to_string()),
        ..oidc(idp.issuer())
    };
    let backend = OidcAuthentication::new(advertisement);

    let repository: lore_base::types::RepositoryId = "00112233445566778899aabbccddeeff"
        .parse()
        .expect("a valid repository id");
    let exchanged = backend
        .exchange_for_repository(idp.issuer(), "the-authn-token", repository, "")
        .await
        .expect("the exchange mints a token");

    let exchange = idp.last_exchange();
    assert_eq!(
        exchange.get("grant_type").map(String::as_str),
        Some("urn:ietf:params:oauth:grant-type:token-exchange")
    );
    assert_eq!(
        exchange.get("subject_token").map(String::as_str),
        Some("the-authn-token")
    );
    assert_eq!(
        exchange.get("subject_token_type").map(String::as_str),
        Some("urn:ietf:params:oauth:token-type:access_token")
    );
    assert_eq!(
        exchange.get("requested_token_type").map(String::as_str),
        Some("urn:ietf:params:oauth:token-type:access_token")
    );
    assert_eq!(
        exchange.get("resource").map(String::as_str),
        Some("https://lore.example.com/partitions/00112233445566778899aabbccddeeff"),
        "the template's {{id}} is the partition ID"
    );
    assert_eq!(exchange.get("scope"), None);

    // The minted token is what comes back, with its claims mapped.
    assert_ne!(exchanged.token, "the-authn-token");
    assert_eq!(exchanged.acceptable_root_domains, vec![".example.com"]);
    assert!(exchanged.expires_ms > now_ms());
}

#[tokio::test]
async fn the_scope_template_names_the_partition_as_a_scope() {
    let idp = spawn_token_provider().await;
    let advertisement = Oidc {
        token_exchange_issuer: Some(idp.issuer().to_string()),
        scope_template: Some("partition:{id}".to_string()),
        ..oidc(idp.issuer())
    };
    let backend = OidcAuthentication::new(advertisement);

    let repository: lore_base::types::RepositoryId = "00112233445566778899aabbccddeeff"
        .parse()
        .expect("a valid repository id");
    backend
        .exchange_for_repository(idp.issuer(), "the-authn-token", repository, "")
        .await
        .expect("the exchange mints a token");

    let exchange = idp.last_exchange();
    assert_eq!(
        exchange.get("scope").map(String::as_str),
        Some("partition:00112233445566778899aabbccddeeff")
    );
    assert_eq!(exchange.get("resource"), None);
}

/// A custom resource is named verbatim, whatever the template mode: the
/// caller owns any prefix convention (D2).
#[tokio::test]
async fn the_custom_resource_exchange_names_the_resource_verbatim() {
    let idp = spawn_token_provider().await;
    let scoped = Oidc {
        token_exchange_issuer: Some(idp.issuer().to_string()),
        scope_template: Some("partition:{id}".to_string()),
        ..oidc(idp.issuer())
    };
    let backend = OidcAuthentication::new(scoped);
    backend
        .exchange_for_custom_resource(
            idp.issuer(),
            "the-authn-token",
            "some-prefix/resource-7",
            "",
        )
        .await
        .expect("the exchange mints a token");
    assert_eq!(
        idp.last_exchange().get("resource").map(String::as_str),
        Some("some-prefix/resource-7"),
    );

    // And in resource mode, still verbatim.
    let resource = Oidc {
        token_exchange_issuer: Some(idp.issuer().to_string()),
        resource_template: Some("https://lore.example.com/partitions/{id}".to_string()),
        ..oidc(idp.issuer())
    };
    let backend = OidcAuthentication::new(resource);
    backend
        .exchange_for_custom_resource(
            idp.issuer(),
            "the-authn-token",
            "some-prefix/resource-7",
            "",
        )
        .await
        .expect("the exchange mints a token");
    assert_eq!(
        idp.last_exchange().get("resource").map(String::as_str),
        Some("some-prefix/resource-7"),
    );
}

#[tokio::test]
async fn an_exchange_configuration_that_names_no_carrier_is_refused() {
    let idp = spawn_token_provider().await;
    // The issuer without a template.
    let backend = OidcAuthentication::new(Oidc {
        token_exchange_issuer: Some(idp.issuer().to_string()),
        ..oidc(idp.issuer())
    });
    let error = backend
        .exchange_for_repository(idp.issuer(), "t", Default::default(), "")
        .await
        .expect_err("an issuer without a template is a misconfiguration");
    assert!(
        error.to_string().contains("token_exchange_issuer"),
        "{error}"
    );

    // A template without the issuer.
    let backend = OidcAuthentication::new(Oidc {
        resource_template: Some("https://lore.example.com/partitions/{id}".to_string()),
        ..oidc(idp.issuer())
    });
    let error = backend
        .exchange_for_repository(idp.issuer(), "t", Default::default(), "")
        .await
        .expect_err("a template without an issuer is a misconfiguration");
    assert!(error.to_string().contains("resource_template"), "{error}");

    // Both templates.
    let backend = OidcAuthentication::new(Oidc {
        token_exchange_issuer: Some(idp.issuer().to_string()),
        resource_template: Some("https://lore.example.com/partitions/{id}".to_string()),
        scope_template: Some("partition:{id}".to_string()),
        ..oidc(idp.issuer())
    });
    let error = backend
        .exchange_for_repository(idp.issuer(), "t", Default::default(), "")
        .await
        .expect_err("both templates is a misconfiguration");
    assert!(error.to_string().contains("exactly one"), "{error}");
}

/// `--token-type api-key` becomes the Lore API-key `subject_token_type`; a
/// full `urn:...` passes through verbatim; an unknown short name is refused
/// naming the supported set.
#[tokio::test]
async fn the_external_token_exchange_maps_the_token_type() {
    let idp = spawn_token_provider().await;
    let backend = OidcAuthentication::new(oidc(idp.issuer()));

    let exchanged = backend
        .exchange_external_token(idp.issuer(), "the-api-key", "api-key", "")
        .await
        .expect("the api-key exchange mints an authentication token");
    let exchange = idp.last_exchange();
    assert_eq!(
        exchange.get("subject_token_type").map(String::as_str),
        Some("urn:lore:params:oauth:token-type:api-key"),
    );
    assert_eq!(
        exchange.get("subject_token").map(String::as_str),
        Some("the-api-key")
    );
    assert_eq!(
        exchange.get("requested_token_type").map(String::as_str),
        Some("urn:ietf:params:oauth:token-type:access_token")
    );
    assert_eq!(exchanged.user_id, "user-1");

    // A full token-type URI passes through verbatim.
    backend
        .exchange_external_token(
            idp.issuer(),
            "t",
            "urn:example:params:token-type:custom",
            "",
        )
        .await
        .expect("a urn: token type passes through");
    assert_eq!(
        idp.last_exchange()
            .get("subject_token_type")
            .map(String::as_str),
        Some("urn:example:params:token-type:custom"),
    );

    // A provider short name the UCS auth service knew has no meaning here.
    let error = backend
        .exchange_external_token(idp.issuer(), "t", "github", "")
        .await
        .expect_err("an unknown short name is refused");
    assert!(
        error.to_string().contains("'github'") && error.to_string().contains("api-key"),
        "{error}"
    );
}
