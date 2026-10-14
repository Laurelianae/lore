// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

/// The shared fake OIDC provider, included once for the whole binary:
/// including it in more than one submodule of the same test binary trips
/// `duplicate_mod`.
#[path = "../support/oidc_provider.rs"]
pub mod provider;

mod exchange;
mod mode;
mod oidc;
mod token_only;
mod ucs_auth;

use lore_transport::auth::*;

/// A scheme with no user service still resolves users: the
/// bearer from their token, everyone else as their ID.
#[tokio::test]
async fn an_unregistered_scheme_gets_the_token_only_service() {
    /// `{"iss":"lore","sub":"alice","name":"Alice","exp":2000000000,"aud":["example.com"]}`
    const ALICE_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJsb3JlIiwic3ViIjoiYWxpY2UiLCJuYW1lIjoiQWxpY2UiLCJleHAiOjIwMDAwMDAwMDAsImF1ZCI6WyJleGFtcGxlLmNvbSJdfQ.signature";
    const AUTH_URL: &str = "no-service-here://auth.test.invalid";

    let users = user_service::find(AUTH_URL)
        .get_user_info(
            AUTH_URL,
            ALICE_TOKEN,
            lore_base::types::RepositoryId::default(),
            &["alice".to_string(), "bob".to_string()],
            "corr",
        )
        .await
        .expect("the default service never fails");
    let names: Vec<&str> = users.iter().map(|u| u.user_name.as_str()).collect();
    assert_eq!(names, ["Alice", "bob"]);
}

/// The builtin schemes resolve through the auth service, exactly as
/// before the service was split from authentication.
#[test]
fn builtin_schemes_are_served_by_the_auth_service() {
    for scheme in lore_transport::auth::ucs_auth::SCHEMES {
        let auth_url = format!("{scheme}://auth.example.com");
        let service = user_service::find(&auth_url);
        let auth = authentication::find(&auth_url).expect("a builtin scheme");
        assert!(
            std::ptr::addr_eq(Arc::as_ptr(&service), Arc::as_ptr(&auth)),
            "scheme {scheme} should resolve users through the same auth service instance"
        );
    }
}

/// An instance registered for one exact URL wins over the scheme registry,
/// while other URLs on the same scheme keep the scheme implementation.
/// Overwriting a URL's instance hands the endpoint to the replacement, so a
/// refreshed advertisement wins.
#[test]
fn an_instance_registered_for_a_url_wins_over_the_scheme_registry() {
    let oidc_url = "https://oidc-registers-itself.example.com";
    let other_url = "https://other-host.example.com";
    let oidc =
        Arc::new(lore_transport::auth::oidc::backend::OidcAuthentication::new(Default::default()));

    authentication::add_for_url(oidc_url, oidc.clone());

    let found = authentication::find(oidc_url).expect("the instance is found by its URL");
    assert!(
        std::ptr::addr_eq(Arc::as_ptr(&found), Arc::as_ptr(&oidc)),
        "the exact URL must resolve to the registered instance"
    );

    // The same scheme elsewhere keeps the scheme implementation (`https`
    // falls back to the UCS auth service).
    let found = authentication::find(other_url).expect("the scheme fallback is found");
    assert!(
        !std::ptr::addr_eq(Arc::as_ptr(&found), Arc::as_ptr(&oidc)),
        "another URL on the same scheme must not get the instance"
    );

    // A replacement for the same URL takes over.
    let replacement =
        Arc::new(lore_transport::auth::oidc::backend::OidcAuthentication::new(Default::default()));
    authentication::add_for_url(oidc_url, replacement.clone());
    let found = authentication::find(oidc_url).expect("the replacement is found");
    assert!(
        std::ptr::addr_eq(Arc::as_ptr(&found), Arc::as_ptr(&replacement)),
        "the newest instance for a URL must win"
    );
}
