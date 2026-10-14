// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! The RFC 8628 device grant against the server-advertised issuer, the
//! `refresh_token` grant, and the RFC 8693 exchange that mints
//! partition-scoped tokens.
//!
//! This module is the client's only new HTTP surface: every request goes to
//! an endpoint read from a discovery document, which checks every URL it
//! hands out for `https` (or loopback `http`).

use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lore_base::lore_spawn_net;
use lore_base::lore_warn;
use lore_base::types::RepositoryId;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use tokio_util::task::AbortOnDropHandle;

use crate::auth::oidc::MAX_RESPONSE_BYTES;
use crate::auth::oidc::body_excerpt;
use crate::auth::oidc::discovery::discover;
use crate::auth::oidc::http_client;
use crate::auth::oidc::is_permitted_url;
use crate::error::ProtocolError;
use crate::traits::Authentication;
use crate::types::AuthSession;
use crate::types::AuthSessionPoll;
use crate::types::AuthenticationToken;
use crate::types::AuthorizationToken;
use crate::types::Oidc;

/// The device grant, as RFC 8628 §3.4 names it on the token endpoint.
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The RFC 8693 §2.1 token-exchange grant.
const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// The RFC 8693 token type an access token is requested as and presented as.
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// The Lore API-key token type (LEP:620), the `subject_token_type` the
/// `api-key` alias names.
const API_KEY_TOKEN_TYPE: &str = "urn:lore:params:oauth:token-type:api-key";

/// The scope requested on every device and refresh grant, on top of the
/// scopes the server advertises: a credential that dies when the user
/// closes their browser would send people back through login far more often
/// than the token store does (LEP:600).
const OFFLINE_ACCESS_SCOPE: &str = "offline_access";

/// The poll interval RFC 8628 §3.2 lets the provider omit; the client then
/// polls every five seconds.
const DEFAULT_POLL_INTERVAL: u64 = 5;

/// The OIDC path's `Authentication` backend: one instance per issuer,
/// holding the advertisement the server sent in its environment. The
/// instance is registered under the issuer URL (`authentication::add_for_url`),
/// and the flow hands that same URL back as `auth_url` -- the issuer the
/// grants are requested from.
pub struct OidcAuthentication {
    advertisement: Oidc,
}

/// The RFC 8628 §3.2 device authorization response. Fields RFC marks
/// optional are optional here too.
#[derive(Debug, Deserialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    #[serde(default)]
    user_code: Option<String>,
    #[serde(default)]
    verification_uri: Option<String>,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    interval: Option<u64>,
}

/// The RFC 6749 §5.2 error response a token endpoint answers with.
#[derive(Debug, Deserialize)]
struct TokenErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// The RFC 6749 §5.1 success response, carrying what this client reads.
#[derive(Debug, Deserialize)]
struct TokenSuccessResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// A provider response: the status and the body, capped at
/// [`MAX_RESPONSE_BYTES`] like every other document read from a provider.
struct ProviderResponse {
    status: u16,
    body: String,
}

/// How an authorization exchange is answered (see
/// [`OidcAuthentication::exchange_mode`]).
enum ExchangeMode<'a> {
    /// Tier 1: the authentication token itself is the authorization token.
    Passthrough,
    /// Tier 2: mint a token at the exchange issuer, naming the partition as
    /// an RFC 8707 `resource` per the template.
    Resource { issuer: &'a str, template: &'a str },
    /// Tier 2: mint a token at the exchange issuer, naming the partition as
    /// a `scope` per the template.
    Scope { issuer: &'a str, template: &'a str },
}

impl OidcAuthentication {
    pub fn new(advertisement: Oidc) -> Self {
        Self { advertisement }
    }

    /// How an authorization exchange is answered, per the advertisement:
    /// Tier 1 (no exchange configuration) hands the authentication token
    /// on; Tier 2 (`token_exchange_issuer` plus exactly one of the two
    /// partition-naming templates) mints a scoped token at the exchange
    /// issuer. Any other combination is the misconfiguration the server's
    /// startup rule refuses -- named here rather than silently falling back
    /// to Tier 1, which would discard the least-privilege property the
    /// operator configured (D2).
    fn exchange_mode(&self) -> Result<ExchangeMode<'_>, ProtocolError> {
        let advertised_at = self.advertisement.issuer.as_str();
        let exchange_issuer = self.advertisement.token_exchange_issuer.as_deref();
        let resource = self.advertisement.resource_template.as_deref();
        let scope = self.advertisement.scope_template.as_deref();
        match (exchange_issuer, resource, scope) {
            (None, None, None) => Ok(ExchangeMode::Passthrough),
            (Some(issuer), Some(template), None) => Ok(ExchangeMode::Resource { issuer, template }),
            (Some(issuer), None, Some(template)) => Ok(ExchangeMode::Scope { issuer, template }),
            (Some(_), None, None) => Err(ProtocolError::internal(format!(
                "the OIDC advertisement for {advertised_at} sets token_exchange_issuer without a resource_template or scope_template"
            ))),
            (None, Some(_), None) => Err(ProtocolError::internal(format!(
                "the OIDC advertisement for {advertised_at} sets resource_template without token_exchange_issuer"
            ))),
            (None, None, Some(_)) => Err(ProtocolError::internal(format!(
                "the OIDC advertisement for {advertised_at} sets scope_template without token_exchange_issuer"
            ))),
            (Some(_), Some(_), Some(_)) => Err(ProtocolError::internal(format!(
                "the OIDC advertisement for {advertised_at} sets both resource_template and scope_template; exactly one may be set"
            ))),
            (None, Some(_), Some(_)) => Err(ProtocolError::internal(format!(
                "the OIDC advertisement for {advertised_at} sets both resource_template and scope_template without token_exchange_issuer"
            ))),
        }
    }

    /// The scopes requested at login and refresh: the server's advertised
    /// set plus `offline_access`, deduplicated in order.
    fn grant_scopes(&self) -> Vec<String> {
        let mut scopes = Vec::with_capacity(self.advertisement.scopes.len() + 1);
        for scope in &self.advertisement.scopes {
            if !scope.is_empty() && !scopes.contains(scope) {
                scopes.push(scope.clone());
            }
        }
        if !scopes.iter().any(|scope| scope == OFFLINE_ACCESS_SCOPE) {
            scopes.push(OFFLINE_ACCESS_SCOPE.to_string());
        }
        scopes
    }

    /// Maps a token-endpoint success response onto an `AuthenticationToken`.
    ///
    /// The access token is expected to be a JWT the issuer minted (the RFC
    /// 9068 profile): identity, expiry and root domains are read from its
    /// claims. The signature is not verified here -- the token has just
    /// arrived over TLS from the advertised issuer, and the server verifies
    /// what it receives (D8). A token that cannot be read fails closed with
    /// a naming error rather than logging anyone in under a guess.
    fn authentication_token(
        &self,
        granted: &TokenSuccessResponse,
        issuer: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        let claims = payload_claims(&granted.access_token, issuer)?;

        let identity_claim = self.advertisement.identity_claim();
        let user_id = claims
            .get(identity_claim)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ProtocolError::internal(format!(
                    "the access token from {issuer} carries no '{identity_claim}' claim"
                ))
            })?
            .to_string();
        let user_name = claims
            .get("name")
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                claims
                    .get("preferred_username")
                    .and_then(serde_json::Value::as_str)
            })
            .unwrap_or_default()
            .to_string();
        let expires_ms = match claims.get("exp").and_then(serde_json::Value::as_u64) {
            Some(exp) => exp.saturating_mul(1000),
            // No `exp` in the JWT: the token response's `expires_in`,
            // counted from now, is the only lifetime on offer.
            None => granted
                .expires_in
                .map(|secs| now_ms().saturating_add(secs.saturating_mul(1000)))
                .ok_or_else(|| {
                    ProtocolError::internal(format!(
                        "the access token from {issuer} carries no exp and the token response no expires_in"
                    ))
                })?,
        };

        Ok(AuthenticationToken {
            token: granted.access_token.clone(),
            user_id,
            user_name,
            expires_ms,
            acceptable_root_domains: acceptable_root_domains(&claims),
            refresh_token: granted.refresh_token.clone(),
            scope: granted.scope.clone(),
        })
    }

    /// Tier 1 passthrough: the grants live in the authentication token
    /// itself, read there by the server's `GlobalGrantsAuthorizer`, so the
    /// "exchange" hands the same token on. Used when the deployment
    /// configures no Tier 2 token-exchange issuer.
    fn authorization_token_passthrough(
        &self,
        authn_token: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        let issuer = self.advertisement.issuer.as_str();
        let claims = payload_claims(authn_token, issuer)?;
        let expires_ms = claims
            .get("exp")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ProtocolError::internal(format!(
                    "the authentication token from {issuer} carries no exp"
                ))
            })?
            .saturating_mul(1000);
        Ok(AuthorizationToken {
            token: authn_token.to_string(),
            expires_ms,
            acceptable_root_domains: acceptable_root_domains(&claims),
        })
    }

    /// The endpoint RFC 8693 grants go to: the configured exchange issuer
    /// when the advertisement names one, else the advertised issuer itself
    /// (providers implement the exchange grant at their token endpoint).
    fn exchange_endpoint(&self) -> &str {
        self.advertisement
            .token_exchange_issuer
            .as_deref()
            .unwrap_or(&self.advertisement.issuer)
    }

    /// Mints a token at `issuer` with the RFC 8693 exchange grant: the
    /// subject token is presented as `subject_token_type`, the minted token
    /// is requested as `requested_token_type`, and `extra` carries the
    /// partition naming (`resource` or `scope`, one per request, D3).
    async fn token_exchange(
        &self,
        issuer: &str,
        subject_token: &str,
        subject_token_type: &str,
        requested_token_type: &str,
        extra: &[(&str, &str)],
    ) -> Result<TokenSuccessResponse, ProtocolError> {
        let document = discover(issuer)
            .await
            .map_err(|err| ProtocolError::internal_with_context(err, "discovering the issuer"))?;

        let mut pairs = vec![
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", subject_token),
            ("subject_token_type", subject_token_type),
            ("requested_token_type", requested_token_type),
        ];
        pairs.extend_from_slice(extra);
        let body = form_encoded(&pairs);
        let response = post_form(document.token_endpoint.clone(), body).await?;

        if let Ok(error) = serde_json::from_str::<TokenErrorResponse>(&response.body) {
            return Err(ProtocolError::internal(format!(
                "token exchange failed: {}{}",
                error.error,
                error
                    .error_description
                    .as_deref()
                    .map(|description| format!(": {description}"))
                    .unwrap_or_default()
            )));
        }
        parse_json(&response, &document.token_endpoint)
    }

    /// Runs the RFC 8693 exchange and maps the minted token onto an
    /// `AuthorizationToken` from its claims: `exp` and the D5 derivation.
    async fn exchange_token(
        &self,
        issuer: &str,
        authn_token: &str,
        extra: &[(&str, &str)],
    ) -> Result<AuthorizationToken, ProtocolError> {
        let granted = self
            .token_exchange(
                issuer,
                authn_token,
                ACCESS_TOKEN_TYPE,
                ACCESS_TOKEN_TYPE,
                extra,
            )
            .await?;

        let claims = payload_claims(&granted.access_token, issuer)?;
        let expires_ms = claims
            .get("exp")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ProtocolError::internal(format!("the token minted at {issuer} carries no exp"))
            })?
            .saturating_mul(1000);
        Ok(AuthorizationToken {
            token: granted.access_token,
            expires_ms,
            acceptable_root_domains: acceptable_root_domains(&claims),
        })
    }
}

#[async_trait]
impl Authentication for OidcAuthentication {
    async fn start_auth_session(
        &self,
        auth_url: &str,
        _client_state: &str,
        _correlation_id: &str,
    ) -> Result<AuthSession, ProtocolError> {
        // `client_state` is a UCS Auth concept: its sessions are keyed by
        // it. An RFC 8628 session is keyed by the device code alone, so it
        // is ignored here.
        let document = discover(auth_url)
            .await
            .map_err(|err| ProtocolError::internal_with_context(err, "discovering the issuer"))?;
        // `token_endpoint` is mandatory in the discovery document and
        // checked there; the device endpoint is optional, so it is required
        // here, naming the issuer when absent.
        let device_endpoint = document
            .device_authorization_endpoint
            .as_deref()
            .ok_or_else(|| {
                ProtocolError::internal(format!(
                    "the OIDC provider at {auth_url} does not advertise a device_authorization_endpoint"
                ))
            })?;

        let body = form_encoded(&[
            ("client_id", self.advertisement.client_id.as_str()),
            ("scope", &self.grant_scopes().join(" ")),
        ]);
        let response = post_form(device_endpoint.to_string(), body).await?;
        let authorization: DeviceAuthorizationResponse = parse_json(&response, device_endpoint)?;

        let login_url = authorization
            .verification_uri_complete
            .as_deref()
            .or(authorization.verification_uri.as_deref())
            .ok_or_else(|| {
                ProtocolError::internal(format!(
                    "the OIDC provider at {auth_url} returned neither a verification_uri_complete nor a verification_uri for its device session"
                ))
            })?;
        check_login_url(login_url, auth_url)?;

        let expires_in = authorization.expires_in.ok_or_else(|| {
            ProtocolError::internal(format!(
                "the OIDC provider at {auth_url} returned no expires_in for its device session"
            ))
        })?;

        Ok(AuthSession {
            session_code: authorization.device_code,
            login_url: login_url.to_string(),
            // The code the user types at `login_url` from another machine.
            // Empty when the provider sends only a `verification_uri`
            // without a code -- `login_url` carries it in that case.
            user_code: authorization.user_code.unwrap_or_default(),
            interval: Duration::from_secs(authorization.interval.unwrap_or(DEFAULT_POLL_INTERVAL)),
            expires_in: Duration::from_secs(expires_in),
        })
    }

    async fn poll_auth_session(
        &self,
        auth_url: &str,
        _client_state: &str,
        session_code: &str,
        _correlation_id: &str,
    ) -> Result<AuthSessionPoll, ProtocolError> {
        let document = discover(auth_url)
            .await
            .map_err(|err| ProtocolError::internal_with_context(err, "discovering the issuer"))?;

        let body = form_encoded(&[
            ("grant_type", DEVICE_CODE_GRANT),
            ("device_code", session_code),
            ("client_id", self.advertisement.client_id.as_str()),
        ]);
        let response = post_form(document.token_endpoint.clone(), body).await?;

        // RFC 8628 §3.5: the pending answers arrive as RFC 6749 §5.2 errors.
        if let Ok(error) = serde_json::from_str::<TokenErrorResponse>(&response.body) {
            return match error.error.as_str() {
                "authorization_pending" => Ok(AuthSessionPoll::Pending),
                "slow_down" => Ok(AuthSessionPoll::SlowDown),
                "expired_token" => Err(ProtocolError::internal("login session expired")),
                "access_denied" => Err(ProtocolError::internal("login denied")),
                other => Err(ProtocolError::internal(format!(
                    "login failed: {}{}",
                    other,
                    error
                        .error_description
                        .as_deref()
                        .map(|description| format!(": {description}"))
                        .unwrap_or_default()
                ))),
            };
        }

        let granted: TokenSuccessResponse = parse_json(&response, &document.token_endpoint)?;
        Ok(AuthSessionPoll::Complete(
            self.authentication_token(&granted, auth_url)?,
        ))
    }

    async fn exchange_external_token(
        &self,
        _auth_url: &str,
        token: &str,
        token_type: &str,
        _correlation_id: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        let subject_token_type = subject_token_type(token_type, &self.advertisement.issuer)?;
        let granted = self
            .token_exchange(
                self.exchange_endpoint(),
                token,
                subject_token_type.as_str(),
                ACCESS_TOKEN_TYPE,
                &[],
            )
            .await?;
        self.authentication_token(&granted, &self.advertisement.issuer)
    }

    async fn refresh_authentication(
        &self,
        auth_url: &str,
        refresh_token: &str,
        _correlation_id: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        let document = discover(auth_url)
            .await
            .map_err(|err| ProtocolError::internal_with_context(err, "discovering the issuer"))?;

        let body = form_encoded(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", self.advertisement.client_id.as_str()),
            ("scope", &self.grant_scopes().join(" ")),
        ]);
        let response = post_form(document.token_endpoint.clone(), body).await?;

        if let Ok(error) = serde_json::from_str::<TokenErrorResponse>(&response.body) {
            // A refresh token already rotated out is answered `invalid_grant`;
            // so is a token the provider no longer accepts for any reason.
            return Err(ProtocolError::internal(format!(
                "token refresh failed: {}{}",
                error.error,
                error
                    .error_description
                    .as_deref()
                    .map(|description| format!(": {description}"))
                    .unwrap_or_default()
            )));
        }

        let granted: TokenSuccessResponse = parse_json(&response, &document.token_endpoint)?;
        self.authentication_token(&granted, auth_url)
    }

    async fn exchange_for_repository(
        &self,
        _auth_url: &str,
        authn_token: &str,
        repository: RepositoryId,
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        match self.exchange_mode()? {
            ExchangeMode::Passthrough => self.authorization_token_passthrough(authn_token),
            // One resource per request (D3): `{id}` in the template stands
            // for the partition ID.
            ExchangeMode::Resource { issuer, template } => {
                let resource = template.replace("{id}", &repository.to_string());
                self.exchange_token(issuer, authn_token, &[("resource", resource.as_str())])
                    .await
            }
            ExchangeMode::Scope { issuer, template } => {
                let scope = template.replace("{id}", &repository.to_string());
                self.exchange_token(issuer, authn_token, &[("scope", scope.as_str())])
                    .await
            }
        }
    }

    async fn exchange_for_custom_resource(
        &self,
        _auth_url: &str,
        authn_token: &str,
        resource_id: &str,
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        match self.exchange_mode()? {
            ExchangeMode::Passthrough => self.authorization_token_passthrough(authn_token),
            // Verbatim for non-partition callers (D2), whatever the
            // template mode: the caller owns any prefix convention.
            ExchangeMode::Resource { issuer, .. } | ExchangeMode::Scope { issuer, .. } => {
                self.exchange_token(issuer, authn_token, &[("resource", resource_id)])
                    .await
            }
        }
    }
}

/// Maps a `--token-type` name to an RFC 8693 `subject_token_type` (LEP
/// "API key login implemented as a token exchange"): `api-key` names the
/// Lore API-key token type, and a value already shaped `urn:...` passes
/// through verbatim. Any other short name is refused, naming what the path
/// understands -- a provider name the UCS auth service knew has no meaning
/// on the OIDC path.
fn subject_token_type(token_type: &str, issuer: &str) -> Result<String, ProtocolError> {
    match token_type {
        "api-key" => Ok(API_KEY_TOKEN_TYPE.to_string()),
        value if value.starts_with("urn:") => Ok(value.to_string()),
        other => Err(ProtocolError::internal(format!(
            "unsupported token type '{other}' for the OIDC path at {issuer}; use 'api-key' or a full 'urn:...' token type"
        ))),
    }
}

/// Checks the URL the user is asked to open, so a provider cannot hand the
/// client a URL that leaks a credential or leaves the https perimeter. The
/// URL itself is never echoed into the error: it is untrusted input.
fn check_login_url(login_url: &str, issuer: &str) -> Result<(), ProtocolError> {
    let url = url::Url::parse(login_url).map_err(|err| {
        ProtocolError::internal_with_context(
            err,
            "the device session returned a malformed verification URL",
        )
    })?;
    if !is_permitted_url(&url, true) {
        return Err(ProtocolError::internal(format!(
            "the OIDC provider at {issuer} returned a verification URL that is not https (or loopback http)"
        )));
    }
    Ok(())
}

/// The D5 derivation, applied to claims read off the wire as JSON: the
/// issuer's `root_domains` claim under its fixed name or its namespaced
/// alias when either is present, else the `aud` entries that have a usable
/// shape. This mirrors `JWTUserInfo::acceptable_root_domains` for a payload
/// the typed decode cannot carry (a custom identity claim or a missing
/// `exp`), sharing the claim names and the entry rule with it.
fn acceptable_root_domains(claims: &serde_json::Value) -> Vec<String> {
    for claim in [
        lore_credential::ROOT_DOMAINS_CLAIM,
        lore_credential::NAMESPACED_ROOT_DOMAINS_CLAIM,
    ] {
        if let Some(domains) = claims.get(claim).and_then(serde_json::Value::as_array) {
            let domains: Vec<String> = domains
                .iter()
                .filter_map(|entry| entry.as_str().map(str::to_string))
                .collect();
            if !domains.is_empty() {
                return domains;
            }
        }
    }
    match claims.get("aud") {
        Some(serde_json::Value::Array(entries)) => entries
            .iter()
            .filter_map(|entry| {
                entry
                    .as_str()
                    .and_then(lore_credential::audience_entry_root_domain)
            })
            .collect(),
        Some(serde_json::Value::String(entry)) => {
            lore_credential::audience_entry_root_domain(entry)
                .into_iter()
                .collect()
        }
        _ => Vec::new(),
    }
}

/// Parses a JWT's payload without verifying the signature.
fn payload_claims(token: &str, issuer: &str) -> Result<serde_json::Value, ProtocolError> {
    let payload = token.split('.').nth(1).ok_or_else(|| {
        ProtocolError::internal(format!(
            "the access token from {issuer} is not a JWT (no payload segment)"
        ))
    })?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|err| {
            ProtocolError::internal_with_context(
                err,
                &format!("the access token from {issuer} has a malformed payload"),
            )
        })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        ProtocolError::internal_with_context(
            err,
            &format!("the access token from {issuer} has a malformed payload"),
        )
    })
}

/// Serializes a form body, as the grants are sent (`application/x-www-form-urlencoded`,
/// RFC 6749 §2.3.1).
fn form_encoded(pairs: &[(&str, &str)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        serializer.append_pair(name, value);
    }
    serializer.finish()
}

/// POSTs `body` as a form to `endpoint` and returns the response. Runs on
/// the net runtime, where the pooled client's driver tasks live, so a
/// caller on a short-lived runtime leaves no request behind.
async fn post_form(endpoint: String, body: String) -> Result<ProviderResponse, ProtocolError> {
    AbortOnDropHandle::new(lore_spawn_net!(async move {
        let client = http_client()
            .map_err(|err| ProtocolError::internal_with_context(err, "building the HTTP client"))?;
        let mut response = client
            .post(endpoint.as_str())
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .send()
            .await
            .map_err(|err| {
                ProtocolError::internal_with_context(err, "the request to the provider failed")
            })?;
        let status = response.status().as_u16();
        let body = match super::discovery::read_capped_body(&mut response).await {
            Ok(Some(body)) => body,
            Ok(None) => {
                lore_warn!("The response from {endpoint} exceeds {MAX_RESPONSE_BYTES} bytes");
                return Err(ProtocolError::internal(format!(
                    "the response from {endpoint} exceeds {MAX_RESPONSE_BYTES} bytes"
                )));
            }
            Err(err) => {
                return Err(ProtocolError::internal_with_context(
                    err,
                    "reading the response from the provider failed",
                ));
            }
        };
        Ok(ProviderResponse {
            status,
            body: String::from_utf8_lossy(&body).into_owned(),
        })
    }))
    .await
    .map_err(|source| {
        ProtocolError::internal_with_context(source, "the provider request task failed")
    })?
}

/// Parses a provider response body as JSON, failing with the status and a
/// body excerpt when it is not.
fn parse_json<T: DeserializeOwned>(
    response: &ProviderResponse,
    endpoint: &str,
) -> Result<T, ProtocolError> {
    serde_json::from_str(&response.body).map_err(|err| {
        lore_warn!(
            "HTTP {} from {endpoint} is not the expected JSON: {}",
            response.status,
            body_excerpt(&response.body)
        );
        ProtocolError::internal_with_context(
            err,
            &format!(
                "HTTP {} from {endpoint} is not the expected JSON",
                response.status
            ),
        )
    })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
