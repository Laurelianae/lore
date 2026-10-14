// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use jsonwebtoken::TokenData;
use lore_base::lore_debug;
use lore_error_set::prelude::*;
use serde::Deserialize;
use serde_with::OneOrMany;
use serde_with::formats::PreferMany;
use serde_with::serde_as;

use crate::token_store::IdentityToken;

#[derive(Debug, Default, Clone)]
pub struct UserInfo {
    pub id: String,
    pub name: String,
    pub token: String,
    pub preferred_username: String,
    pub is_service_account: bool,
    pub expires: u64,
}

// An AuthN or an AuthZ token
#[serde_as]
#[derive(Debug, Deserialize, Clone)]
pub struct JWTUserInfo {
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "sub")]
    pub user_id: String,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub is_service_account: Option<bool>,
    #[serde(rename = "exp")]
    pub expires: u64,
    #[serde_as(as = "OneOrMany<_, PreferMany>")]
    #[serde(rename = "aud")]
    pub audience: Vec<String>,
    /// The root domains the issuer granted, tried before `aud` (D5).
    #[serde(default)]
    pub root_domains: Option<Vec<String>>,
    /// The namespaced alias of `root_domains`, for providers that require
    /// namespaced custom claims (D5).
    #[serde(rename = "https://lore.org/claims/root_domains", default)]
    pub namespaced_root_domains: Option<Vec<String>>,
}

impl JWTUserInfo {
    /// All the root domains this token is intended for, derived per the OIDC
    /// LEP's D5: the issuer's `root_domains` claim under its fixed name or
    /// its namespaced alias when either is present, else the `aud` entries
    /// that have a usable shape. The issuer's own URL is deliberately not
    /// part of the list; `store_user_token` appends the auth endpoint's
    /// domain, which keeps the fail-closed case (no usable source) working
    /// by sending the token back to the endpoint it came from only.
    pub fn acceptable_root_domains(&self) -> Vec<String> {
        for claim in [
            self.root_domains.as_ref(),
            self.namespaced_root_domains.as_ref(),
        ] {
            if let Some(domains) = claim
                && !domains.is_empty()
            {
                return domains.clone();
            }
        }
        self.audience
            .iter()
            .filter_map(|entry| audience_entry_root_domain(entry))
            .collect()
    }
}

/// The claim the issuer sets to name the root domains its tokens may be
/// sent to (D5). Fixed, so nothing in an attacker-controlled environment
/// response can point the client at a different claim.
pub const ROOT_DOMAINS_CLAIM: &str = "root_domains";

/// The namespaced alias of [`ROOT_DOMAINS_CLAIM`], for providers that
/// require namespaced custom claims (D5).
pub const NAMESPACED_ROOT_DOMAINS_CLAIM: &str = "https://lore.org/claims/root_domains";

/// One `aud` entry's contribution to the root-domain list (D5): the host of
/// an `https` URI, or a domain-shaped entry as a suffix. An opaque
/// identifier such as `lore-api` contributes nothing.
pub fn audience_entry_root_domain(entry: &str) -> Option<String> {
    if let Ok(url) = url::Url::parse(entry) {
        return if url.scheme() == "https" {
            url.host_str().map(str::to_string)
        } else {
            None
        };
    }
    let entry = entry.strip_prefix('.').unwrap_or(entry);
    if entry.is_empty() || !entry.contains('.') {
        return None;
    }
    let label_shaped = entry.split('.').all(|label| {
        !label.is_empty()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    label_shaped.then(|| format!(".{entry}"))
}

pub async fn user_info<P>(
    auth_url: &str,
    identity: &str,
    token_filter: P,
    identity_token: &str,
    access_token: &str,
) -> Option<UserInfo>
where
    P: FnMut(&&IdentityToken) -> bool,
{
    lore_debug!("Get user {identity} info from {auth_url}");

    let Ok(token) = crate::token_store::load_user_token(
        auth_url,
        identity,
        token_filter,
        identity_token,
        access_token,
    )
    .await
    else {
        return None;
    };

    user_info_from_token(token)
}

pub fn identity_from_token(token: &str) -> String {
    user_info_from_token(token.to_string())
        .map(|info| info.id)
        .unwrap_or_default()
}

pub fn insecure_decode_token(
    token: &str,
) -> Result<TokenData<JWTUserInfo>, jsonwebtoken::errors::Error> {
    let header = jsonwebtoken::decode_header(token)?;
    let key = jsonwebtoken::DecodingKey::from_secret(&[]);
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.insecure_disable_signature_validation();
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.validate_nbf = false;
    jsonwebtoken::decode::<JWTUserInfo>(token, &key, &validation)
}

pub fn user_info_from_token(token: String) -> Option<UserInfo> {
    let Ok(token_data) = insecure_decode_token(&token) else {
        return None;
    };
    Some(UserInfo {
        id: token_data.claims.user_id.clone(),
        name: token_data.claims.name.clone().unwrap_or_default(),
        token,
        preferred_username: token_data.claims.preferred_username.unwrap_or_default(),
        is_service_account: token_data.claims.is_service_account.unwrap_or_default(),
        // JWT has number of seconds since UNIX epoch in UTC - we want milliseconds like
        // all other timestamps in Lore, also in UTC
        expires: token_data.claims.expires * 1000,
    })
}

#[error_set]
pub enum JwtUsageError {}

pub fn domain_in_root_domains(domain: &str, root_domains: &[String]) -> bool {
    root_domains.iter().any(|acceptable_root| {
        // Require a label boundary, not a raw suffix, so `epicgames.net`
        // rejects a look-alike such as `evilepicgames.net`. A leading `.`
        // is optional and does not change the match.
        let apex = acceptable_root.strip_prefix('.').unwrap_or(acceptable_root);
        domain == apex || domain.ends_with(&format!(".{apex}"))
    })
}

pub fn verify_jwt_usage_for_remote(
    jwt: &JWTUserInfo,
    remote_domain: &str,
) -> Result<(), JwtUsageError> {
    let root_domains = jwt.acceptable_root_domains();
    if domain_in_root_domains(remote_domain, &root_domains) {
        return Ok(());
    }

    lore_debug!(
        "JWT acceptable domains '{root_domains:?}' does not contain '{remote_domain}' - forbidding JWT leak"
    );
    Err(JwtUsageError::internal(format!(
        "JWT 'aud' does not specify remote domain '{remote_domain}'"
    )))
}
