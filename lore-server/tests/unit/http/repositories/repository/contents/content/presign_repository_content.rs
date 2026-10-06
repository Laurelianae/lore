// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use lore_base::runtime::LORE_CONTEXT;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::http::security_headers::ContentTypePolicy;
use lore_server::http::server::LoreHttpServerSettings;
use lore_server::http::server::ServerHealth;
use lore_server::http::server::ServerState;
use lore_server::http::server::create_router;
use rand::random;
use serde_json::json;

use crate::http::test_utils::content_type_policy;
use crate::http::test_utils::presign_config_with_policy;
use crate::store::test_support::test_store_create;

async fn mint(body: serde_json::Value) -> axum_test::TestResponse {
    mint_with_policy(body, ContentTypePolicy::default()).await
}

/// Posts `body` to the mint endpoint of a server whose allowlist comes from
/// `policy`. The store is fresh, so the address does not exist and requests
/// that pass validation reach the existence check.
async fn mint_with_policy(
    body: serde_json::Value,
    policy: ContentTypePolicy,
) -> axum_test::TestResponse {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution, async move {
            let repository = random::<lore_revision::lore::RepositoryId>();
            let repo_hex = format!("{repository}");
            let address = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff-ffffffffffffffffffffffffffffffff";

            let test_health = ServerHealth::new_without_availability(immutable_store.clone());
            let state = ServerState {
                immutable_store,
                mutable_store,
                jwt_verifier: None,
                repository_authorizer: Arc::new(AllowAllRepositoryAuthorizer),
                max_file_size: 100,
                presign_config: Some(presign_config_with_policy(policy)),
            };
            let settings = LoreHttpServerSettings::test_default();
            let server =
                TestServer::new(create_router(state, test_health, &settings)).unwrap();

            server
                .post(&format!("/v1/repository/{repo_hex}/content/{address}/presign"))
                .json(&body)
                .await
        })
        .await
}

#[tokio::test]
async fn returns_404_when_address_not_found() {
    let response = mint(json!({"ttl_seconds": 3600})).await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

/// The S3 default type passes the allowlist, so it reaches the existence
/// check and returns 404 rather than 400.
#[tokio::test]
async fn accepts_s3_binary_octet_stream() {
    let response = mint(json!({"content_type": "binary/octet-stream"})).await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn returns_400_for_disallowed_content_type() {
    let response = mint(json!({"content_type": "text/html"})).await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

/// A type added through config passes the allowlist, so it reaches the
/// existence check and returns 404 rather than 400.
#[tokio::test]
async fn accepts_configured_extra_content_type() {
    let response = mint_with_policy(
        json!({"content_type": "application/zip"}),
        content_type_policy(&["application/zip"], &[]),
    )
    .await;

    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

/// A built-in type removed through config is rejected at mint.
#[tokio::test]
async fn returns_400_for_configured_denied_content_type() {
    let response = mint_with_policy(
        json!({"content_type": "application/pdf"}),
        content_type_policy(&[], &["application/pdf"]),
    )
    .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn returns_400_for_unserializable_header_value() {
    // Allowlisted media type, but a control char in the parameter makes it
    // an invalid header value; mint must reject rather than let redeem 500.
    let response = mint(json!({"content_type": "image/png; x=\u{7}"})).await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn presign_permission_matrix() {
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
    use lore_revision::lore::RepositoryId;
    use lore_server::auth::jwk::{JWKService, JWKServiceError};
    use lore_server::auth::jwt::JwtVerifier;
    use lore_server::authnz::global_grants_authorizer::GlobalGrantsAuthorizer;
    use lore_server::authnz::repository_authorizer::{RepositoryAuthorizer, VerifiedToken};
    use lore_server::authnz::resource_grants_authorizer::ResourceGrantsAuthorizer;
    use std::time::{SystemTime, UNIX_EPOCH};

    const SECRET: &[u8] = b"presign-permission-test-secret";
    struct Keys;
    #[async_trait::async_trait]
    impl JWKService for Keys {
        async fn get_key(&self, _kid: &str) -> Result<(DecodingKey, Algorithm), JWKServiceError> {
            Ok((DecodingKey::from_secret(SECRET), Algorithm::HS256))
        }
        fn get_cached_key(&self, _kid: &str) -> Option<(DecodingKey, Algorithm)> {
            Some((DecodingKey::from_secret(SECRET), Algorithm::HS256))
        }
        async fn refresh_key(
            &self,
            _kid: &str,
        ) -> Result<Option<(DecodingKey, Algorithm)>, JWKServiceError> {
            Ok(None)
        }
    }
    struct Policy {
        repository: RepositoryId,
        allowed: bool,
    }
    #[async_trait::async_trait]
    impl RepositoryAuthorizer for Policy {
        async fn check_repository_access(
            &self,
            token: Option<&VerifiedToken<'_>>,
            repository: RepositoryId,
            action: Option<&str>,
        ) -> Result<(), tonic::Status> {
            assert_eq!(repository, self.repository);
            assert!(!token.unwrap().raw.is_empty());
            if action.is_none() || (action == Some("presign") && self.allowed) {
                Ok(())
            } else {
                Err(tonic::Status::permission_denied("denied"))
            }
        }
    }

    for case in 0..10 {
        let (immutable_store, mutable_store, execution) = test_store_create().await.unwrap();
        LORE_CONTEXT
            .scope(execution, async move {
                let repository = random::<RepositoryId>();
                let (fragment, address, payload) = lore_revision::fragment::generate_random();
                immutable_store
                    .clone()
                    .put(repository, address, fragment, Some(payload), false)
                    .await
                    .unwrap();
                let allowed = matches!(case, 3 | 4 | 5 | 7);
                let mut claims = AuthorizationToken {
                    issuer: "issuer".into(),
                    user_id: "user".into(),
                    audience: vec!["lore-test".into()],
                    expires: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        + 60,
                    issued_at: 1,
                    ..Default::default()
                };
                let mut authorizer: Arc<dyn RepositoryAuthorizer> =
                    Arc::new(GlobalGrantsAuthorizer::new(Some("roles".into())));
                match case {
                    2 => claims.is_service_account = Some(true),
                    3 => claims.extra = json!({"roles": ["presign"]}).as_object().unwrap().clone(),
                    4..=6 => {
                        let resource = if case == 5 {
                            "all".into()
                        } else if case == 6 {
                            format!("repo-{}", random::<RepositoryId>())
                        } else {
                            format!("repo-{repository}")
                        };
                        claims.extra = json!({"access": {"entries": [
                        {"id": resource, "actions": []}, {"id": resource, "actions": ["presign"]}
                    ]}}).as_object().unwrap().clone();
                        authorizer = Arc::new(ResourceGrantsAuthorizer::new(
                            "access.entries".into(),
                            "id".into(),
                            Some("actions".into()),
                            "repo-{id}".into(),
                            "all".into(),
                        ));
                    }
                    7 | 8 => {
                        authorizer = Arc::new(Policy {
                            repository,
                            allowed,
                        });
                    }
                    9 => claims.extra = json!({"roles": ["admin"]}).as_object().unwrap().clone(),
                    _ => {}
                }
                let state = ServerState {
                    immutable_store: immutable_store.clone(),
                    mutable_store,
                    jwt_verifier: Some(JwtVerifier {
                        jwk_service: Arc::new(Keys),
                        jwt_issuer: Some(vec!["issuer".into()]),
                        jwt_audience: Some(vec!["lore-test".into()]),
                        jwt_typ: None,
                        identity_claim: "sub".into(),
                    }),
                    repository_authorizer: authorizer,
                    max_file_size: 100,
                    presign_config: Some(presign_config_with_policy(Default::default())),
                };
                let health = ServerHealth::new_without_availability(immutable_store);
                let server = TestServer::new(create_router(
                    state,
                    health,
                    &LoreHttpServerSettings::test_default(),
                ))
                .unwrap();
                let mut header = Header::new(Algorithm::HS256);
                header.kid = Some("key".into());
                let jwt = jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(SECRET))
                    .unwrap();
                let mut request = server
                    .post(&format!(
                        "/v1/repository/{repository}/content/{address}/presign"
                    ))
                    .json(&json!({}));
                if case != 0 {
                    request = request
                        .add_header(axum::http::header::AUTHORIZATION, format!("Bearer {jwt}"));
                }
                let response = request.await;
                let expected = if case == 0 {
                    StatusCode::UNAUTHORIZED
                } else if allowed {
                    StatusCode::OK
                } else {
                    StatusCode::FORBIDDEN
                };
                assert_eq!(response.status_code(), expected, "case={case}");
                if allowed {
                    assert!(
                        response.json::<serde_json::Value>()["url_suffix"]
                            .as_str()
                            .unwrap()
                            .contains("token=")
                    );
                }
            })
            .await;
    }
}
