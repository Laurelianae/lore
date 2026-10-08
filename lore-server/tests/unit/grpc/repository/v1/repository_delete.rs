// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_proto::lore::repository::v1::RepositoryDeleteRequest;
use lore_revision::lore::RepositoryId;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryMetadata;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::grpc::repository::v1::repository_delete::*;
use lore_telemetry::InstrumentProvider;
use rand::random;
use tonic::Request;

use crate::store::test_support::test_store_create;

struct TestInstrumentProvider;

impl InstrumentProvider for TestInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "test"
    }
}

async fn seed_repository(
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    id: RepositoryId,
    creator: &str,
) {
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        id,
    ));
    let metadata_hash = repository::metadata_store(
        repository.clone(),
        RepositoryMetadata {
            name: "the-repository".to_string(),
            creator: creator.to_string(),
            ..Default::default()
        },
    )
    .await
    .expect("Failed to store repository metadata");
    repository::metadata_store_hash(repository.clone(), metadata_hash)
        .await
        .expect("Failed to store repository metadata hash");
    repository::store_name_to_id(repository, "the-repository", id)
        .await
        .expect("Failed to store repository name to id mapping");
}

fn delete_request(id: RepositoryId, token: AuthorizationToken) -> Request<RepositoryDeleteRequest> {
    let id_bytes: Context = id.into();
    let mut request = Request::new(RepositoryDeleteRequest {
        id: id_bytes.into(),
    });
    request.extensions_mut().insert(token);
    request
}

/// The creator check compares the recorded creator against the token's
/// `identity_claim` value, so a deployment recording
/// `preferred_username` lets the same user, presenting the same claim,
/// delete — while the subject the provider minted alongside is not what
/// is compared.
#[tokio::test]
async fn the_creator_check_compares_the_identity_claim() {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let id = random::<RepositoryId>();
        seed_repository(immutable_store.clone(), mutable_store.clone(), id, "alice").await;

        let by_subject = AuthorizationToken {
            user_id: "f7d3a1c2-0000-0000-0000-000000000000".to_string(),
            preferred_username: Some("alice".to_string()),
            ..Default::default()
        };
        let status = handler(
            delete_request(id, by_subject.clone()),
            None,
            Arc::new(AllowAllRepositoryAuthorizer),
            immutable_store.clone(),
            mutable_store.clone(),
            &TestInstrumentProvider,
        )
        .await
        .expect_err("the subject is not the recorded creator");
        assert_eq!(status.code(), tonic::Code::PermissionDenied);

        let by_username = AuthorizationToken {
            identity: Some("alice".to_string()),
            ..by_subject
        };
        handler(
            delete_request(id, by_username),
            None,
            Arc::new(AllowAllRepositoryAuthorizer),
            immutable_store,
            mutable_store,
            &TestInstrumentProvider,
        )
        .await
        .expect("the identity claim matches the recorded creator");
    }))
    .await;
}

#[tokio::test]
async fn repository_delete_permission_matrix() {
    use lore_server::authnz::global_grants_authorizer::GlobalGrantsAuthorizer;
    use lore_server::authnz::repository_authorizer::RawToken;
    use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
    use lore_server::authnz::repository_authorizer::VerifiedToken;
    use lore_server::authnz::resource_grants_authorizer::ResourceGrantsAuthorizer;
    use serde_json::json;

    struct Policy(RepositoryId);
    #[async_trait::async_trait]
    impl RepositoryAuthorizer for Policy {
        async fn check_repository_access(
            &self,
            token: Option<&VerifiedToken<'_>>,
            id: RepositoryId,
            action: Option<&str>,
        ) -> Result<(), tonic::Status> {
            assert_eq!(id, self.0);
            assert_eq!(token.unwrap().raw, "verified-token");
            if action.is_none() || action == Some("admin") {
                Ok(())
            } else {
                Err(tonic::Status::permission_denied("denied"))
            }
        }
    }

    for v1 in [false, true] {
        for case in 0..11 {
            let (immutable_store, mutable_store, execution) = test_store_create().await.unwrap();
            Box::pin(LORE_CONTEXT.scope(execution, async move {
                let id = random::<RepositoryId>();
                let allowed = matches!(case, 0 | 5 | 6 | 7 | 8 | 10);
                let mut claims = AuthorizationToken {
                    user_id: "caller".into(),
                    ..Default::default()
                };
                let mut authorizer: Arc<dyn RepositoryAuthorizer> =
                    Arc::new(GlobalGrantsAuthorizer::new(Some("roles".into())));
                let creator = if matches!(case, 0 | 2 | 9) {
                    "caller"
                } else {
                    "someone-else"
                };
                match case {
                    0 | 1 => {
                        authorizer = Arc::new(AllowAllRepositoryAuthorizer);
                        claims.user_id = String::new();
                    }
                    4 => claims.is_service_account = Some(true),
                    5 | 6 => {
                        claims.extra = json!({"roles": [if case == 5 {"owner"} else {"admin"}]})
                            .as_object()
                            .unwrap()
                            .clone();
                    }
                    7..=9 => {
                        let resource = if case == 8 {
                            "all".into()
                        } else if case == 9 {
                            format!("repo-{}", random::<RepositoryId>())
                        } else {
                            format!("repo-{id}")
                        };
                        claims.extra = json!({"access": {"entries": [
                            {"id": resource, "actions": []},
                            {"id": resource, "actions": [if case == 8 {"admin"} else {"owner"}]}
                        ]}})
                        .as_object()
                        .unwrap()
                        .clone();
                        authorizer = Arc::new(ResourceGrantsAuthorizer::new(
                            "access.entries".into(),
                            "id".into(),
                            Some("actions".into()),
                            "repo-{id}".into(),
                            "all".into(),
                        ));
                    }
                    10 => authorizer = Arc::new(Policy(id)),
                    _ => {}
                }
                // In no-auth mode the caller identity is the unknown-user marker.
                let creator = if case == 0 { "<unknown>" } else { creator };
                seed_repository(immutable_store.clone(), mutable_store.clone(), id, creator).await;
                let context = Arc::new(RepositoryContext::new_server_context(
                    immutable_store.clone(),
                    mutable_store.clone(),
                    id,
                ));
                let before = repository::metadata_hash(context.clone()).await.unwrap();
                let mut request = delete_request(id, claims);
                if case < 2 {
                    request.extensions_mut().remove::<AuthorizationToken>();
                } else {
                    request
                        .extensions_mut()
                        .insert(RawToken("verified-token".into()));
                }
                // Misleading metadata must not authorize a different body target.
                request.metadata_mut().insert_bin(
                    lore_transport::grpc::REPOSITORY_ID_KEY,
                    tonic::metadata::BinaryMetadataValue::from_bytes(
                        random::<RepositoryId>().data(),
                    ),
                );
                let result = if v1 {
                    handler(
                        request,
                        None,
                        authorizer,
                        immutable_store,
                        mutable_store,
                        &TestInstrumentProvider,
                    )
                    .await
                    .map(|_| ())
                } else {
                    let (metadata, extensions, req) = request.into_parts();
                    let request = Request::from_parts(
                        metadata,
                        extensions,
                        lore_proto::RepositoryDeleteRequest { id: req.id },
                    );
                    lore_server::grpc::handlers::repository_delete::handler(
                        request,
                        None,
                        authorizer,
                        immutable_store,
                        mutable_store,
                        &TestInstrumentProvider,
                    )
                    .await
                    .map(|_| ())
                };
                assert_eq!(result.is_ok(), allowed, "v1={v1}, case={case}: {result:?}");
                if !allowed {
                    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
                    assert_eq!(
                        repository::metadata_hash(context.clone()).await.unwrap(),
                        before
                    );
                    assert_eq!(
                        repository::id_from_name(context, "the-repository")
                            .await
                            .unwrap(),
                        id
                    );
                }
            }))
            .await;
        }
    }
}

#[tokio::test]
async fn legacy_repository_delete_denial_preserves_repository() {
    use lore_server::authnz::global_grants_authorizer::GlobalGrantsAuthorizer;
    use lore_server::authnz::repository_authorizer::RawToken;
    use tonic_prost::prost::Message;

    for v1 in [false, true] {
        for code in [tonic::Code::PermissionDenied, tonic::Code::Unauthenticated] {
            let id = random::<RepositoryId>();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let app = axum::Router::new().route(
                "/ucs.auth.RebacApi/DeleteResource",
                axum::routing::post(
                    move |headers: axum::http::HeaderMap, body: axum::body::Bytes| async move {
                        assert_eq!(headers["authorization"], "Bearer verified-token");
                        let req =
                            lore_proto::rebac::DeleteResourceRequest::decode(&body[5..]).unwrap();
                        assert_eq!(req.resource_id, format!("urc-{id}"));
                        tonic::Status::new(code, "denied").into_http::<axum::body::Body>()
                    },
                ),
            );
            let server = lore_base::lore_spawn!(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let (immutable_store, mutable_store, execution) = test_store_create().await.unwrap();
            Box::pin(LORE_CONTEXT.scope(execution, async move {
                seed_repository(immutable_store.clone(), mutable_store.clone(), id, "caller").await;
                let context = Arc::new(RepositoryContext::new_server_context(
                    immutable_store.clone(),
                    mutable_store.clone(),
                    id,
                ));
                let before = repository::metadata_hash(context.clone()).await.unwrap();
                let mut request = delete_request(
                    id,
                    AuthorizationToken {
                        user_id: "caller".into(),
                        is_service_account: Some(true),
                        extra: serde_json::json!({"roles": ["write"]})
                            .as_object()
                            .unwrap()
                            .clone(),
                        ..Default::default()
                    },
                );
                request
                    .extensions_mut()
                    .insert(RawToken("verified-token".into()));
                request
                    .metadata_mut()
                    .insert("authorization", "Bearer verified-token".parse().unwrap());
                let authorizer = Arc::new(GlobalGrantsAuthorizer::new(Some("roles".into())));
                let result = if v1 {
                    handler(
                        request,
                        Some(url),
                        authorizer,
                        immutable_store,
                        mutable_store,
                        &TestInstrumentProvider,
                    )
                    .await
                    .map(|_| ())
                } else {
                    let (metadata, extensions, req) = request.into_parts();
                    let request = Request::from_parts(
                        metadata,
                        extensions,
                        lore_proto::RepositoryDeleteRequest { id: req.id },
                    );
                    lore_server::grpc::handlers::repository_delete::handler(
                        request,
                        Some(url),
                        authorizer,
                        immutable_store,
                        mutable_store,
                        &TestInstrumentProvider,
                    )
                    .await
                    .map(|_| ())
                };
                assert_eq!(result.unwrap_err().code(), code);
                assert_eq!(
                    repository::metadata_hash(context.clone()).await.unwrap(),
                    before
                );
                assert_eq!(
                    repository::id_from_name(context, "the-repository")
                        .await
                        .unwrap(),
                    id
                );
            }))
            .await;
            server.abort();
        }
    }
}
