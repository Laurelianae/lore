// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
mod forwarded_request {
    use std::sync::Arc;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_proto::lore::repository::v1::RepositoryCreateRequest;
    use lore_proto::lore::repository::v1::RepositoryCreateResponse;
    use lore_revision::lore::RepositoryId;
    use lore_server::grpc::forwarded_requests::ForwardedRequestResult;
    use lore_server::grpc::forwarded_requests::ForwardedRequests;
    use lore_server::grpc::forwarded_requests::InternalClientError;
    use lore_server::grpc::forwarded_requests::RpcFlags;
    use lore_server::grpc::forwarded_requests::repository_service::ForwardedRepositoryServiceClient;
    use lore_server::grpc::forwarded_requests::revision_service::ForwardedRevisionServiceClient;
    use lore_server::grpc::repository::v1::repository_create::*;
    use lore_server::hooks::HookDispatcher;
    use rand::random;
    use tonic::Request;
    use tonic::Response;
    use tonic::Status;

    use crate::store::test_support::test_store_create;

    struct TestInstrumentProvider;

    impl lore_telemetry::InstrumentProvider for TestInstrumentProvider {
        fn namespace(&self) -> &'static str {
            "test"
        }
    }

    /// Single-use client that returns a pre-configured result on its one call.
    struct SingleShotClient {
        response: Arc<Mutex<Option<ForwardedRequestResult<RepositoryCreateResponse>>>>,
    }

    #[async_trait]
    impl ForwardedRepositoryServiceClient for SingleShotClient {
        async fn repository_create(
            &mut self,
            _request: Request<RepositoryCreateRequest>,
        ) -> ForwardedRequestResult<RepositoryCreateResponse> {
            self.response
                .lock()
                .unwrap()
                .take()
                .expect("repository_create called more than once")
        }

        async fn repository_get(
            &mut self,
            _request: Request<lore_proto::lore::repository::v1::RepositoryGetRequest>,
        ) -> ForwardedRequestResult<lore_proto::lore::repository::v1::RepositoryGetResponse>
        {
            unreachable!("repository_get should not be called in repository_create tests")
        }
    }

    struct StubForwardedRequests {
        flags: RpcFlags,
        response: Arc<Mutex<Option<ForwardedRequestResult<RepositoryCreateResponse>>>>,
    }

    impl StubForwardedRequests {
        fn forwarding_enabled(
            response: ForwardedRequestResult<RepositoryCreateResponse>,
        ) -> Arc<Self> {
            Arc::new(Self {
                flags: RpcFlags {
                    repository_create: true,
                    ..Default::default()
                },
                response: Arc::new(Mutex::new(Some(response))),
            })
        }

        fn forwarding_disabled(
            response: ForwardedRequestResult<RepositoryCreateResponse>,
        ) -> Arc<Self> {
            Arc::new(Self {
                flags: RpcFlags {
                    repository_create: false,
                    ..Default::default()
                },
                response: Arc::new(Mutex::new(Some(response))),
            })
        }
    }

    impl ForwardedRequests for StubForwardedRequests {
        fn rpc_flags(&self) -> &RpcFlags {
            &self.flags
        }

        fn forwarded_revision_service(&self) -> Box<dyn ForwardedRevisionServiceClient> {
            unreachable!(
                "forwarded_revision_service should not be called in repository_create tests"
            )
        }

        fn forwarded_repository_service(&self) -> Box<dyn ForwardedRepositoryServiceClient> {
            Box::new(SingleShotClient {
                response: Arc::clone(&self.response),
            })
        }
    }

    fn make_request(repository_id: RepositoryId, name: &str) -> Request<RepositoryCreateRequest> {
        let id_bytes: lore_base::types::Context = repository_id.into();
        Request::new(RepositoryCreateRequest {
            id: bytes::Bytes::from(id_bytes),
            name: name.into(),
            description: String::new(),
            default_branch_id: bytes::Bytes::from(lore_base::types::Context::from(
                uuid::Uuid::now_v7(),
            )),
            default_branch_name: "main".into(),
            creator: Some("alice".into()),
        })
    }

    #[tokio::test]
    async fn delegates_to_remote_and_returns_response() {
        // When the flag is enabled the other server's response is returned directly;
        // repository_create_implementation is NOT called so the local store stays empty.
        let repository_id = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        let repo_record = lore_proto::lore::model::v1::Repository {
            name: "test-repo".into(),
            ..Default::default()
        };
        let repo_response = Ok(Ok(Response::new(RepositoryCreateResponse {
            repository: Some(repo_record),
        })));
        let forwarded_requests = StubForwardedRequests::forwarding_enabled(repo_response);

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let hook_dispatcher = HookDispatcher::empty();

            let response = handler(
                make_request(repository_id, "test-repo"),
                None, /* no auth */
                std::sync::Arc::new(
                    lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer,
                ),
                immutable_store,
                mutable_store,
                &Some(forwarded_requests as Arc<dyn ForwardedRequests>),
                &hook_dispatcher,
                &TestInstrumentProvider,
            )
            .await
            .expect("should succeed");

            let repo = response
                .into_inner()
                .repository
                .expect("response should include Repository");
            assert_eq!(repo.name, "test-repo");
        }))
        .await;
    }

    #[tokio::test]
    async fn error_status_returned_to_caller() {
        // An error status from the forwarded server is forwarded directly to the original caller.
        let repository_id = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        let forwarded_request_result = Ok(Err(Status::already_exists("test error forwarded")));
        let forwarded_requests =
            StubForwardedRequests::forwarding_enabled(forwarded_request_result);

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let hook_dispatcher = HookDispatcher::empty();

            let err = handler(
                make_request(repository_id, "test-repo"),
                None,
                std::sync::Arc::new(
                    lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer,
                ),
                immutable_store,
                mutable_store,
                &Some(forwarded_requests as Arc<dyn ForwardedRequests>),
                &hook_dispatcher,
                &TestInstrumentProvider,
            )
            .await
            .expect_err("forwarded error should propagate");

            assert_eq!(err.code(), tonic::Code::AlreadyExists);
            assert!(err.message().contains("test error forwarded"));
        }))
        .await;
    }

    #[tokio::test]
    async fn internal_client_error_maps_to_internal_status() {
        // A transport-level failure (InternalClientError) is mapped to Status::internal.
        let repository_id = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        let forwarded_requests =
            StubForwardedRequests::forwarding_enabled(Err(InternalClientError::internal("oops")));

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let hook_dispatcher = HookDispatcher::empty();

            let err = handler(
                make_request(repository_id, "test-repo"),
                None,
                std::sync::Arc::new(
                    lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer,
                ),
                immutable_store,
                mutable_store,
                &Some(forwarded_requests as Arc<dyn ForwardedRequests>),
                &hook_dispatcher,
                &TestInstrumentProvider,
            )
            .await
            .expect_err("transport error should become internal status");

            assert_eq!(err.code(), tonic::Code::Internal);
            assert!(err.message().contains("Error making forwarded request"));
        }))
        .await;
    }

    #[tokio::test]
    async fn flag_disabled_falls_through_to_local_execution() {
        // When repository_create is false the local path runs, even if a
        // ForwardedRequests is present. The stub client is not called.
        let repository_id = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        // response is irrelevant — client must never be called
        let forwarded_result = Ok(Err(Status::internal("should not be called")));
        let forwarded_requests = StubForwardedRequests::forwarding_disabled(forwarded_result);

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let hook_dispatcher = HookDispatcher::empty();

            let response = handler(
                make_request(repository_id, "my-repo"),
                None, /* no auth */
                std::sync::Arc::new(
                    lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer,
                ),
                immutable_store,
                mutable_store,
                &Some(forwarded_requests as Arc<dyn ForwardedRequests>),
                &hook_dispatcher,
                &TestInstrumentProvider,
            )
            .await
            .expect("local execution should succeed");

            let repo = response
                .into_inner()
                .repository
                .expect("response should include Repository");
            assert_eq!(repo.name, "my-repo");
        }))
        .await;
    }
}

/// A denied create or retry must not dispatch hooks or repair repository mappings.
#[tokio::test]
async fn claim_creation_and_retries_require_write_before_hooks() {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Context;
    use lore_base::types::RepositoryId;
    use lore_revision::repository::RepositoryContext;
    use lore_revision::repository::{self};
    use lore_server::auth::jwt::AuthorizationToken;
    use lore_server::auth::jwt::ResourcePermission;
    use lore_server::authnz::repository_authorizer::AuthClientAuthorizer;
    use lore_server::authnz::repository_authorizer::RawToken;
    use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
    use lore_server::grpc::repository::v1::repository_create::handler;
    use lore_server::hooks::Hook;
    use lore_server::hooks::HookContext;
    use lore_server::hooks::HookDispatcher;
    use lore_server::hooks::HookError;
    use lore_server::hooks::HookPoint;
    use tonic::Request;

    use crate::store::test_support::test_store_create;

    struct Counter(Arc<AtomicUsize>);
    impl Hook for Counter {
        fn name(&self) -> &'static str {
            "creation-counter"
        }
        fn hook_points(&self) -> &'static [HookPoint] {
            &[HookPoint::RepositoryCreate]
        }
        fn pre_handler(&self, _context: &HookContext) -> Result<(), HookError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    struct Metrics;
    impl lore_telemetry::InstrumentProvider for Metrics {
        fn namespace(&self) -> &'static str {
            "creation-permissions"
        }
    }
    let (immutable, mutable, execution) = test_store_create().await.unwrap();
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let id = rand::random::<RepositoryId>();
        let context = Arc::new(RepositoryContext::new_server_context(
            immutable.clone(),
            mutable.clone(),
            id,
        ));
        let count = Arc::new(AtomicUsize::new(0));
        let hooks = HookDispatcher::from_hooks_default(vec![(
            "counter".into(),
            Box::new(Counter(count.clone())),
        )]);
        let authorizer: Arc<dyn RepositoryAuthorizer> =
            Arc::new(AuthClientAuthorizer::new("https://auth.invalid".into()));
        let branch = rand::random::<Context>();
        let request = |permission: &str| {
            let mut request =
                Request::new(lore_proto::lore::repository::v1::RepositoryCreateRequest {
                    id: id.data().to_vec().into(),
                    name: "creation-permissions".into(),
                    description: String::new(),
                    default_branch_id: branch.into(),
                    default_branch_name: "main".into(),
                    creator: None,
                });
            request.extensions_mut().insert(AuthorizationToken {
                user_id: "creator".into(),
                resources: Some(vec![ResourcePermission {
                    resource_id: format!("urc-{id}"),
                    permission: vec![permission.into()],
                }]),
                ..Default::default()
            });
            request.extensions_mut().insert(RawToken("verified".into()));
            request
        };
        assert_eq!(
            handler(
                request("read"),
                None,
                authorizer.clone(),
                immutable.clone(),
                mutable.clone(),
                &None,
                &hooks,
                &Metrics
            )
            .await
            .unwrap_err()
            .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert!(repository::metadata_hash(context.clone()).await.is_err());
        handler(
            request("write"),
            None,
            authorizer.clone(),
            immutable.clone(),
            mutable.clone(),
            &None,
            &hooks,
            &Metrics,
        )
        .await
        .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let hash = repository::metadata_hash(context.clone()).await.unwrap();
        repository::store_name_to_id(
            context.clone(),
            "creation-permissions",
            RepositoryId::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            handler(
                request("read"),
                None,
                authorizer.clone(),
                immutable.clone(),
                mutable.clone(),
                &None,
                &hooks,
                &Metrics
            )
            .await
            .unwrap_err()
            .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(
            repository::metadata_hash(context.clone()).await.unwrap(),
            hash
        );
        let mapping = repository::id_from_name(context.clone(), "creation-permissions").await;
        assert!(mapping.is_err() || mapping.unwrap().is_zero());
        handler(
            request("write"),
            None,
            authorizer,
            immutable,
            mutable,
            &None,
            &hooks,
            &Metrics,
        )
        .await
        .unwrap();
        assert_eq!(
            repository::id_from_name(context, "creation-permissions")
                .await
                .unwrap(),
            id
        );
    }))
    .await;
}
