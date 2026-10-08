// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::RepositoryId;
use lore_proto::lore::model::v1::Repository as RepositoryRecord;
use lore_proto::lore::repository::v1;
use lore_proto::lore::repository::v1::repository_service_server::RepositoryService;
use lore_proto::lore::repository::v1::repository_service_server::RepositoryServiceServer;
use lore_transport::connection::SuppliedCredentials;
use lore_transport::grpc::GRPCConnection;
use lore_transport::grpc::RequestLoggerLayer;
use lore_transport::grpc::repository_client;
use lore_transport::traits::Repository;
use parking_lot::Mutex;
use tonic::Request;
use tonic::Response;
use tonic::Status;

struct RecordingServer {
    received: Arc<Mutex<Vec<(String, String)>>>,
    credentials: Arc<SuppliedCredentials>,
    first_failure: AtomicBool,
    reconnect: bool,
    failure_method: &'static str,
}

impl RecordingServer {
    fn record<T>(&self, method: &str, request: &Request<T>) -> Result<(), Status> {
        self.received.lock().push((method.into(), bearer(request)));
        if method == self.failure_method && self.first_failure.swap(false, Ordering::Relaxed) {
            self.credentials.update("login", "rotated-access");
            return Err(if self.reconnect {
                Status::unavailable("reconnect this client")
            } else {
                Status::resource_exhausted("retry this request")
            });
        }
        Ok(())
    }
}

fn record() -> RepositoryRecord {
    RepositoryRecord {
        id: Bytes::from(vec![1; 16]),
        name: "test".into(),
        metadata: Bytes::from(vec![0; 32]),
        ..Default::default()
    }
}

fn bearer<T>(request: &Request<T>) -> String {
    request
        .metadata()
        .get("authorization")
        .map(|value| value.to_str().unwrap().to_string())
        .unwrap_or_default()
}

#[tonic::async_trait]
impl RepositoryService for RecordingServer {
    async fn repository_create(
        &self,
        request: Request<v1::RepositoryCreateRequest>,
    ) -> Result<Response<v1::RepositoryCreateResponse>, Status> {
        self.record("create", &request)?;
        let request = request.into_inner();
        Ok(Response::new(v1::RepositoryCreateResponse {
            repository: Some(RepositoryRecord {
                id: request.id,
                name: request.name,
                metadata: Bytes::from(vec![0; 32]),
                ..Default::default()
            }),
        }))
    }

    async fn repository_delete(
        &self,
        request: Request<v1::RepositoryDeleteRequest>,
    ) -> Result<Response<v1::RepositoryDeleteResponse>, Status> {
        self.record("delete", &request)?;
        Ok(Response::new(v1::RepositoryDeleteResponse::default()))
    }

    type RepositoryListStream =
        tokio_stream::Iter<std::vec::IntoIter<Result<v1::RepositoryListResponse, Status>>>;
    async fn repository_list(
        &self,
        request: Request<v1::RepositoryListRequest>,
    ) -> Result<Response<Self::RepositoryListStream>, Status> {
        self.record("list", &request)?;
        Ok(Response::new(tokio_stream::iter(vec![Ok(
            v1::RepositoryListResponse {
                repository: Some(record()),
            },
        )])))
    }

    async fn repository_get(
        &self,
        request: Request<v1::RepositoryGetRequest>,
    ) -> Result<Response<v1::RepositoryGetResponse>, Status> {
        self.record("query", &request)?;
        Ok(Response::new(v1::RepositoryGetResponse {
            repository: Some(record()),
        }))
    }

    async fn repository_metadata_get(
        &self,
        request: Request<v1::RepositoryMetadataGetRequest>,
    ) -> Result<Response<v1::RepositoryMetadataGetResponse>, Status> {
        self.record("metadata-get", &request)?;
        Ok(Response::new(v1::RepositoryMetadataGetResponse {
            metadata: Bytes::from(vec![0; 32]),
        }))
    }

    async fn repository_metadata_set(
        &self,
        request: Request<v1::RepositoryMetadataSetRequest>,
    ) -> Result<Response<v1::RepositoryMetadataSetResponse>, Status> {
        self.record("metadata-set", &request)?;
        Ok(Response::new(v1::RepositoryMetadataSetResponse {
            metadata: request.into_inner().updated,
        }))
    }
}

async fn setup(
    credentials: Arc<SuppliedCredentials>,
    auth_url: &str,
    failure: Option<(bool, &'static str)>,
) -> (
    Arc<dyn Repository>,
    Arc<GRPCConnection>,
    Arc<Mutex<Vec<(String, String)>>>,
    tokio::task::JoinHandle<()>,
) {
    let received = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = RecordingServer {
        received: received.clone(),
        credentials: credentials.clone(),
        first_failure: AtomicBool::new(failure.is_some()),
        reconnect: failure.is_some_and(|(reconnect, _)| reconnect),
        failure_method: failure.map_or("", |(_, method)| method),
    };
    #[allow(clippy::disallowed_methods)] // Test-local server task.
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(RepositoryServiceServer::new(server))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let url = format!("http://{address}");
    let channel = tonic::transport::Channel::from_shared(url.clone())
        .unwrap()
        .connect()
        .await
        .unwrap();
    let channel = tower::ServiceBuilder::new()
        .layer(RequestLoggerLayer {})
        .service(channel);
    let connection = Arc::new(GRPCConnection::for_test(url.parse().unwrap(), channel));
    let repository = repository_client(connection.clone(), auth_url, "alice", &credentials)
        .await
        .unwrap();
    (repository, connection, received, task)
}

async fn create(repository: &dyn Repository) {
    repository
        .create(
            "00112233445566778899aabbccddeeff".parse().unwrap(),
            "test",
            "",
            Context::default(),
            "main",
            "alice",
            0,
        )
        .await
        .unwrap();
}

/// Capture actual RPC headers: credential updates must reach cached clients,
/// including fallback to the login credential after an access token is removed.
#[tokio::test]
async fn repository_calls_read_current_credentials() {
    let credentials = Arc::new(SuppliedCredentials::new("login", "first-access"));
    let (repository, _, received, task) = setup(credentials.clone(), "", None).await;
    create(repository.as_ref()).await;
    credentials.update("login", "second-access");
    create(repository.as_ref()).await;
    repository.delete(RepositoryId::default()).await.unwrap();
    credentials.update("login", "");
    create(repository.as_ref()).await;
    repository.delete(RepositoryId::default()).await.unwrap();
    assert_eq!(
        *received.lock(),
        vec![
            ("create".into(), "Bearer first-access".into()),
            ("create".into(), "Bearer second-access".into()),
            ("delete".into(), "Bearer second-access".into()),
            ("create".into(), "Bearer login".into()),
            ("delete".into(), "Bearer login".into()),
        ]
    );
    task.abort();
}

#[tokio::test]
async fn creation_uses_a_supplied_access_token_without_a_login_token() {
    let credentials = Arc::new(SuppliedCredentials::new("", "access-only"));
    let (repository, _, received, task) = setup(credentials, "", None).await;
    create(repository.as_ref()).await;
    assert_eq!(received.lock()[0].1, "Bearer access-only");
    task.abort();
}

#[tokio::test]
async fn creation_preserves_stored_login_and_anonymous_fallbacks() {
    let credentials = Arc::new(SuppliedCredentials::default());
    let (repository, connection, received, task) = setup(credentials.clone(), "", None).await;
    let auth = connection
        .repository_authz("", "alice", RepositoryId::default(), &credentials)
        .await;
    auth.write().authentication_token = "stored-login".into();
    create(repository.as_ref()).await;
    auth.write().authentication_token.clear();
    create(repository.as_ref()).await;
    assert_eq!(
        *received.lock(),
        vec![
            ("create".into(), "Bearer stored-login".into()),
            ("create".into(), "".into()),
        ]
    );
    task.abort();
}

#[tokio::test]
async fn legacy_creation_keeps_the_authentication_token() {
    let credentials = Arc::new(SuppliedCredentials::new("login", "repository-access"));
    let (repository, _, received, task) =
        setup(credentials.clone(), "ucs-auth://auth.example.com", None).await;
    create(repository.as_ref()).await;
    credentials.update("login", "rotated-access");
    create(repository.as_ref()).await;
    assert!(
        received
            .lock()
            .iter()
            .all(|(_, token)| token == "Bearer login")
    );
    task.abort();
}

/// Both the inner throttling retry and the outer reconnect rebuild must read
/// the new access token rather than preserving the first attempt's credential.
#[tokio::test]
async fn creation_uses_rotated_credentials_on_retry_and_reconnect() {
    for reconnect in [false, true] {
        let credentials = Arc::new(SuppliedCredentials::new("login", "first-access"));
        let (repository, _, received, task) =
            setup(credentials, "", Some((reconnect, "create"))).await;
        create(repository.as_ref()).await;
        assert_eq!(
            *received.lock(),
            vec![
                ("create".into(), "Bearer first-access".into()),
                ("create".into(), "Bearer rotated-access".into()),
            ]
        );
        task.abort();
    }
}

async fn invoke(repository: &dyn Repository, method: &str) {
    let id = RepositoryId::default();
    match method {
        "query" => {
            repository.query(Some(id), None).await.unwrap();
        }
        "query-name" => {
            repository.query(None, Some("test")).await.unwrap();
        }
        "list" => {
            assert_eq!(repository.list().await.unwrap().len(), 1);
        }
        "metadata-get" => {
            repository.metadata_get(id).await.unwrap();
        }
        "metadata-set" => {
            assert!(
                repository
                    .metadata_set(id, Hash::default(), Hash::default())
                    .await
                    .unwrap()
                    .success
            );
        }
        "delete" => {
            repository.delete(id).await.unwrap();
        }
        _ => panic!("unknown test method"),
    }
}

const METHODS: [&str; 6] = [
    "query",
    "query-name",
    "list",
    "metadata-get",
    "metadata-set",
    "delete",
];

#[tokio::test]
async fn all_repository_rpcs_send_access_tokens_in_claim_mode() {
    for identity in ["", "login"] {
        let credentials = Arc::new(SuppliedCredentials::new(identity, "first-access"));
        let (repository, _, received, task) = setup(credentials.clone(), "", None).await;
        for method in METHODS {
            invoke(repository.as_ref(), method).await;
        }
        credentials.update(identity, "second-access");
        for method in METHODS {
            invoke(repository.as_ref(), method).await;
        }
        let received = received.lock();
        assert_eq!(received.len(), 12);
        assert!(
            received[..6]
                .iter()
                .all(|(_, token)| token == "Bearer first-access")
        );
        assert!(
            received[6..]
                .iter()
                .all(|(_, token)| token == "Bearer second-access")
        );
        task.abort();
    }
}

#[tokio::test]
async fn all_repository_rpcs_preserve_legacy_login_selection() {
    let credentials = Arc::new(SuppliedCredentials::new("login", "scoped-access"));
    let (repository, _, received, task) =
        setup(credentials, "ucs-auth://auth.example.com", None).await;
    for method in METHODS {
        invoke(repository.as_ref(), method).await;
    }
    assert_eq!(received.lock().len(), 6);
    assert!(
        received
            .lock()
            .iter()
            .all(|(_, token)| token == "Bearer login")
    );
    task.abort();
}

#[tokio::test]
async fn sibling_rpcs_read_rotated_credentials_on_retry_and_reconnect() {
    for reconnect in [false, true] {
        for method in METHODS.into_iter().filter(|method| *method != "query-name") {
            let credentials = Arc::new(SuppliedCredentials::new("login", "first-access"));
            let (repository, _, received, task) =
                setup(credentials, "", Some((reconnect, method))).await;
            invoke(repository.as_ref(), method).await;
            assert_eq!(
                *received.lock(),
                vec![
                    (method.into(), "Bearer first-access".into()),
                    (method.into(), "Bearer rotated-access".into()),
                ]
            );
            task.abort();
        }
    }
}
