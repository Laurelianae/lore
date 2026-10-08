// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;
use lore_base::lore_spawn;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_revision::fragment::generate_random;
use lore_server::protocol::attribute_map::AttributeMap;
use lore_server::protocol::replication_store::get::Get;
use lore_server::protocol::replication_store::header::ReplicationHeader;
use lore_server::quic::ProtocolErrorInfo;
use lore_server::quic::QuicService;
use lore_server::quic::StreamDataHandler;
use lore_server::quic::StreamHandlerFactory;
use lore_server::quic::quinn::QuinnConfigBuilder;
use lore_server::quic::quinn::QuinnServer;
use lore_server::quic::quinn::build_cert_verifier;
use lore_server::quic::quinn::service_store::ServiceStore;
use lore_server::quic::quinn::service_store::StreamDataHandlerBuilder;
use lore_server::quic::replication_store_service::ReplicationServiceErrorCode;
use lore_server::quic::replication_store_service::client::CommandBehavior;
use lore_server::quic::replication_store_service::client::ReplicationStoreClient;
use lore_server::quic::replication_store_service::client::ReplicationStoreClientError;
use lore_server::quic::replication_store_service::client::StoreClient;
use lore_server::quic::stream_handler::*;
use lore_server::quic::tests::TEST_PROTOCOL;
use lore_server::quic::tests::TEST_PROTOCOL_V4;
use lore_server::quic::tests::TestHandlerFactory;
use lore_server::quic::tests::server_certs;
use lore_server::quic::tests::test_data_path;
use lore_transport::quic::QuicErrorStatus;
use lore_transport::quic::QuicOpCode;
use lore_transport::quic::QuicServiceError;
use lore_transport::quic::client::CertificateSettings;
use lore_transport::quic::client::ClientCerts;
use lore_transport::quic::client::CongestionAlgorithm;
use lore_transport::quic::client::DEFAULT_EXPECTED_RTT_MS;
use lore_transport::quic::client::STREAM_COUNT;
use lore_transport::quic::client::TransportConfig;
use lore_transport::quic::client::insecure_client_auth;
use lore_transport::quic::command_header::CommandHeader;
use lore_transport::quic::storage_service::Command;
use quinn::ClientConfig;
use quinn::ConnectionError;
use quinn::Endpoint;
use quinn::ReadError;
use quinn::ReadExactError;
use quinn::RecvStream;
use quinn::SendStream;
use quinn::crypto::rustls::QuicClientConfig;
use rand::random;
use tokio::io::AsyncWriteExt;
use zerocopy::IntoBytes;

use crate::store::test_support::test_store_create;

fn untrusted_client_cert_paths() -> anyhow::Result<(PathBuf, PathBuf)> {
    let path = test_data_path();
    let cert = path.join("untrusted_cert.pem");
    let key = path.join("untrusted_key.pem");
    Ok((cert, key))
}

fn trusted_client_cert_paths() -> anyhow::Result<(PathBuf, PathBuf)> {
    let path = test_data_path();
    let cert = path.join("test_client_cert.pem");
    let key = path.join("test_client_key.pem");
    Ok((cert, key))
}

/// A running server and an open client stream to it.
///
/// Quinn's send and receive streams cannot be mocked, so exercising the stream handler needs
/// a real server. The server, endpoint and connection are held because dropping any of them
/// closes the stream.
struct Harness {
    send: SendStream,
    recv: RecvStream,
    connection: quinn::Connection,
    _server: QuinnServer,
    _endpoint: Endpoint,
}

impl Harness {
    /// Open an additional stream on the same connection.
    async fn open_stream(&self) -> (SendStream, RecvStream) {
        self.connection
            .open_bi()
            .await
            .expect("Failed to open additional stream")
    }
}

/// Send a request asking the handler for `behaviour`.
async fn request(send: &mut SendStream, behaviour: MockBehaviour, command_id: u32) {
    send.write(&CommandHeader::new(behaviour.opcode(), command_id, 0).to_bytes())
        .await
        .expect("Failed to write header");
    send.flush().await.expect("Failed flush");
}

/// Read one response header.
async fn response(recv: &mut RecvStream) -> CommandHeader {
    let mut buffer = [0u8; 8];
    recv.read_exact(&mut buffer)
        .await
        .expect("Failed to read response");
    CommandHeader::from_bytes(&buffer)
}

/// Serve `factory` for `protocol` on a loopback endpoint and open a client stream to it.
///
/// The client skips certificate verification and presents none of its own; the mTLS tests
/// build their endpoints by hand because varying exactly that is what they test.
async fn serve_and_connect(
    factory: Box<dyn StreamHandlerFactory>,
    protocol: &'static str,
) -> Harness {
    serve_and_connect_with_stream_limit(factory, protocol, STREAM_COUNT as u64).await
}

async fn serve_and_connect_with_stream_limit(
    factory: Box<dyn StreamHandlerFactory>,
    protocol: &'static str,
    stream_limit: u64,
) -> Harness {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let server_addr = socket.local_addr().expect("Failed socket setup");
    drop(socket);

    let (cert_path, key_path, _) = server_certs().expect("Bad cert paths");
    let server = QuinnServer::start(
        QuinnConfigBuilder::new()
            .address(server_addr)
            .cert_file(cert_path)
            .pkey_file(key_path)
            .stream_handler_factory(factory)
            .max_bidi_streams(stream_limit)
            .build()
            .unwrap(),
    )
    .expect("Failed Quinn server start");

    let mut crypto_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(insecure_client_auth::SkipServerVerification::new())
        .with_no_client_auth();
    crypto_config.alpn_protocols = vec![protocol.as_bytes().into()];

    let client_config = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto_config).expect("Failed client config"),
    ));

    let client_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut endpoint = Endpoint::client(client_addr).expect("Failed to create client endpoint");
    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (send, recv) = connection
        .open_bi()
        .await
        .expect("Failed to setup bidirectional channel");

    Harness {
        send,
        recv,
        connection,
        _server: server,
        _endpoint: endpoint,
    }
}

const MOCK_PROTOCOL: &str = "mock-test/0.1";
const MOCK_MAX_CHUNK: usize = 4096;

/// How long [`MockBehaviour::Block`] holds a permit: longer than any test runs, and unrelated
/// to the timeouts under test so changing one does not move the other.
const BLOCKING_HANDLER_SLEEP: Duration = Duration::from_secs(3600);

/// Time a refusal that involves no waiting is allowed to take, with room for a loaded host.
const SHED_BUDGET: Duration = Duration::from_secs(1);

#[derive(Debug, thiserror::Error)]
#[error("mock error")]
struct MockError;

/// What a request asks the handler to do, carried by the command opcode so that one service
/// instance can behave differently on different streams of a connection.
#[derive(Copy, Clone, Debug)]
enum MockBehaviour {
    /// Hold the permit for [`BLOCKING_HANDLER_SLEEP`].
    Block,
    /// Answer immediately.
    Echo,
    /// Answer with more bytes than [`MOCK_MAX_CHUNK`] allows.
    Oversized,
}

impl MockBehaviour {
    fn opcode(self) -> QuicOpCode {
        match self {
            MockBehaviour::Block => 1,
            MockBehaviour::Echo => 2,
            MockBehaviour::Oversized => 3,
        }
    }

    fn from_opcode(opcode: QuicOpCode) -> Option<Self> {
        [
            MockBehaviour::Block,
            MockBehaviour::Echo,
            MockBehaviour::Oversized,
        ]
        .into_iter()
        .find(|behaviour| behaviour.opcode() == opcode)
    }
}

struct MockService;

#[async_trait]
impl QuicService for MockService {
    type ParsedRequestType = MockBehaviour;
    type RequestParseErrorType = MockError;
    type RequestHandlerError = MockError;

    fn get_service_name_label(&self) -> &'static str {
        "mock_test"
    }

    fn parse_request_bytes(
        &self,
        header: &CommandHeader,
        _bytes: Bytes,
    ) -> Result<MockBehaviour, MockError> {
        MockBehaviour::from_opcode(header.cmd).ok_or(MockError)
    }

    async fn run_request_handler(
        &self,
        _context: Arc<AttributeMap>,
        request: MockBehaviour,
    ) -> Result<Vec<Bytes>, MockError> {
        match request {
            MockBehaviour::Block => {
                tokio::time::sleep(BLOCKING_HANDLER_SLEEP).await;
                Ok(vec![Bytes::new()])
            }
            MockBehaviour::Echo => Ok(vec![Bytes::new()]),
            MockBehaviour::Oversized => Ok(vec![Bytes::from(vec![0xAB; MOCK_MAX_CHUNK + 1])]),
        }
    }

    fn command_to_metrics_label(&self, _opcode: QuicOpCode) -> &'static str {
        "test_cmd"
    }

    fn transform_protocol_error(&self, _error: &MockError) -> ProtocolErrorInfo {
        ProtocolErrorInfo {
            response_error_code: QuicServiceError::Failed as QuicErrorStatus,
            message_handle_label: "mock_error",
            is_internal_error: true,
            is_appropriate_for_logging: true,
        }
    }

    fn max_chunk_size(&self) -> usize {
        MOCK_MAX_CHUNK
    }

    fn build_request_span(
        &self,
        header: &CommandHeader,
        _message: &MockBehaviour,
        _context: &Arc<AttributeMap>,
    ) -> tracing::Span {
        lore_server::quic::storage_service::build_storage_protocol_request_span(
            header.cmd,
            lore_server::telemetry::StorageProtocol::StorageV0,
            lore_server::quic::NO_CONNECTION_ID,
            lore_server::quic::NO_REPOSITORY_ID,
            lore_server::quic::NO_CORRELATION_ID,
            lore_server::quic::NO_USER_ID,
            lore_server::quic::NO_USER_AGENT,
        )
    }
}

/// Limits generous enough not to interfere, with the ceiling derived as the server does.
fn test_limits() -> AdmissionLimits {
    let process_limit = 100;
    AdmissionLimits {
        process_limit,
        inflight_limit: process_limit * STREAM_COUNT as usize,
        handler_timeout: None,
        permit_timeout: None,
    }
}

/// Factory serving one service under one protocol with explicit limits.
struct SingleServiceFactory {
    service_store: ServiceStore,
}

impl SingleServiceFactory {
    fn new<ServiceType: QuicService + 'static>(
        protocol: &'static str,
        make_service: fn() -> ServiceType,
        limits: AdmissionLimits,
    ) -> Self {
        let mut service_store = ServiceStore::default();
        service_store.add_service(
            protocol,
            Box::new(move |context: Arc<AttributeMap>| {
                Box::new(StreamHandler::new(
                    Arc::new(make_service()),
                    context,
                    limits,
                )) as Box<dyn StreamDataHandler>
            }) as StreamDataHandlerBuilder,
        );
        Self { service_store }
    }
}

impl StreamHandlerFactory for SingleServiceFactory {
    fn supported_protocols(&self) -> Vec<String> {
        self.service_store.get_supported_services()
    }

    fn get_stream_handler_builder(
        &self,
        protocol: &str,
    ) -> Option<(&&'static str, &StreamDataHandlerBuilder)> {
        self.service_store.get_stream_builder(protocol)
    }
}

#[tokio::test]
async fn test_command() {
    let repository = random::<Context>();

    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");
    lore_spawn!(LORE_CONTEXT.scope(execution.clone(), async move {
        let mut harness = serve_and_connect(
            Box::new(TestHandlerFactory::new(
                immutable_store,
                mutable_store.clone(),
            )),
            TEST_PROTOCOL,
        )
        .await;

        let token = "some-token";
        let token_bytes = token.as_bytes();

        let header = CommandHeader::new(
            Command::Authorize as QuicOpCode,
            random::<u32>(),
            size_of::<Context>() + token_bytes.len(),
        );
        let header_bytes = header.to_bytes();

        // Split across two writes, so the server has to buffer a partial header.
        harness
            .send
            .write(&header_bytes[..4])
            .await
            .expect("Failed to write header");
        harness.send.flush().await.expect("Failed flush");
        tokio::time::sleep(Duration::from_millis(1)).await;

        let mut data = bytes::BytesMut::new();
        data.extend_from_slice(&header_bytes[4..]);
        data.extend_from_slice(repository.as_bytes());
        data.extend_from_slice(token_bytes);

        harness
            .send
            .write(data.to_vec().as_slice())
            .await
            .expect("Failed to write data");
        harness.send.flush().await.expect("Failed flush");

        assert_eq!(
            header.response_success(0),
            response(&mut harness.recv).await
        );

        harness.send.finish().expect("Failed to finish stream");
    }))
    .await
    .expect("Test task failed");
}

#[tokio::test]
async fn server_with_mtls_rejects_clients_without_certs() {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");
    lore_spawn!(LORE_CONTEXT.scope(execution.clone(), async move {
        // Unfortunately, there's no way to mock or otherwise fake Quinn Send/Recv streams, so in
        // order to test the stream handler we need to spin up an actual server instance.

        // Find an available port.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = socket.local_addr().expect("Failed socket setup");
        drop(socket);

        let client_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

        let (cert_path, key_path, ca_cert) = server_certs().expect("Bad cert paths");

        let _server = QuinnServer::start(
            QuinnConfigBuilder::new()
                .address(server_addr)
                .cert_file(cert_path)
                .pkey_file(key_path)
                .cert_chain(Some(ca_cert.clone()))
                .client_cert_verifier(
                    build_cert_verifier(ca_cert).expect("Failed client cert verifier"),
                )
                .stream_handler_factory(Box::new(TestHandlerFactory::new(
                    immutable_store,
                    mutable_store.clone(),
                )))
                .build()
                .unwrap(),
        )
        .expect("Failed Quinn server start");

        let mut crypto_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(insecure_client_auth::SkipServerVerification::new())
            // no certs provided - we should be rejected
            .with_no_client_auth();

        crypto_config.alpn_protocols = [TEST_PROTOCOL]
            .iter()
            .map(|alpn| alpn.as_bytes().into())
            .collect();

        let client_config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto_config).expect("Failed client config"),
        ));

        let mut endpoint = Endpoint::client(client_addr).expect("Failed to create client endpoint");
        endpoint.set_default_client_config(client_config);

        // it is expected the client can 'connect', as under the hood
        // the server client TLS handshake is still occurring
        let connection = endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .expect("Failed to setup bidirectional channel");

        // but when we try to do something with the connection (like receive data)
        // eventually the TLS handshake will have finished and reject our connection
        let mut response_buffer = [0u8; 8];
        let error = recv
            .read_exact(&mut response_buffer)
            .await
            .expect_err("receive should have failed");
        let ReadExactError::ReadError(read_error) = error else {
            panic!("Unexpected error type {error:?}");
        };
        let ReadError::ConnectionLost(connection_lost) = read_error else {
            panic!("Unexpected read error {read_error:?}");
        };
        let ConnectionError::ConnectionClosed(closed_error) = connection_lost else {
            panic!("Unexpected connection lost error {connection_lost:?}");
        };
        assert_eq!(closed_error.reason, "peer sent no certificates");

        // Close the client side of the stream.
        send.finish().expect("Failed to finish stream");
    }))
    .await
    .expect("Test task failed");
}

#[tokio::test]
async fn server_with_mtls_accepts_clients_with_certs() {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");
    lore_spawn!(LORE_CONTEXT.scope(execution.clone(), async move {
        // Unfortunately, there's no way to mock or otherwise fake Quinn Send/Recv streams, so in
        // order to test the stream handler we need to spin up an actual server instance.

        // Find an available port.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = socket.local_addr().expect("Failed socket setup");
        drop(socket);

        let (cert_path, key_path, ca_cert) = server_certs().expect("Bad cert paths");
        let (client_cert, client_key) = trusted_client_cert_paths().expect("Bad client cert paths");

        let _server = QuinnServer::start(
            QuinnConfigBuilder::new()
                .address(server_addr)
                .cert_file(cert_path)
                .pkey_file(key_path)
                .cert_chain(Some(ca_cert.clone()))
                .client_cert_verifier(
                    build_cert_verifier(ca_cert.clone()).expect("Failed client cert verifier"),
                )
                .stream_handler_factory(Box::new(TestHandlerFactory::new(
                    immutable_store,
                    mutable_store.clone(),
                )))
                .build()
                .unwrap(),
        )
        .expect("Failed Quinn server start");

        // `s` suffix so the server's certificate is validated
        let remote_url = format!("quics://{server_addr}");
        let client = ReplicationStoreClient::connect(
            &remote_url,
            CertificateSettings {
                custom_ca: Some(ca_cert),
                client: Some(ClientCerts {
                    cert_file: client_cert,
                    pkey_file: client_key,
                }),
            },
            None,
            TransportConfig {
                max_bytes_bandwidth_per_second: 1_000_000,
                expected_rtt_ms: DEFAULT_EXPECTED_RTT_MS,
                congestion_algorithm: CongestionAlgorithm::Bbr,
                initial_cwnd: None,
            },
            CommandBehavior {
                message_limit: 10,
                should_await_command_permit: false,
            },
            None,
            None,
        )
        .await
        .expect("Failed to establish client connection");

        // requests should be handled gracefully
        let (_, address, _) = generate_random();
        let client_error = client
            .get(Get {
                header: ReplicationHeader {
                    correlation_id: Default::default(),
                    repository: random(),
                },
                address,
            })
            .await
            .expect_err("Failed to get request");
        assert!(matches!(
            client_error,
            ReplicationStoreClientError::ServiceError(ReplicationServiceErrorCode::AddressNotFound)
        ));
    }))
    .await
    .expect("Test task failed");
}

#[tokio::test]
async fn server_with_mtls_rejects_clients_with_invalid_certs() {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");
    lore_spawn!(LORE_CONTEXT.scope(execution.clone(), async move {
        // Unfortunately, there's no way to mock or otherwise fake Quinn Send/Recv streams, so in
        // order to test the stream handler we need to spin up an actual server instance.

        // Find an available port.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = socket.local_addr().expect("Failed socket setup");
        drop(socket);

        let (cert_path, key_path, ca_cert) = server_certs().expect("Bad cert paths");
        let (untrusted_cert, untrusted_key) =
            untrusted_client_cert_paths().expect("Bad untrusted cert paths");

        let _server = QuinnServer::start(
            QuinnConfigBuilder::new()
                .address(server_addr)
                .cert_file(cert_path.clone())
                .pkey_file(key_path.clone())
                .cert_chain(Some(ca_cert.clone()))
                .client_cert_verifier(
                    build_cert_verifier(ca_cert.clone()).expect("Failed client cert verifier"),
                )
                .stream_handler_factory(Box::new(TestHandlerFactory::new(
                    immutable_store,
                    mutable_store.clone(),
                )))
                .build()
                .unwrap(),
        )
        .expect("Failed Quinn server start");

        let remote_url = format!("quic://{server_addr}");
        let client = ReplicationStoreClient::connect(
            &remote_url,
            CertificateSettings {
                custom_ca: None,
                client: Some(ClientCerts {
                    cert_file: untrusted_cert,
                    pkey_file: untrusted_key,
                }),
            },
            None,
            TransportConfig {
                max_bytes_bandwidth_per_second: 1_000_000,
                expected_rtt_ms: DEFAULT_EXPECTED_RTT_MS,
                congestion_algorithm: CongestionAlgorithm::Bbr,
                initial_cwnd: None,
            },
            CommandBehavior {
                message_limit: 10,
                should_await_command_permit: false,
            },
            None,
            None,
        )
        .await;

        // The client finishes its side of the handshake once it has validated the
        // server; the server's refusal of our untrusted certificate arrives after
        // that as a connection close. Whether that close lands before `connect`
        // returns is a race, so accept a refusal at either point — both show the
        // certificate was rejected.
        let Ok(client) = client else {
            return;
        };

        let (_, address, _) = generate_random();
        let client_error = client
            .get(Get {
                header: ReplicationHeader {
                    correlation_id: Default::default(),
                    repository: random(),
                },
                address,
            })
            .await
            .expect_err("request over a rejected connection must fail");
        assert!(matches!(
            client_error,
            ReplicationStoreClientError::ConnectionFailed
        ));
    }))
    .await
    .expect("Test task failed");
}

#[tokio::test]
async fn server_without_mtls_accepts_clients_without_certs() {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");
    lore_spawn!(LORE_CONTEXT.scope(execution.clone(), async move {
        // Unfortunately, there's no way to mock or otherwise fake Quinn Send/Recv streams, so in
        // order to test the stream handler we need to spin up an actual server instance.

        // Find an available port.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = socket.local_addr().expect("Failed socket setup");
        drop(socket);

        let (cert_path, key_path, _) = server_certs().expect("Bad cert paths");

        let _server = QuinnServer::start(
            // no client_cert_verifier which defaults to NoClientAuth verifier
            QuinnConfigBuilder::new()
                .address(server_addr)
                .cert_file(cert_path.clone())
                .pkey_file(key_path.clone())
                .stream_handler_factory(Box::new(TestHandlerFactory::new(
                    immutable_store,
                    mutable_store.clone(),
                )))
                .build()
                .unwrap(),
        )
        .expect("Failed Quinn server start");

        let remote_url = format!("quic://{server_addr}");
        let client = ReplicationStoreClient::connect(
            &remote_url,
            CertificateSettings {
                custom_ca: None,
                client: None,
            },
            None,
            TransportConfig {
                max_bytes_bandwidth_per_second: 1_000_000,
                expected_rtt_ms: DEFAULT_EXPECTED_RTT_MS,
                congestion_algorithm: CongestionAlgorithm::Bbr,
                initial_cwnd: None,
            },
            CommandBehavior {
                message_limit: 10,
                should_await_command_permit: false,
            },
            None,
            None,
        )
        .await
        .expect("Failed to establish client connection");

        // requests should be handled gracefully
        let (_, address, _) = generate_random();
        let client_error = client
            .get(Get {
                header: ReplicationHeader {
                    correlation_id: Default::default(),
                    repository: random(),
                },
                address,
            })
            .await
            .expect_err("Failed to get request");
        assert!(matches!(
            client_error,
            ReplicationStoreClientError::ServiceError(ReplicationServiceErrorCode::AddressNotFound)
        ));
    }))
    .await
    .expect("Test task failed");
}

#[tokio::test]
async fn unsupported_protocol_rejects_client() {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");
    lore_spawn!(LORE_CONTEXT.scope(execution.clone(), async move {
        // Unfortunately, there's no way to mock or otherwise fake Quinn Send/Recv streams, so in
        // order to test the stream handler we need to spin up an actual server instance.

        // Find an available port.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = socket.local_addr().expect("Failed socket setup");
        drop(socket);

        let client_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

        let (cert_path, key_path, _) = server_certs().expect("Bad cert paths");

        let _server = QuinnServer::start(
            QuinnConfigBuilder::new()
                .address(server_addr)
                .cert_file(cert_path)
                .pkey_file(key_path)
                .stream_handler_factory(Box::new(TestHandlerFactory::new(
                    immutable_store,
                    mutable_store.clone(),
                )))
                .build()
                .unwrap(),
        )
        .expect("Failed Quinn server start");

        let mut crypto_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(insecure_client_auth::SkipServerVerification::new())
            .with_no_client_auth();

        crypto_config.alpn_protocols = ["no-test/0.2"]
            .iter()
            .map(|alpn| alpn.as_bytes().into())
            .collect();

        let client_config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto_config).expect("Failed client config"),
        ));

        let mut endpoint = Endpoint::client(client_addr).expect("Failed to create client endpoint");
        endpoint.set_default_client_config(client_config);

        let connection_error = endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap_err();
        let ConnectionError::ConnectionClosed(frame) = connection_error else {
            panic!("Unexpected error type {connection_error:?}");
        };
        assert_eq!(frame.reason, "peer doesn't support any known protocol");
    }))
    .await
    .expect("Test task failed");
}

#[tokio::test]
async fn handler_returns_error_when_response_exceeds_max_chunk_size() {
    let (_immutable_store, _mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");
    lore_spawn!(LORE_CONTEXT.scope(execution.clone(), async move {
        let mut harness = serve_and_connect(
            Box::new(SingleServiceFactory::new(
                MOCK_PROTOCOL,
                || MockService,
                test_limits(),
            )),
            MOCK_PROTOCOL,
        )
        .await;

        request(&mut harness.send, MockBehaviour::Oversized, random::<u32>()).await;

        let response = response(&mut harness.recv).await;
        assert!(
            response.error,
            "Expected error response for oversized message, got: {response:?}"
        );
        assert_eq!(
            response.size_or_status,
            QuicServiceError::Failed as u32,
            "Expected Failed error status for oversized response"
        );

        harness.send.finish().expect("Failed to finish stream");
    }))
    .await
    .expect("Test task failed");
}

/// Permit exhaustion is answered on the permit timeout rather than the handler timeout.
#[tokio::test]
async fn permit_exhaustion_is_answered_before_the_handler_timeout() {
    const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);
    const PERMIT_TIMEOUT: Duration = Duration::from_millis(200);

    let (_immutable_store, _mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");
    lore_spawn!(LORE_CONTEXT.scope(execution.clone(), async move {
        let mut harness = serve_and_connect(
            Box::new(SingleServiceFactory::new(
                MOCK_PROTOCOL,
                || MockService,
                AdmissionLimits {
                    process_limit: 1,
                    handler_timeout: Some(HANDLER_TIMEOUT),
                    permit_timeout: Some(PERMIT_TIMEOUT),
                    ..test_limits()
                },
            )),
            MOCK_PROTOCOL,
        )
        .await;

        for command_id in [1, 2] {
            request(&mut harness.send, MockBehaviour::Block, command_id).await;
        }

        let started = Instant::now();
        let response = response(&mut harness.recv).await;
        let elapsed = started.elapsed();
        assert_eq!(
            response.command_id, 2,
            "expected the queued request to be answered first, got: {response:?}"
        );
        assert!(
            response.error,
            "expected an error response, got: {response:?}"
        );
        assert_eq!(
            response.size_or_status,
            QuicServiceError::SlowDown as u32,
            "expected SlowDown when no permit is available"
        );
        assert!(
            (PERMIT_TIMEOUT..PERMIT_TIMEOUT * 5).contains(&elapsed),
            "expected a wait of about {PERMIT_TIMEOUT:?}, took {elapsed:?}"
        );

        harness.send.finish().expect("Failed to finish stream");
    }))
    .await
    .expect("Test task failed");
}

/// The connection ceiling refuses outright, capping how many requests can be parked holding
/// a parsed payload -- which the per-stream permit wait alone does not.
#[tokio::test]
async fn connection_inflight_ceiling_sheds_without_waiting() {
    const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);
    const PERMIT_TIMEOUT: Duration = Duration::from_secs(10);

    let (_immutable_store, _mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");
    lore_spawn!(LORE_CONTEXT.scope(execution.clone(), async move {
        let mut harness = serve_and_connect(
            Box::new(SingleServiceFactory::new(
                MOCK_PROTOCOL,
                || MockService,
                AdmissionLimits {
                    process_limit: 64,
                    inflight_limit: 1,
                    handler_timeout: Some(HANDLER_TIMEOUT),
                    permit_timeout: Some(PERMIT_TIMEOUT),
                },
            )),
            MOCK_PROTOCOL,
        )
        .await;

        for command_id in [1, 2] {
            request(&mut harness.send, MockBehaviour::Block, command_id).await;
        }

        let started = Instant::now();
        let response = response(&mut harness.recv).await;
        let elapsed = started.elapsed();
        assert_eq!(response.command_id, 2, "got: {response:?}");
        assert!(
            response.error,
            "expected an error response, got: {response:?}"
        );
        assert_eq!(
            response.size_or_status,
            QuicServiceError::SlowDown as u32,
            "expected SlowDown at the connection ceiling"
        );
        assert!(
            elapsed < SHED_BUDGET,
            "the ceiling must refuse outright, took {elapsed:?}"
        );

        harness.send.finish().expect("Failed to finish stream");
    }))
    .await
    .expect("Test task failed");
}

/// A request cannot report an error, so a header carrying the error bit tears the stream down
/// rather than being served.
#[tokio::test]
async fn a_request_header_carrying_the_error_bit_closes_the_stream() {
    let (_immutable_store, _mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");
    lore_spawn!(LORE_CONTEXT.scope(execution.clone(), async move {
        let mut harness = serve_and_connect(
            Box::new(SingleServiceFactory::new(
                MOCK_PROTOCOL,
                || MockService,
                test_limits(),
            )),
            MOCK_PROTOCOL,
        )
        .await;

        let header = CommandHeader::new(MockBehaviour::Echo as QuicOpCode, 1, 0)
            .response_error(QuicServiceError::Failed as u32);
        harness
            .send
            .write(&header.to_bytes())
            .await
            .expect("Failed to write header");
        harness.send.flush().await.expect("Failed flush");

        let outcome = harness.recv.read_chunk(usize::MAX, false).await;
        assert!(
            outcome.is_err() || matches!(outcome, Ok(None)),
            "expected the stream to be closed, got: {outcome:?}"
        );
    }))
    .await
    .expect("Test task failed");
}

/// A request the service cannot parse is answered `InvalidCommand` and recorded, rather than
/// answered without reaching the operation latency metric at all.
#[tokio::test]
async fn unparseable_request_is_rejected() {
    const UNKNOWN_OPCODE: QuicOpCode = 99;

    let (_immutable_store, _mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");
    lore_spawn!(LORE_CONTEXT.scope(execution.clone(), async move {
        let mut harness = serve_and_connect(
            Box::new(SingleServiceFactory::new(
                MOCK_PROTOCOL,
                || MockService,
                test_limits(),
            )),
            MOCK_PROTOCOL,
        )
        .await;

        harness
            .send
            .write(&CommandHeader::new(UNKNOWN_OPCODE, 1, 0).to_bytes())
            .await
            .expect("Failed to write header");
        harness.send.flush().await.expect("Failed flush");

        let response = response(&mut harness.recv).await;
        assert_eq!(response.command_id, 1, "got: {response:?}");
        assert!(
            response.error,
            "expected an error response, got: {response:?}"
        );
        assert_eq!(
            response.size_or_status,
            QuicServiceError::InvalidCommand as u32,
            "expected InvalidCommand for a request the service cannot parse"
        );

        harness.send.finish().expect("Failed to finish stream");
    }))
    .await
    .expect("Test task failed");
}

/// Both the stream permit and the connection admission count come back down when a request
/// completes, so capacity does not degrade as requests are served.
///
/// The limits leave slack of one because the spawned task answers before releasing, so a
/// client can see its response a moment ahead of the release.
#[tokio::test]
async fn permits_are_released_when_a_request_completes() {
    const REQUESTS: u32 = 20;

    let (_immutable_store, _mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");
    lore_spawn!(LORE_CONTEXT.scope(execution.clone(), async move {
        let mut harness = serve_and_connect(
            Box::new(SingleServiceFactory::new(
                MOCK_PROTOCOL,
                || MockService,
                AdmissionLimits {
                    process_limit: 2,
                    inflight_limit: 2,
                    ..test_limits()
                },
            )),
            MOCK_PROTOCOL,
        )
        .await;

        for command_id in 1..=REQUESTS {
            request(&mut harness.send, MockBehaviour::Echo, command_id).await;
            let served = response(&mut harness.recv).await;
            assert_eq!(served.command_id, command_id, "got: {served:?}");
            assert!(
                !served.error,
                "request {command_id} was refused, so a permit from an earlier request was \
                     never released: {served:?}"
            );
        }

        harness.send.finish().expect("Failed to finish stream");
    }))
    .await
    .expect("Test task failed");
}

/// Each stream has its own permit pool, so saturating one does not refuse work on another
/// stream of the same connection.
#[tokio::test]
async fn stream_permit_pools_are_independent() {
    const PERMIT_TIMEOUT: Duration = Duration::from_millis(200);

    let (_immutable_store, _mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");
    lore_spawn!(LORE_CONTEXT.scope(execution.clone(), async move {
        let mut harness = serve_and_connect(
            Box::new(SingleServiceFactory::new(
                MOCK_PROTOCOL,
                || MockService,
                AdmissionLimits {
                    process_limit: 1,
                    inflight_limit: 8,
                    handler_timeout: Some(Duration::from_secs(30)),
                    permit_timeout: Some(PERMIT_TIMEOUT),
                },
            )),
            MOCK_PROTOCOL,
        )
        .await;
        let (mut send_b, mut recv_b) = harness.open_stream().await;

        // Occupy the first stream's only permit, then have it refuse a second request.
        for command_id in [1, 2] {
            request(&mut harness.send, MockBehaviour::Block, command_id).await;
        }
        let refused = response(&mut harness.recv).await;
        assert_eq!(refused.command_id, 2, "got: {refused:?}");
        assert_eq!(
            refused.size_or_status,
            QuicServiceError::SlowDown as u32,
            "the saturated stream should refuse its second request"
        );

        request(&mut send_b, MockBehaviour::Echo, 3).await;
        let served = response(&mut recv_b).await;
        assert_eq!(served.command_id, 3, "got: {served:?}");
        assert!(
            !served.error,
            "a second stream was refused while the first was saturated, so the permit pool \
                 is shared across the connection rather than per stream: {served:?}"
        );

        harness.send.finish().expect("Failed to finish stream");
        send_b.finish().expect("Failed to finish stream");
    }))
    .await
    .expect("Test task failed");
}

#[tokio::test]
async fn test_v4_authorize_put_get_query_stop() {
    use lore_base::types::Fragment;
    use lore_transport::quic::command_header::COMMAND_HEADER_SIZE_V4;

    let repository = random::<Context>();

    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");

    let (fragment, address, payload) = generate_random();
    let (_, other_address, _) = generate_random();

    lore_spawn!(LORE_CONTEXT.scope(execution.clone(), async move {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = socket.local_addr().expect("Failed socket setup");
        drop(socket);

        let client_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let (cert_path, key_path, _) = server_certs().expect("Bad cert paths");

        let _server = QuinnServer::start(
            QuinnConfigBuilder::new()
                .address(server_addr)
                .cert_file(cert_path)
                .pkey_file(key_path)
                .stream_handler_factory(Box::new(TestHandlerFactory::new(
                    immutable_store,
                    mutable_store,
                )))
                .build()
                .unwrap(),
        )
        .expect("Failed Quinn server start");

        let mut crypto_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(insecure_client_auth::SkipServerVerification::new())
            .with_no_client_auth();

        crypto_config.alpn_protocols = [TEST_PROTOCOL_V4]
            .iter()
            .map(|alpn| alpn.as_bytes().into())
            .collect();

        let client_config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto_config).expect("Failed client config"),
        ));

        let mut endpoint = Endpoint::client(client_addr).expect("Failed to create client endpoint");
        endpoint.set_default_client_config(client_config);

        let connection = endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .expect("Failed to setup bidirectional channel");

        let mut cmd_id: u32 = 0;
        let mut next_cmd_id = || {
            cmd_id += 1;
            cmd_id
        };

        // Helper: send a v4 command and read the response header
        async fn send_v4_cmd(
            send: &mut quinn::SendStream,
            recv: &mut quinn::RecvStream,
            header: CommandHeader,
            payload: &[u8],
        ) -> CommandHeader {
            send.write(&header.to_bytes_v4())
                .await
                .expect("write header");
            send.write(payload).await.expect("write payload");
            send.flush().await.expect("flush");

            let mut buf = [0u8; COMMAND_HEADER_SIZE_V4];
            recv.read_exact(&mut buf).await.expect("read response");
            CommandHeader::from_bytes_v4(&buf)
        }

        // Helper: read response payload
        async fn read_payload(recv: &mut quinn::RecvStream, len: usize) -> Vec<u8> {
            let mut buf = vec![0u8; len];
            recv.read_exact(&mut buf).await.expect("read payload");
            buf
        }

        // === Authorize Start ===
        let corr_id = b"test-corr-id";
        let mut auth_payload = Vec::new();
        auth_payload.push(0u8); // action = start
        auth_payload.extend_from_slice(repository.as_bytes());
        auth_payload.push(corr_id.len() as u8);
        auth_payload.extend_from_slice(corr_id);
        auth_payload.extend_from_slice(&0u16.to_le_bytes()); // no token

        let id = next_cmd_id();
        let resp = send_v4_cmd(
            &mut send,
            &mut recv,
            CommandHeader::new_with_session(
                Command::Authorize as QuicOpCode,
                id,
                auth_payload.len(),
                0,
            ),
            &auth_payload,
        )
        .await;

        assert!(!resp.error, "Authorize start failed: {resp:?}");
        assert_eq!(resp.size_or_status, 4);
        let session_id_bytes = read_payload(&mut recv, 4).await;
        let session_id = u32::from_le_bytes(session_id_bytes.try_into().unwrap());
        assert!(session_id >= 1);

        // === Put a fragment via the protocol ===
        let mut put_payload = Vec::new();
        put_payload.extend_from_slice(address.as_bytes());
        put_payload.extend_from_slice(fragment.as_bytes());
        put_payload.extend_from_slice(&payload);

        let id = next_cmd_id();
        let resp = send_v4_cmd(
            &mut send,
            &mut recv,
            CommandHeader::new_with_session(
                Command::Put as QuicOpCode,
                id,
                put_payload.len(),
                session_id,
            ),
            &put_payload,
        )
        .await;

        assert!(!resp.error, "Put failed: {resp:?}");
        assert_eq!(resp.command_id, id);
        assert_eq!(resp.session_id, session_id);
        assert_eq!(resp.size_or_status, 0); // empty response

        // === Get the fragment we just put ===
        let get_payload = address.as_bytes().to_vec();
        let id = next_cmd_id();
        let resp = send_v4_cmd(
            &mut send,
            &mut recv,
            CommandHeader::new_with_session(
                Command::Get as QuicOpCode,
                id,
                get_payload.len(),
                session_id,
            ),
            &get_payload,
        )
        .await;

        assert!(!resp.error, "Get failed: {resp:?}");
        assert_eq!(resp.command_id, id);
        assert_eq!(resp.session_id, session_id);
        assert!(resp.size_or_status > 0);

        let get_data = read_payload(&mut recv, resp.size_or_status as usize).await;
        // Response is Fragment + payload bytes
        assert!(get_data.len() >= size_of::<Fragment>());
        let returned_payload = &get_data[size_of::<Fragment>()..];
        assert_eq!(returned_payload, payload.as_ref());

        // === Get a non-existent address should fail ===
        let other_get_payload = other_address.as_bytes().to_vec();
        let id = next_cmd_id();
        let resp = send_v4_cmd(
            &mut send,
            &mut recv,
            CommandHeader::new_with_session(
                Command::Get as QuicOpCode,
                id,
                other_get_payload.len(),
                session_id,
            ),
            &other_get_payload,
        )
        .await;

        assert!(resp.error, "Get non-existent should fail");
        assert_eq!(resp.command_id, id);
        // NotFound = 4
        assert_eq!(resp.size_or_status, 4);

        // === Query: one existing, one non-existent ===
        let mut query_payload = Vec::new();
        query_payload.extend_from_slice(address.as_bytes());
        query_payload.extend_from_slice(other_address.as_bytes());

        let id = next_cmd_id();
        let resp = send_v4_cmd(
            &mut send,
            &mut recv,
            CommandHeader::new_with_session(
                Command::Query as QuicOpCode,
                id,
                query_payload.len(),
                session_id,
            ),
            &query_payload,
        )
        .await;

        assert!(!resp.error, "Query failed: {resp:?}");
        assert_eq!(resp.command_id, id);
        assert_eq!(resp.size_or_status, 2); // 2 results, one byte each

        let query_results = read_payload(&mut recv, 2).await;
        assert_eq!(query_results[0], 0); // ExistFullMatch for the put address
        assert_eq!(query_results[1], 3); // NotFound for other address

        // === Second session with different correlation ID ===
        let corr_id_2 = b"test-corr-id-2";
        let mut auth_payload_2 = Vec::new();
        auth_payload_2.push(0u8); // action = start
        auth_payload_2.extend_from_slice(repository.as_bytes());
        auth_payload_2.push(corr_id_2.len() as u8);
        auth_payload_2.extend_from_slice(corr_id_2);
        auth_payload_2.extend_from_slice(&0u16.to_le_bytes()); // no token

        let id = next_cmd_id();
        let resp = send_v4_cmd(
            &mut send,
            &mut recv,
            CommandHeader::new_with_session(
                Command::Authorize as QuicOpCode,
                id,
                auth_payload_2.len(),
                0,
            ),
            &auth_payload_2,
        )
        .await;

        assert!(!resp.error, "Authorize start session 2 failed: {resp:?}");
        assert_eq!(resp.size_or_status, 4);
        let session_id_2_bytes = read_payload(&mut recv, 4).await;
        let session_id_2 = u32::from_le_bytes(session_id_2_bytes.try_into().unwrap());
        assert!(session_id_2 >= 1);
        assert_ne!(session_id_2, session_id, "Sessions must have different IDs");

        // === Put a second fragment via session 2 ===
        let (fragment2, address2, payload2) = generate_random();
        let mut put_payload_2 = Vec::new();
        put_payload_2.extend_from_slice(address2.as_bytes());
        put_payload_2.extend_from_slice(fragment2.as_bytes());
        put_payload_2.extend_from_slice(&payload2);

        let id = next_cmd_id();
        let resp = send_v4_cmd(
            &mut send,
            &mut recv,
            CommandHeader::new_with_session(
                Command::Put as QuicOpCode,
                id,
                put_payload_2.len(),
                session_id_2,
            ),
            &put_payload_2,
        )
        .await;

        assert!(!resp.error, "Put via session 2 failed: {resp:?}");
        assert_eq!(resp.session_id, session_id_2);

        // === Get fragment via session 2 ===
        let get_payload_2 = address2.as_bytes().to_vec();
        let id = next_cmd_id();
        let resp = send_v4_cmd(
            &mut send,
            &mut recv,
            CommandHeader::new_with_session(
                Command::Get as QuicOpCode,
                id,
                get_payload_2.len(),
                session_id_2,
            ),
            &get_payload_2,
        )
        .await;

        assert!(!resp.error, "Get via session 2 failed: {resp:?}");
        assert_eq!(resp.session_id, session_id_2);
        assert!(resp.size_or_status > 0);

        let get_data_2 = read_payload(&mut recv, resp.size_or_status as usize).await;
        let returned_payload_2 = &get_data_2[size_of::<Fragment>()..];
        assert_eq!(returned_payload_2, payload2.as_ref());

        // === Copy via session 1: copy fragment2 within same repo ===
        let mut copy_payload = Vec::new();
        copy_payload.extend_from_slice(repository.as_bytes()); // source_repo (16 bytes)
        copy_payload.extend_from_slice(address2.hash.as_bytes()); // source hash (32 bytes)
        copy_payload.extend_from_slice(address2.context.as_bytes()); // source context (16 bytes)
        // v4 wire bumped Copy to 80 bytes — append target_context. This test preserves
        // the source's context so the destination tuple is the same as the source's
        // (cross-partition copy) — matching the legacy semantics.
        copy_payload.extend_from_slice(address2.context.as_bytes()); // target context (16 bytes)

        let id = next_cmd_id();
        let resp = send_v4_cmd(
            &mut send,
            &mut recv,
            CommandHeader::new_with_session(
                Command::Copy as QuicOpCode,
                id,
                copy_payload.len(),
                session_id,
            ),
            &copy_payload,
        )
        .await;

        assert!(!resp.error, "Copy via session 1 failed: {resp:?}");
        assert_eq!(resp.session_id, session_id);

        // === GetMetadata via session 2: both addresses should exist ===
        let mut query_payload_2 = Vec::new();
        query_payload_2.extend_from_slice(address.as_bytes());
        query_payload_2.extend_from_slice(address2.as_bytes());

        let id = next_cmd_id();
        let resp = send_v4_cmd(
            &mut send,
            &mut recv,
            CommandHeader::new_with_session(
                Command::Query as QuicOpCode,
                id,
                query_payload_2.len(),
                session_id_2,
            ),
            &query_payload_2,
        )
        .await;

        assert!(!resp.error, "GetMetadata via session 2 failed: {resp:?}");
        assert_eq!(resp.size_or_status, 2);
        let query_results_2 = read_payload(&mut recv, 2).await;
        assert_eq!(query_results_2[0], 0, "address from session 1 should exist");
        assert_eq!(query_results_2[1], 0, "address from session 2 should exist");

        // === Authorize Stop session 1 ===
        let id = next_cmd_id();
        let resp = send_v4_cmd(
            &mut send,
            &mut recv,
            CommandHeader::new_with_session(Command::Authorize as QuicOpCode, id, 1, session_id),
            &[1u8], // action = stop
        )
        .await;

        assert!(!resp.error, "Authorize stop session 1 failed: {resp:?}");
        assert_eq!(resp.size_or_status, 0);

        // === Session 2 should still work after session 1 stopped ===
        let id = next_cmd_id();
        let resp = send_v4_cmd(
            &mut send,
            &mut recv,
            CommandHeader::new_with_session(
                Command::Get as QuicOpCode,
                id,
                get_payload_2.len(),
                session_id_2,
            ),
            &get_payload_2,
        )
        .await;

        assert!(
            !resp.error,
            "Get via session 2 after session 1 stopped should work"
        );
        let _ = read_payload(&mut recv, resp.size_or_status as usize).await;

        // === Get with stopped session 1 should fail ===
        let id = next_cmd_id();
        let resp = send_v4_cmd(
            &mut send,
            &mut recv,
            CommandHeader::new_with_session(
                Command::Get as QuicOpCode,
                id,
                get_payload.len(),
                session_id,
            ),
            &get_payload,
        )
        .await;

        assert!(resp.error, "Get on stopped session 1 should fail");

        // === Authorize Stop session 2 ===
        let id = next_cmd_id();
        let resp = send_v4_cmd(
            &mut send,
            &mut recv,
            CommandHeader::new_with_session(Command::Authorize as QuicOpCode, id, 1, session_id_2),
            &[1u8], // action = stop
        )
        .await;

        assert!(!resp.error, "Authorize stop session 2 failed: {resp:?}");

        send.finish().expect("Failed to finish stream");
    }))
    .await
    .expect("Test task failed");
}

/// Exercise both dispatchers over actual QUIC streams, including denied storage state.
#[tokio::test]
async fn authenticated_storage_permission_matrix_on_both_protocols() {
    use lore_base::types::Hash;
    use lore_base::types::KeyType;
    use lore_base::types::RepositoryId;
    use lore_server::auth::jwk::JWKService;
    use lore_server::auth::jwk::JWKServiceError;
    use lore_server::auth::jwt::AuthorizationToken;
    use lore_server::auth::jwt::JwtVerifier;
    use lore_server::auth::jwt::ResourcePermission;
    use lore_server::authnz::global_grants_authorizer::GlobalGrantsAuthorizer;
    use lore_server::authnz::repository_authorizer::AuthClientAuthorizer;
    use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
    use lore_server::authnz::resource_grants_authorizer::ResourceGrantsAuthorizer;
    use lore_transport::quic::command_header::COMMAND_HEADER_SIZE_V4;
    use serde_json::json;

    struct Keys;
    #[async_trait::async_trait]
    impl JWKService for Keys {
        fn get_cached_key(
            &self,
            _kid: &str,
        ) -> Option<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm)> {
            Some((
                jsonwebtoken::DecodingKey::from_secret(b"permission-test"),
                jsonwebtoken::Algorithm::HS256,
            ))
        }
        async fn get_key(
            &self,
            kid: &str,
        ) -> Result<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm), JWKServiceError> {
            Ok(self.get_cached_key(kid).unwrap())
        }
        async fn refresh_key(
            &self,
            kid: &str,
        ) -> Result<Option<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm)>, JWKServiceError>
        {
            Ok(self.get_cached_key(kid))
        }
    }
    async fn send_command(
        harness: &mut Harness,
        v4: bool,
        command: Command,
        session: u32,
        payload: &[u8],
    ) -> CommandHeader {
        let header = CommandHeader::new_with_session(
            command as QuicOpCode,
            random::<u32>(),
            payload.len(),
            session,
        );
        let bytes = if v4 {
            header.to_bytes_v4().to_vec()
        } else {
            header.to_bytes().to_vec()
        };
        harness.send.write_all(&bytes).await.unwrap();
        harness.send.write_all(payload).await.unwrap();
        harness.send.flush().await.unwrap();
        let mut response = vec![0u8; if v4 { COMMAND_HEADER_SIZE_V4 } else { 8 }];
        harness.recv.read_exact(&mut response).await.unwrap();
        if v4 {
            CommandHeader::from_bytes_v4(&response)
        } else {
            CommandHeader::from_bytes(&response)
        }
    }
    async fn drain(harness: &mut Harness, header: &CommandHeader) -> Vec<u8> {
        if header.error {
            return vec![];
        }
        let mut bytes = vec![0; header.size_or_status as usize];
        harness.recv.read_exact(&mut bytes).await.unwrap();
        bytes
    }

    for v4 in [false, true] {
        for tier in 0..3 {
            for (actions, read, write) in [
                (vec![], false, false),
                (vec!["unknown"], false, false),
                (vec!["read"], true, false),
                (vec!["write"], true, true),
                (vec!["admin"], true, true),
                (vec!["owner"], true, true),
            ] {
                let (immutable, mutable, execution) = test_store_create().await.unwrap();
                Box::pin(LORE_CONTEXT.scope(execution, async move {
                    let repository = random::<RepositoryId>();
                    let authorizer: Arc<dyn RepositoryAuthorizer> = match tier {
                        0 => Arc::new(GlobalGrantsAuthorizer::new(Some("roles".into()))),
                        1 => Arc::new(ResourceGrantsAuthorizer::new(
                            "resources".into(),
                            "resource_id".into(),
                            None,
                            "urc-{id}".into(),
                            "urc-*".into(),
                        )),
                        _ => Arc::new(AuthClientAuthorizer::new("https://auth.invalid".into())),
                    };
                    let claims = AuthorizationToken {
                        user_id: "reader".into(),
                        audience: vec!["test".into()],
                        expires: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            + 60,
                        resources: Some(vec![ResourcePermission {
                            resource_id: format!("urc-{repository}"),
                            permission: actions.iter().map(|action| action.to_string()).collect(),
                        }]),
                        extra: json!({"roles": actions}).as_object().unwrap().clone(),
                        ..Default::default()
                    };
                    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
                    header.kid = Some("key".into());
                    let token = jsonwebtoken::encode(
                        &header,
                        &claims,
                        &jsonwebtoken::EncodingKey::from_secret(b"permission-test"),
                    )
                    .unwrap();
                    let verifier = JwtVerifier {
                        jwk_service: Arc::new(Keys),
                        jwt_issuer: None,
                        jwt_audience: Some(vec!["test".into()]),
                        jwt_typ: None,
                        identity_claim: "sub".into(),
                    };
                    let factory = TestHandlerFactory::with_authorization(
                        immutable.clone(),
                        mutable.clone(),
                        Arc::new(Some(verifier)),
                        authorizer,
                    );
                    let mut harness = serve_and_connect(
                        Box::new(factory),
                        if v4 { TEST_PROTOCOL_V4 } else { TEST_PROTOCOL },
                    )
                    .await;
                    let mut auth = vec![];
                    if v4 {
                        auth.push(0);
                    }
                    auth.extend_from_slice(repository.data());
                    if v4 {
                        auth.push(0);
                        auth.extend_from_slice(&(token.len() as u16).to_le_bytes());
                    }
                    auth.extend_from_slice(token.as_bytes());
                    let response =
                        send_command(&mut harness, v4, Command::Authorize, 0, &auth).await;
                    assert_eq!(
                        !response.error, read,
                        "v4={v4}, tier={tier}, actions={actions:?}"
                    );
                    if !read {
                        return;
                    }
                    let response_bytes = drain(&mut harness, &response).await;
                    let session = if v4 {
                        u32::from_le_bytes(response_bytes.try_into().unwrap())
                    } else {
                        0
                    };
                    let (fragment, address, payload) = generate_random();
                    immutable
                        .clone()
                        .put(repository, address, fragment, Some(payload.clone()), false)
                        .await
                        .unwrap();
                    let response =
                        send_command(&mut harness, v4, Command::Get, session, address.as_bytes())
                            .await;
                    assert!(!response.error);
                    drain(&mut harness, &response).await;
                    let (new_fragment, new_address, new_payload) = generate_random();
                    let mut put = new_address.as_bytes().to_vec();
                    put.extend_from_slice(new_fragment.as_bytes());
                    put.extend_from_slice(&new_payload);
                    let response =
                        send_command(&mut harness, v4, Command::Put, session, &put).await;
                    assert_eq!(!response.error, write);
                    drain(&mut harness, &response).await;
                    assert_eq!(
                        immutable.clone().get(repository, new_address).await.is_ok(),
                        write
                    );
                    let key = random::<Hash>();
                    let value = random::<Hash>();
                    let mut store = key.as_bytes().to_vec();
                    store.extend_from_slice(value.as_bytes());
                    store.push(KeyType::Resolve as u8);
                    let response =
                        send_command(&mut harness, v4, Command::MutableStore, session, &store)
                            .await;
                    assert_eq!(!response.error, write);
                    drain(&mut harness, &response).await;
                    assert_eq!(
                        mutable
                            .clone()
                            .load(repository, key, KeyType::Resolve)
                            .await
                            .unwrap_or_default(),
                        if write { value } else { Hash::default() }
                    );
                    mutable
                        .clone()
                        .store(repository, key, value, KeyType::Resolve)
                        .await
                        .unwrap();
                    let changed = random::<Hash>();
                    let mut cas = key.as_bytes().to_vec();
                    cas.extend_from_slice(value.as_bytes());
                    cas.extend_from_slice(changed.as_bytes());
                    cas.push(KeyType::Resolve as u8);
                    let response =
                        send_command(&mut harness, v4, Command::MutableCas, session, &cas).await;
                    assert_eq!(!response.error, write);
                    drain(&mut harness, &response).await;
                    assert_eq!(
                        mutable
                            .clone()
                            .load(repository, key, KeyType::Resolve)
                            .await
                            .unwrap(),
                        if write { changed } else { value }
                    );
                    let mut copy = repository.data().to_vec();
                    copy.extend_from_slice(address.as_bytes());
                    if v4 {
                        copy.extend_from_slice(random::<Context>().as_bytes());
                    }
                    let response =
                        send_command(&mut harness, v4, Command::Copy, session, &copy).await;
                    assert_eq!(!response.error, write);
                    drain(&mut harness, &response).await;
                    if v4 {
                        let resolve_key = random::<Hash>();
                        let mut resolved = resolve_key.as_bytes().to_vec();
                        resolved.extend_from_slice(&put);
                        let response = send_command(
                            &mut harness,
                            v4,
                            Command::PutResolved,
                            session,
                            &resolved,
                        )
                        .await;
                        assert_eq!(!response.error, write);
                        drain(&mut harness, &response).await;
                        assert_eq!(
                            mutable
                                .clone()
                                .load(repository, resolve_key, KeyType::Resolve)
                                .await
                                .unwrap_or_default(),
                            if write {
                                new_address.hash
                            } else {
                                Hash::default()
                            }
                        );
                        mutable
                            .clone()
                            .store(repository, resolve_key, value, KeyType::Resolve)
                            .await
                            .unwrap();
                        let mut deletion = resolve_key.as_bytes().to_vec();
                        deletion.extend_from_slice(&[0u8; 48 + 16]);
                        let response = send_command(
                            &mut harness,
                            v4,
                            Command::PutResolved,
                            session,
                            &deletion,
                        )
                        .await;
                        assert_eq!(!response.error, write);
                        drain(&mut harness, &response).await;
                        assert_eq!(
                            mutable
                                .clone()
                                .load(repository, resolve_key, KeyType::Resolve)
                                .await
                                .unwrap_or_default(),
                            if write { Hash::default() } else { value }
                        );
                    }
                    harness.send.finish().unwrap();
                }))
                .await;
            }
        }
    }
}

mod authorization_expiry {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    use lore_base::types::RepositoryId;
    use lore_server::auth::jwk::JWKService;
    use lore_server::auth::jwk::JWKServiceError;
    use lore_server::auth::jwt::AuthorizationToken;
    use lore_server::auth::jwt::JwtVerifier;
    use lore_server::auth::jwt::ResourcePermission;
    use lore_server::authnz::repository_authorizer::AuthClientAuthorizer;
    use lore_transport::connection::SuppliedCredentials;
    use lore_transport::error::ProtocolError;
    use lore_transport::quic::client::ServiceClient;
    use lore_transport::quic::storage_service::auth::StorageClientAuth;
    use lore_transport::quic::storage_service::client::StorageClient;
    use lore_transport::session::SessionAuthorization;
    use lore_transport::traits::Storage;

    use super::*;

    struct Keys;
    #[async_trait]
    impl JWKService for Keys {
        fn get_cached_key(
            &self,
            _: &str,
        ) -> Option<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm)> {
            Some((
                jsonwebtoken::DecodingKey::from_secret(b"expiry-test"),
                jsonwebtoken::Algorithm::HS256,
            ))
        }
        async fn get_key(
            &self,
            kid: &str,
        ) -> Result<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm), JWKServiceError> {
            Ok(self.get_cached_key(kid).unwrap())
        }
        async fn refresh_key(
            &self,
            kid: &str,
        ) -> Result<Option<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm)>, JWKServiceError>
        {
            Ok(self.get_cached_key(kid))
        }
    }
    fn verifier() -> Arc<Option<JwtVerifier>> {
        Arc::new(Some(JwtVerifier {
            jwk_service: Arc::new(Keys),
            jwt_issuer: None,
            jwt_audience: Some(vec!["expiry".into()]),
            jwt_typ: None,
            identity_claim: "sub".into(),
        }))
    }
    fn token(expires: u64, repositories: &[RepositoryId], action: &str) -> String {
        let claims = AuthorizationToken {
            user_id: "expiry-user".into(),
            audience: vec!["expiry".into()],
            expires,
            resources: Some(
                repositories
                    .iter()
                    .map(|repository| ResourcePermission {
                        resource_id: format!("urc-{repository}"),
                        permission: vec![action.into()],
                    })
                    .collect(),
            ),
            ..Default::default()
        };
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some("expiry-key".into());
        jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(b"expiry-test"),
        )
        .unwrap()
    }
    async fn command(
        harness: &mut Harness,
        v4: bool,
        command: Command,
        session: u32,
        payload: &[u8],
    ) -> (CommandHeader, Vec<u8>) {
        let header =
            CommandHeader::new_with_session(command as u8, random(), payload.len(), session);
        let bytes = if v4 {
            header.to_bytes_v4().to_vec()
        } else {
            header.to_bytes().to_vec()
        };
        harness.send.write_all(&bytes).await.unwrap();
        harness.send.write_all(payload).await.unwrap();
        harness.send.flush().await.unwrap();
        let mut response = vec![0; if v4 { 12 } else { 8 }];
        harness.recv.read_exact(&mut response).await.unwrap();
        let header = if v4 {
            CommandHeader::from_bytes_v4(&response)
        } else {
            CommandHeader::from_bytes(&response)
        };
        let mut data = vec![
            0;
            if header.error {
                0
            } else {
                header.size_or_status as usize
            }
        ];
        harness.recv.read_exact(&mut data).await.unwrap();
        (header, data)
    }
    async fn authorize(
        harness: &mut Harness,
        v4: bool,
        repository: RepositoryId,
        token: &str,
    ) -> u32 {
        let mut payload = if v4 { vec![0] } else { vec![] };
        payload.extend_from_slice(repository.data());
        if v4 {
            payload.push(0);
            payload.extend_from_slice(&(token.len() as u16).to_le_bytes());
        }
        payload.extend_from_slice(token.as_bytes());
        let (header, data) = command(harness, v4, Command::Authorize, 0, &payload).await;
        assert!(!header.error, "{header:?}");
        if v4 {
            u32::from_le_bytes(data.try_into().unwrap())
        } else {
            0
        }
    }

    #[tokio::test]
    async fn open_connections_reject_expired_reads_writes_and_cached_copies() {
        for v4 in [false, true] {
            let (immutable, mutable, execution) = test_store_create().await.unwrap();
            LORE_CONTEXT
                .scope(execution, async move {
                    let repository = random();
                    let source = random();
                    let expires = jsonwebtoken::get_current_timestamp() + 30;
                    let now = Arc::new(AtomicU64::new(expires));
                    let factory = TestHandlerFactory::with_authorization_clock(
                        immutable.clone(),
                        mutable,
                        verifier(),
                        Arc::new(AuthClientAuthorizer::new("https://auth.invalid".into())),
                        {
                            let now = now.clone();
                            Arc::new(move || now.load(Ordering::SeqCst))
                        },
                    );
                    let mut harness = serve_and_connect(
                        Box::new(factory),
                        if v4 { TEST_PROTOCOL_V4 } else { TEST_PROTOCOL },
                    )
                    .await;
                    let session = authorize(
                        &mut harness,
                        v4,
                        repository,
                        &token(expires, &[repository, source], "write"),
                    )
                    .await;
                    let valid_session = if v4 {
                        authorize(
                            &mut harness,
                            true,
                            repository,
                            &token(expires + 3600, &[repository], "read"),
                        )
                        .await
                    } else {
                        0
                    };
                    let (fragment, address, payload) = generate_random();
                    immutable
                        .clone()
                        .put(source, address, fragment, Some(payload), false)
                        .await
                        .unwrap();
                    let mut copy = source.data().to_vec();
                    copy.extend_from_slice(address.as_bytes());
                    if v4 {
                        copy.extend_from_slice(address.context.as_bytes());
                    }
                    assert!(
                        !command(&mut harness, v4, Command::Copy, session, &copy)
                            .await
                            .0
                            .error
                    );
                    assert!(
                        !command(&mut harness, v4, Command::Get, session, address.as_bytes())
                            .await
                            .0
                            .error
                    );
                    now.store(expires + 60, Ordering::SeqCst);
                    assert!(
                        !command(&mut harness, v4, Command::Get, session, address.as_bytes())
                            .await
                            .0
                            .error
                    );
                    let (new_fragment, new_address, new_payload) = generate_random();
                    let mut put = new_address.as_bytes().to_vec();
                    put.extend_from_slice(new_fragment.as_bytes());
                    put.extend_from_slice(&new_payload);
                    now.store(expires + 61, Ordering::SeqCst);
                    if !v4 {
                        // Reject reauthorization even before a storage command has observed
                        // expiry and installed the sticky retirement marker.
                        let mut reconnect = repository.data().to_vec();
                        reconnect.extend_from_slice(
                            token(expires + 3600, &[repository], "read").as_bytes(),
                        );
                        let (header, _) =
                            command(&mut harness, false, Command::Authorize, 0, &reconnect).await;
                        assert!(header.error);
                        assert_eq!(
                            header.size_or_status,
                            QuicServiceError::AuthorizationExpired as u32
                        );
                    }
                    for (operation, bytes) in [
                        (Command::Get, address.as_bytes()),
                        (Command::Put, put.as_slice()),
                        (Command::Copy, copy.as_slice()),
                    ] {
                        let (header, _) =
                            command(&mut harness, v4, operation, session, bytes).await;
                        assert!(header.error);
                        assert_eq!(
                            header.size_or_status,
                            QuicServiceError::AuthorizationExpired as u32
                        );
                    }
                    assert!(
                        immutable
                            .clone()
                            .get(repository, new_address)
                            .await
                            .is_err()
                    );
                    if v4 {
                        assert!(
                            !command(
                                &mut harness,
                                true,
                                Command::Get,
                                valid_session,
                                address.as_bytes()
                            )
                            .await
                            .0
                            .error
                        );
                        let reader = authorize(
                            &mut harness,
                            true,
                            repository,
                            &token(expires + 3600, &[repository], "read"),
                        )
                        .await;
                        assert!(
                            !command(&mut harness, true, Command::Get, reader, address.as_bytes())
                                .await
                                .0
                                .error
                        );
                        let (header, _) =
                            command(&mut harness, true, Command::Put, reader, &put).await;
                        assert_eq!(
                            header.size_or_status,
                            QuicServiceError::NotAuthorized as u32
                        );
                    }
                    if !v4 {
                        // A retired legacy connection must reject Connect before installing
                        // a fresh token; otherwise authorization would misleadingly succeed.
                        let mut reconnect = repository.data().to_vec();
                        reconnect.extend_from_slice(
                            token(expires + 3600, &[repository], "read").as_bytes(),
                        );
                        let (header, _) =
                            command(&mut harness, false, Command::Authorize, 0, &reconnect).await;
                        assert!(header.error);
                        assert_eq!(
                            header.size_or_status,
                            QuicServiceError::AuthorizationExpired as u32
                        );
                    }
                    now.store(expires - 1, Ordering::SeqCst);
                    assert_eq!(
                        command(&mut harness, v4, Command::Get, session, address.as_bytes())
                            .await
                            .0
                            .size_or_status,
                        QuicServiceError::AuthorizationExpired as u32
                    );
                })
                .await;
        }
    }

    async fn bounded<T>(label: &str, future: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(30), future)
            .await
            .unwrap_or_else(|_| panic!("timed out: {label}"))
    }

    #[tokio::test]
    async fn actual_client_recovers_once_with_latest_token_and_enforces_new_grants() {
        let (immutable, mutable, execution) = test_store_create().await.unwrap();
        bounded(
            "client recovery scenario",
            LORE_CONTEXT.scope(execution, async move {
                let repository = random::<RepositoryId>();
                let expires = jsonwebtoken::get_current_timestamp() + 30;
                let now = Arc::new(AtomicU64::new(expires));
                let factory = TestHandlerFactory::with_authorization_clock(
                    immutable.clone(),
                    mutable,
                    verifier(),
                    Arc::new(AuthClientAuthorizer::new("https://auth.invalid".into())),
                    {
                        let now = now.clone();
                        Arc::new(move || now.load(Ordering::SeqCst))
                    },
                );
                let mut harness = serve_and_connect_with_stream_limit(
                    Box::new(factory),
                    TEST_PROTOCOL_V4,
                    (STREAM_COUNT + 1) as u64,
                )
                .await;
                // The raw harness opens a stream of its own. Release that slot before
                // the real client fills the server's eight-stream connection limit.
                harness.send.finish().unwrap();
                harness.recv.stop(quinn::VarInt::from_u32(0)).unwrap();

                let credentials = Arc::new(SuppliedCredentials::new(
                    "",
                    &token(expires, &[repository], "write"),
                ));
                let adapter = Arc::new(StorageClientAuth {
                    recipient_domain: "localhost".into(),
                    auth_url: String::new(),
                    identity: "expiry-user".into(),
                    partition: repository,
                    user_agent: "expiry-test".into(),
                });
                let storage = Arc::new(StorageClient::new(
                    std::sync::Weak::new(),
                    "lores://localhost",
                    TransportConfig {
                        max_bytes_bandwidth_per_second: 1_000_000,
                        expected_rtt_ms: DEFAULT_EXPECTED_RTT_MS,
                        congestion_algorithm: CongestionAlgorithm::Bbr,
                        initial_cwnd: None,
                    },
                    adapter,
                    "",
                    "localhost",
                    "expiry-user",
                    repository,
                    harness.connection.clone(),
                    &credentials,
                ));
                bounded("create stream", storage.quic().create_initial_stream())
                    .await
                    .unwrap();

                storage.quic().stream_count.store(1, Ordering::Relaxed);
                let id = bounded("session start", storage.session_start(repository, "expiry"))
                    .await
                    .unwrap();

                let session = SessionAuthorization::new(
                    storage.clone(),
                    id,
                    repository,
                    "expiry".into(),
                    credentials.clone(),
                );
                let (fragment, address, payload) = generate_random();
                immutable
                    .clone()
                    .put(repository, address, fragment, Some(payload), false)
                    .await
                    .unwrap();
                assert!(
                    session
                        .execute(|storage, id| async move { storage.get(id, &address).await })
                        .await
                        .is_ok()
                );

                now.store(expires + 61, Ordering::SeqCst);
                assert!(matches!(
                    session
                        .execute(|storage, id| async move { storage.get(id, &address).await })
                        .await,
                    Err(ProtocolError::NotAuthenticated(_))
                ));

                credentials.update("", &token(expires + 3600, &[repository], "read"));
                assert!(
                    session
                        .execute(|storage, id| async move { storage.get(id, &address).await })
                        .await
                        .is_ok()
                );

                let (new_fragment, new_address, new_payload) = generate_random();
                assert!(matches!(
                    session
                        .execute(|storage, id| {
                            let payload = new_payload.clone();
                            async move {
                                storage
                                    .put(id, new_address, new_fragment, Some(payload))
                                    .await
                            }
                        })
                        .await,
                    Err(ProtocolError::NotAuthorized(_))
                ));
                assert!(immutable.get(repository, new_address).await.is_err());
            }),
        )
        .await;
    }
}
