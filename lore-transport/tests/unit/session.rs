// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use lore_transport::error::ProtocolError;
use lore_transport::session::*;

/// A lazy session whose resolver counts its calls and always fails with `error`, so how
/// often it is asked is what the test reads and what it resolves to is out of the way.
fn counting_session(calls: Arc<AtomicUsize>, error: ProtocolError) -> StorageSession {
    StorageSession::pending(move || {
        let calls = calls.clone();
        let error = error.clone();
        async move {
            calls.fetch_add(1, Ordering::Relaxed);
            Err(error)
        }
    })
}

/// One resolution serves every operation, a failure the caller cannot retry past being
/// held like a success.
#[tokio::test]
async fn a_lazy_session_resolves_once() {
    let calls = Arc::new(AtomicUsize::new(0));
    let session = counting_session(calls.clone(), ProtocolError::internal("nothing to resolve"));

    assert!(session.is_lazy());
    assert!(session.partition().await.is_err());
    assert!(session.partition().await.is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

/// The read path recovers a rotated server session map by invalidating the
/// session and retrying that same session, which only gets a `session_id` the
/// server knows about where the session resolves again.
#[tokio::test]
async fn an_invalidated_lazy_session_resolves_again() {
    let calls = Arc::new(AtomicUsize::new(0));
    let session = counting_session(calls.clone(), ProtocolError::internal("nothing to resolve"));

    assert!(session.partition().await.is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    session.invalidate().await;

    assert!(session.partition().await.is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

/// The read and write paths back off on `SlowDown` and retry the same session without
/// invalidating it, so a throttled `session_start` has to be asked again for the retry to
/// reach the server at all.
#[tokio::test]
async fn a_throttled_lazy_session_resolves_again() {
    let calls = Arc::new(AtomicUsize::new(0));
    let session = counting_session(
        calls.clone(),
        ProtocolError::from(lore_base::error::SlowDown),
    );

    let first = session.partition().await;
    let second = session.partition().await;

    assert!(first.is_err_and(|err| err.is_slow_down()));
    assert!(second.is_err_and(|err| err.is_slow_down()));
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

mod expiry_recovery {
    use async_trait::async_trait;
    use bytes::Bytes;
    use lore_base::error::NotAuthenticated;
    use lore_base::error::NotAuthorized;
    use lore_base::types::*;
    use lore_transport::connection::SuppliedCredentials;
    use lore_transport::traits::Storage;
    use parking_lot::Mutex;

    use super::*;

    struct TestStorage {
        credentials: Arc<SuppliedCredentials>,
        starts: AtomicUsize,
        calls: AtomicUsize,
        stopped: Mutex<Vec<u32>>,
        grants: Mutex<std::collections::HashMap<u32, String>>,
        deny: bool,
        expire_replay: bool,
    }

    #[async_trait]
    impl Storage for TestStorage {
        async fn session_start(&self, _: Partition, _: &str) -> Result<u32, ProtocolError> {
            let id = self.starts.fetch_add(1, Ordering::SeqCst) as u32 + 2;
            tokio::task::yield_now().await;
            let token = self.credentials.tokens().1;
            if token == "transient" && id == 2 {
                return Err(lore_base::error::SlowDown.into());
            }
            if token == "expired" {
                return Err(NotAuthenticated.into());
            }
            self.grants.lock().insert(id, token);
            Ok(id)
        }
        async fn session_stop(&self, id: u32) -> Result<(), ProtocolError> {
            self.stopped.lock().push(id);
            Ok(())
        }
        async fn query(&self, id: u32, _: &[Address]) -> Result<Bytes, ProtocolError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            if self.deny {
                return Err(NotAuthorized.into());
            }
            if id == 1 || self.expire_replay {
                return Err(NotAuthenticated.into());
            }
            Ok(Bytes::from_static(b"ok"))
        }
        async fn put(
            &self,
            id: u32,
            _: Address,
            _: Fragment,
            _: Option<Bytes>,
        ) -> Result<(), ProtocolError> {
            self.query(id, &[]).await?;
            if self
                .grants
                .lock()
                .get(&id)
                .is_some_and(|token| token == "reader")
            {
                return Err(NotAuthorized.into());
            }
            Ok(())
        }
        async fn get(&self, _: u32, _: &Address) -> Result<(Fragment, Bytes), ProtocolError> {
            unreachable!()
        }
        async fn verify(
            &self,
            _: u32,
            _: &Address,
            _: bool,
        ) -> Result<VerifyResult, ProtocolError> {
            unreachable!()
        }
        async fn copy(
            &self,
            _: u32,
            _: Partition,
            _: Address,
            _: Context,
        ) -> Result<(), ProtocolError> {
            unreachable!()
        }
    }

    fn fixture(
        token: &str,
        deny: bool,
        expire_replay: bool,
    ) -> (Arc<TestStorage>, Arc<SessionAuthorization>) {
        let credentials = Arc::new(SuppliedCredentials::new("", token));
        let storage = Arc::new(TestStorage {
            credentials: credentials.clone(),
            starts: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            stopped: Mutex::new(Vec::new()),
            grants: Mutex::new(Default::default()),
            deny,
            expire_replay,
        });
        let authorization = Arc::new(SessionAuthorization::new(
            storage.clone(),
            1,
            rand::random(),
            "corr".into(),
            credentials,
        ));
        (storage, authorization)
    }

    async fn query(authorization: &SessionAuthorization) -> Result<Bytes, ProtocolError> {
        authorization
            .execute(|storage, id| async move { storage.query(id, &[]).await })
            .await
    }

    #[tokio::test]
    async fn current_token_replaces_only_the_expired_session() {
        lore_base::runtime::LORE_CONTEXT
            .scope(Arc::new(()), async {
                let (storage, authorization) = fixture("writer", false, false);
                assert_eq!(
                    query(&authorization).await.unwrap(),
                    Bytes::from_static(b"ok")
                );
                assert_eq!(
                    query(&authorization).await.unwrap(),
                    Bytes::from_static(b"ok")
                );
                assert_eq!(storage.starts.load(Ordering::SeqCst), 1);
                assert_eq!(storage.calls.load(Ordering::SeqCst), 3);
                // Cleanup is scheduled on the net runtime, so wait for its observable outcome.
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    while storage.stopped.lock().is_empty() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                assert_eq!(*storage.stopped.lock(), vec![1]);
            })
            .await;
    }

    #[tokio::test]
    async fn expired_supplied_token_is_terminal_until_credentials_rotate() {
        lore_base::runtime::LORE_CONTEXT
            .scope(Arc::new(()), async {
                let (storage, authorization) = fixture("expired", false, false);
                for _ in 0..3 {
                    assert!(matches!(
                        query(&authorization).await,
                        Err(ProtocolError::NotAuthenticated(_))
                    ));
                }
                assert_eq!(storage.starts.load(Ordering::SeqCst), 1);
                storage.credentials.update("", "writer");
                assert!(query(&authorization).await.is_ok());
                assert_eq!(storage.starts.load(Ordering::SeqCst), 2);
            })
            .await;
    }

    #[tokio::test]
    async fn permission_denial_does_not_reauthorize() {
        lore_base::runtime::LORE_CONTEXT
            .scope(Arc::new(()), async {
                let (storage, authorization) = fixture("writer", true, false);
                assert!(matches!(
                    query(&authorization).await,
                    Err(ProtocolError::NotAuthorized(_))
                ));
                assert_eq!(storage.starts.load(Ordering::SeqCst), 0);
                assert_eq!(storage.calls.load(Ordering::SeqCst), 1);
            })
            .await;
    }

    #[tokio::test]
    async fn replacement_reader_cannot_replay_a_write() {
        lore_base::runtime::LORE_CONTEXT
            .scope(Arc::new(()), async {
                let (storage, authorization) = fixture("reader", false, false);
                let result = authorization
                    .execute(|storage, id| async move {
                        storage
                            .put(id, Address::default(), Fragment::default(), None)
                            .await
                    })
                    .await;
                assert!(matches!(result, Err(ProtocolError::NotAuthorized(_))));
                assert_eq!(storage.starts.load(Ordering::SeqCst), 1);
            })
            .await;
    }

    #[tokio::test]
    async fn expiry_on_replay_never_loops() {
        lore_base::runtime::LORE_CONTEXT
            .scope(Arc::new(()), async {
                let (storage, authorization) = fixture("writer", false, true);
                assert!(matches!(
                    query(&authorization).await,
                    Err(ProtocolError::NotAuthenticated(_))
                ));
                assert_eq!(storage.calls.load(Ordering::SeqCst), 2);
                assert!(matches!(
                    query(&authorization).await,
                    Err(ProtocolError::NotAuthenticated(_))
                ));
                assert_eq!(storage.starts.load(Ordering::SeqCst), 1);
            })
            .await;
    }

    #[tokio::test]
    async fn simultaneous_rejections_share_one_reauthorization() {
        lore_base::runtime::LORE_CONTEXT
            .scope(Arc::new(()), async {
                for token in ["writer", "expired"] {
                    let (storage, authorization) = fixture(token, false, false);
                    let mut tasks = tokio::task::JoinSet::new();
                    for _ in 0..32 {
                        let authorization = authorization.clone();
                        lore_base::lore_spawn!(tasks, async move { query(&authorization).await });
                    }
                    while let Some(result) = tasks.join_next().await {
                        let result = result.unwrap();
                        if token == "writer" {
                            assert!(result.is_ok());
                        } else {
                            assert!(matches!(result, Err(ProtocolError::NotAuthenticated(_))));
                        }
                    }
                    assert_eq!(storage.starts.load(Ordering::SeqCst), 1);
                }
            })
            .await;
    }
    #[tokio::test]
    async fn concurrent_expiry_on_replay_is_terminal_for_the_generation() {
        lore_base::runtime::LORE_CONTEXT
            .scope(Arc::new(()), async {
                let (storage, authorization) = fixture("writer", false, true);
                let mut tasks = tokio::task::JoinSet::new();
                for _ in 0..32 {
                    let authorization = authorization.clone();
                    lore_base::lore_spawn!(tasks, async move { query(&authorization).await });
                }
                while let Some(result) = tasks.join_next().await {
                    assert!(matches!(
                        result.unwrap(),
                        Err(ProtocolError::NotAuthenticated(_))
                    ));
                }
                assert_eq!(storage.starts.load(Ordering::SeqCst), 1);
            })
            .await;
    }

    #[tokio::test]
    async fn backpressure_during_refresh_remains_retryable() {
        lore_base::runtime::LORE_CONTEXT
            .scope(Arc::new(()), async {
                let (storage, authorization) = fixture("transient", false, false);
                assert!(matches!(
                    query(&authorization).await,
                    Err(ProtocolError::SlowDown(_))
                ));
                assert!(query(&authorization).await.is_ok());
                assert_eq!(storage.starts.load(Ordering::SeqCst), 2);
            })
            .await;
    }
    #[tokio::test]
    async fn waiting_rejection_refreshes_an_obsolete_concurrent_replacement() {
        lore_base::runtime::LORE_CONTEXT
            .scope(Arc::new(()), async {
                let (storage, authorization) = fixture("writer", false, false);
                let entered = Arc::new(tokio::sync::Notify::new());
                let release = Arc::new(tokio::sync::Notify::new());
                let waiting = {
                    let authorization = authorization.clone();
                    let entered = entered.clone();
                    let release = release.clone();
                    lore_base::lore_spawn!(async move {
                        authorization
                            .execute(|storage, id| {
                                let entered = entered.clone();
                                let release = release.clone();
                                async move {
                                    if id == 1 {
                                        entered.notify_one();
                                        release.notified().await;
                                        Err(NotAuthenticated.into())
                                    } else if id == 2 {
                                        // The concurrent replacement's old credential has expired.
                                        Err(NotAuthenticated.into())
                                    } else {
                                        storage.query(id, &[]).await
                                    }
                                }
                            })
                            .await
                    })
                };
                tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
                    .await
                    .unwrap();
                assert!(query(&authorization).await.is_ok()); // Establishes ID 2, generation 0.
                storage.credentials.update("", "fresh-writer");
                release.notify_one();
                assert!(
                    tokio::time::timeout(std::time::Duration::from_secs(5), waiting)
                        .await
                        .unwrap()
                        .unwrap()
                        .is_ok()
                );
                assert_eq!(storage.starts.load(Ordering::SeqCst), 2);
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    while storage.stopped.lock().len() < 2 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                let mut stopped = storage.stopped.lock().clone();
                stopped.sort_unstable();
                assert_eq!(stopped, vec![1, 2]);
            })
            .await;
    }

    #[tokio::test]
    async fn final_owner_stops_the_replacement_after_an_active_refresh() {
        lore_base::runtime::LORE_CONTEXT
            .scope(Arc::new(()), async {
                let (storage, authorization) = fixture("writer", false, false);
                let entered = Arc::new(tokio::sync::Notify::new());
                let release = Arc::new(tokio::sync::Notify::new());
                let active = {
                    let authorization = authorization.clone();
                    let entered = entered.clone();
                    let release = release.clone();
                    lore_base::lore_spawn!(async move {
                        authorization
                            .execute(|storage, id| {
                                let entered = entered.clone();
                                let release = release.clone();
                                async move {
                                    if id == 1 {
                                        entered.notify_one();
                                        release.notified().await;
                                    }
                                    storage.query(id, &[]).await
                                }
                            })
                            .await
                    })
                };
                tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
                    .await
                    .unwrap();
                // The handle owner goes away while the operation still owns authorization.
                drop(authorization);
                assert!(storage.stopped.lock().is_empty());
                release.notify_one();
                assert!(
                    tokio::time::timeout(std::time::Duration::from_secs(5), active)
                        .await
                        .unwrap()
                        .unwrap()
                        .is_ok()
                );
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    while storage.stopped.lock().len() < 2 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                let mut stopped = storage.stopped.lock().clone();
                stopped.sort_unstable();
                assert_eq!(stopped, vec![1, 2]);
            })
            .await;
    }
}

mod pooled {
    use std::time::Duration;

    use lore_base::lore_spawn_net;
    use lore_transport::connection::Connection;
    use tokio::task::JoinSet;

    use super::*;
    use crate::quic::storage_service::test_server::PAYLOAD_SIZE;
    use crate::quic::storage_service::test_server::TestStorageServer;
    use crate::quic::storage_service::test_server::test_address as address;
    use crate::quic::storage_service::test_server::test_partition as partition;
    use crate::quic::storage_service::test_server::wait_until;

    /// A pool of one resolved session per storage connection to `server`.
    async fn pool_over(server: &TestStorageServer, connections: usize) -> Arc<SessionPool> {
        let connection = Connection::detached(Vec::new());
        let correlation: Arc<str> = Arc::from("test");
        let sessions = server
            .connect_with_sessions(connections)
            .await
            .into_iter()
            .map(|(storage, session_id)| {
                Arc::new(StorageSession::resolved(
                    storage,
                    connection.clone(),
                    session_id,
                    partition(),
                    correlation.clone(),
                ))
            })
            .collect();
        Arc::new(SessionPool::new(correlation, sessions))
    }

    /// A lazy session resolving to a session over `pool`, counting its resolutions in `calls`.
    fn lazy_over(pool: Arc<SessionPool>, calls: Arc<AtomicUsize>) -> StorageSession {
        StorageSession::pending(move || {
            calls.fetch_add(1, Ordering::Relaxed);
            let pool = pool.clone();
            async move { Ok(Arc::new(StorageSession::pooled(pool))) }
        })
    }

    /// Fetches `count` distinct addresses through `session`, all of them in flight at once.
    async fn fetch_concurrently(session: &Arc<StorageSession>, count: usize) {
        let mut fetches = JoinSet::new();
        for index in 0..count {
            let session = session.clone();
            lore_spawn_net!(fetches, async move { session.get(&address(index)).await });
        }
        while let Some(fetched) = fetches.join_next().await {
            let (_, payload) = fetched.expect("fetch task").expect("fetch");
            assert_eq!(payload.len(), PAYLOAD_SIZE);
        }
    }

    /// The read paths hold one lazy session per repository for its lifetime. Resolving it to
    /// a pooled session is what spreads those reads.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_lazy_session_resolved_to_a_pool_spreads_requests() {
        let server = TestStorageServer::start();
        let calls = Arc::new(AtomicUsize::new(0));
        let session = lazy_over(pool_over(&server, 4).await, calls.clone());

        for index in 0..400 {
            session.get(&address(index)).await.expect("fetch");
        }

        assert_eq!(server.gets_per_connection(), vec![100, 100, 100, 100]);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    /// Every operation of a resolved lazy session reads what it resolved to without the lock its
    /// resolutions take.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_resolved_lazy_session_serves_while_its_resolution_lock_is_held() {
        let server = TestStorageServer::start();
        let session = lazy_over(pool_over(&server, 2).await, Arc::default());
        session.get(&address(0)).await.expect("fetch");

        let _held = session.hold_resolution().await.expect("a lazy session");
        tokio::time::timeout(Duration::from_secs(10), session.get(&address(1)))
            .await
            .expect("an operation waited for the resolution lock")
            .expect("fetch");

        assert_eq!(server.gets_per_connection(), vec![1, 1]);
    }

    /// Invalidating a resolved lazy session drops what it resolved to, so the next operation
    /// resolves again.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_invalidated_resolved_lazy_session_resolves_again() {
        let server = TestStorageServer::start();
        let calls = Arc::new(AtomicUsize::new(0));
        let session = lazy_over(pool_over(&server, 2).await, calls.clone());
        session.get(&address(0)).await.expect("fetch");

        session.invalidate().await;
        session
            .get(&address(1))
            .await
            .expect("fetch after the invalidation");

        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    /// Requests in flight at once are served by every connection at once: the server holds each
    /// until every connection has one, so the fetches finish only when the pool spreads them.
    #[tokio::test(flavor = "multi_thread")]
    async fn requests_in_flight_are_served_by_every_connection_at_once() {
        const CONNECTIONS: usize = 4;
        let server = TestStorageServer::start_gathering(CONNECTIONS);
        let session = Arc::new(StorageSession::pooled(
            pool_over(&server, CONNECTIONS).await,
        ));

        tokio::time::timeout(
            Duration::from_secs(30),
            fetch_concurrently(&session, 16 * CONNECTIONS),
        )
        .await
        .expect("a connection served no request while the others waited for it");

        assert_eq!(server.gets_per_connection(), vec![16; CONNECTIONS]);
    }

    /// A pool that fails to start on one connection stops the sessions it started on the others.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_pool_that_fails_to_start_stops_the_sessions_it_started() {
        let serving = TestStorageServer::start();
        let refusing = TestStorageServer::start_refusing_sessions();
        let mut connections = serving.connect(2).await;
        connections.extend(refusing.connect(1).await);
        let connector = StorageConnector::new(connections);

        let started = connector
            .session_pool(partition(), "test", Connection::detached(Vec::new()))
            .await;

        assert!(started.is_err_and(|err| err.is_slow_down()));
        // The refusal answers as soon as it arrives, while the serving starts race it as detached
        // tasks, so whether they have started their sessions yet when the error returns is a race.
        wait_until(
            || serving.started_sessions_per_connection() == [1, 1],
            "the session starts never reached the server",
        )
        .await;
        wait_until(
            || serving.live_sessions_per_connection() == [0, 0],
            "the sessions started on the serving connections were left open",
        )
        .await;
    }

    /// A pool start dropped while its session starts are in flight stops the sessions they open.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_dropped_pool_start_stops_the_sessions_in_flight() {
        let (server, release) = TestStorageServer::start_holding_session_starts();
        let connector = Arc::new(StorageConnector::new(server.connect(2).await));
        let starting = lore_spawn_net!({
            let connector = connector.clone();
            async move {
                connector
                    .session_pool(partition(), "test", Connection::detached(Vec::new()))
                    .await
            }
        });
        wait_until(
            || server.started_sessions_per_connection() == [1, 1],
            "the session starts never reached the server",
        )
        .await;

        starting.abort();
        assert!(starting.await.is_err_and(|err| err.is_cancelled()));
        release.send_replace(true);

        wait_until(
            || server.live_sessions_per_connection() == [0, 0],
            "the sessions the dropped start opened were left open",
        )
        .await;
    }

    /// A pool start dropped while one of its session starts is held stops each session already
    /// started without waiting for the held start to end.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_dropped_pool_start_stops_each_session_as_its_start_ends() {
        let serving = TestStorageServer::start();
        let (holding, release) = TestStorageServer::start_holding_session_starts();
        let mut connections = serving.connect(1).await;
        connections.extend(holding.connect(1).await);
        let connector = Arc::new(StorageConnector::new(connections));
        let starting = lore_spawn_net!({
            let connector = connector.clone();
            async move {
                connector
                    .session_pool(partition(), "test", Connection::detached(Vec::new()))
                    .await
            }
        });
        wait_until(
            || holding.started_sessions_per_connection() == [1],
            "the held session start never reached the server",
        )
        .await;

        starting.abort();
        assert!(starting.await.is_err_and(|err| err.is_cancelled()));

        wait_until(
            || serving.live_sessions_per_connection() == [0],
            "the started session was left open while another start was held",
        )
        .await;
        release.send_replace(true);
    }

    /// Pool starts racing for one partition under one correlation id all take the winner's pool,
    /// and the sessions the loser started stop. The second start begins once the first's starts
    /// reach the server, so each held start is on a stream of its own.
    #[tokio::test(flavor = "multi_thread")]
    async fn racing_pool_starts_share_the_winners_pool_and_stop_the_losers_sessions() {
        let (server, release) = TestStorageServer::start_holding_session_starts();
        let connector = Arc::new(StorageConnector::new(server.connect(2).await));
        let start = || {
            let connector = connector.clone();
            lore_spawn_net!(async move {
                connector
                    .session_pool(partition(), "test", Connection::detached(Vec::new()))
                    .await
            })
        };
        let first = start();
        wait_until(
            || server.started_sessions_per_connection() == [1, 1],
            "the first start never reached the server",
        )
        .await;
        let second = start();
        wait_until(
            || server.started_sessions_per_connection() == [2, 2],
            "the second start never reached the server",
        )
        .await;
        release.send_replace(true);

        let first = first.await.expect("joined").expect("a pool");
        let second = second.await.expect("joined").expect("a pool");
        assert!(Arc::ptr_eq(&first, &second));
        wait_until(
            || server.live_sessions_per_connection() == [1, 1],
            "the losing start's sessions were left open",
        )
        .await;
    }
}
