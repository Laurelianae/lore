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
