// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::ops::Add;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use async_trait::async_trait;
use bytes::Bytes;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use jsonwebtoken::encode;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_proto::ObliterateRequest;
use lore_revision::lore::RepositoryId;
use lore_server::auth::jwk::JWKService;
use lore_server::auth::jwk::JWKServiceError;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::auth::jwt::DEFAULT_IDENTITY_CLAIM;
use lore_server::auth::jwt::JwtVerifier;
use lore_server::auth::jwt::ResourcePermission;
use lore_server::authnz::resource_grants_authorizer::ResourceGrantsAuthorizer;
use lore_server::grpc::handlers::obliterate::*;
use lore_server::hooks::HookDispatcher;
use lore_storage::Fragment;
use lore_transport::grpc::REPOSITORY_ID_KEY;
use mockall::predicate::eq;
use rand::random;
use tonic::Code;
use tonic::Request;
use tonic::metadata::MetadataValue;

use crate::notification::testing::MockNotificationSender;
use crate::store::test_support::test_store_create;

const ALGORITHM: Algorithm = Algorithm::HS256;
const SIGNING_SECRET: &str = "obliterate-test-secret";

mockall::mock! {
    TestJWKService {}

    #[async_trait]
    impl JWKService for TestJWKService {
        async fn get_key(
            &self,
            kid: &str,
        ) -> Result<(DecodingKey, jsonwebtoken::Algorithm), JWKServiceError>;

        fn get_cached_key(
            &self,
            kid: &str,
        ) -> Option<(DecodingKey, jsonwebtoken::Algorithm)>;

        async fn refresh_key(
            &self,
            kid: &str,
        ) -> Result<Option<(DecodingKey, jsonwebtoken::Algorithm)>, JWKServiceError>;
    }
}

const TEST_AUDIENCE: &str = "lore-test";

fn make_verifier(jwk_service: MockTestJWKService) -> JwtVerifier {
    JwtVerifier {
        jwk_service: Arc::new(jwk_service),
        jwt_issuer: None,
        jwt_audience: Some(vec![TEST_AUDIENCE.to_string()]),
        jwt_typ: None,
        identity_claim: DEFAULT_IDENTITY_CLAIM.to_string(),
    }
}

fn make_jwt(resources: Option<Vec<ResourcePermission>>) -> String {
    let claims = AuthorizationToken {
        user_id: "test-user".to_string(),
        issuer: "test-issuer".to_string(),
        issued_at: 1,
        expires: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .add(Duration::from_secs(60))
            .as_secs(),
        audience: vec![TEST_AUDIENCE.to_string()],
        env: Some("test".to_string()),
        name: Some("test".to_string()),
        preferred_username: Some("test".to_string()),
        client_id: None,
        resources,
        groups: None,
        is_service_account: Some(false),
        idp: Some("test".to_string()),
        extra: Default::default(),
        identity: None,
    };
    sign_claims(&claims)
}

fn sign_claims(claims: &AuthorizationToken) -> String {
    let key = EncodingKey::from_secret(SIGNING_SECRET.as_ref());
    let mut header = Header::new(ALGORITHM);
    header.kid = Some("test-kid".to_string());
    encode(&header, claims, &key).unwrap()
}

fn good_key_service() -> MockTestJWKService {
    let mut service = MockTestJWKService::new();
    service
        .expect_get_key()
        .returning(|_| Ok((DecodingKey::from_secret(SIGNING_SECRET.as_ref()), ALGORITHM)));
    service
}

fn bad_key_service() -> MockTestJWKService {
    let mut service = MockTestJWKService::new();
    service
        .expect_get_key()
        .returning(|_| Err(JWKServiceError::NotFound));
    service
}

fn make_request(
    repository: RepositoryId,
    auth_header: Option<String>,
) -> Request<ObliterateRequest> {
    let mut request = Request::new(ObliterateRequest { address: None });
    request.metadata_mut().insert_bin(
        REPOSITORY_ID_KEY,
        tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
    );
    if let Some(token) = auth_header {
        let value: MetadataValue<tonic::metadata::Ascii> =
            format!("Bearer {token}").parse().unwrap();
        request.metadata_mut().insert("authorization", value);
    }
    request
}

#[tokio::test]
async fn proceeds_without_auth_when_no_verifier_configured() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, _) = test_store_create().await.unwrap();
    let mut notification = MockNotificationSender::new();
    notification.expect_obliterate().never();
    let notification = Arc::new(notification);
    let hook_dispatcher = HookDispatcher::empty();

    let err = handler(
        make_request(repository, None),
        Arc::new(ResourceGrantsAuthorizer::new(
            "resources".into(),
            "resource_id".into(),
            None,
            "urc-{id}".into(),
            "urc-*".into(),
        )),
        immutable_store,
        mutable_store,
        notification,
        &hook_dispatcher,
        &None.into(),
    )
    .await
    .unwrap_err();

    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn returns_unauthenticated_when_authorization_header_absent() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, _) = test_store_create().await.unwrap();
    let notification = Arc::new(MockNotificationSender::new());
    let hook_dispatcher = HookDispatcher::empty();
    // Key service not expected to be called — fail fast if it is
    let verifier = make_verifier(MockTestJWKService::new());

    let err = handler(
        make_request(repository, None),
        Arc::new(ResourceGrantsAuthorizer::new(
            "resources".into(),
            "resource_id".into(),
            None,
            "urc-{id}".into(),
            "urc-*".into(),
        )),
        immutable_store,
        mutable_store,
        notification,
        &hook_dispatcher,
        &Some(verifier).into(),
    )
    .await
    .unwrap_err();

    assert_eq!(err.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn returns_unauthenticated_for_unverifiable_token() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, _) = test_store_create().await.unwrap();
    let notification = Arc::new(MockNotificationSender::new());
    let hook_dispatcher = HookDispatcher::empty();
    let verifier = make_verifier(bad_key_service());

    let err = handler(
        make_request(repository, Some(make_jwt(None))),
        Arc::new(ResourceGrantsAuthorizer::new(
            "resources".into(),
            "resource_id".into(),
            None,
            "urc-{id}".into(),
            "urc-*".into(),
        )),
        immutable_store,
        mutable_store,
        notification,
        &hook_dispatcher,
        &Some(verifier).into(),
    )
    .await
    .unwrap_err();

    assert_eq!(err.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn returns_permission_denied_when_user_lacks_obliterate_permission() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, _) = test_store_create().await.unwrap();
    let notification = Arc::new(MockNotificationSender::new());
    let hook_dispatcher = HookDispatcher::empty();
    let verifier = make_verifier(good_key_service());
    // Token has resources for this repository but without the 'obliterate' permission
    let resources = vec![ResourcePermission {
        resource_id: format!("urc-{repository}"),
        permission: vec!["read".to_string(), "write".to_string()],
    }];

    let err = handler(
        make_request(repository, Some(make_jwt(Some(resources)))),
        Arc::new(ResourceGrantsAuthorizer::new(
            "resources".into(),
            "resource_id".into(),
            None,
            "urc-{id}".into(),
            "urc-*".into(),
        )),
        immutable_store,
        mutable_store,
        notification,
        &hook_dispatcher,
        &Some(verifier).into(),
    )
    .await
    .unwrap_err();

    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn returns_not_found_when_authorized_and_address_absent() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, _) = test_store_create().await.unwrap();
    let mut notification = MockNotificationSender::new();
    // The obliterate notification must not fire: the store returns not_found before we get there
    notification.expect_obliterate().never();
    let notification = Arc::new(notification);
    let hook_dispatcher = HookDispatcher::empty();
    let verifier = make_verifier(good_key_service());
    let resources = vec![ResourcePermission {
        resource_id: format!("urc-{repository}"),
        permission: vec!["read".to_string(), "obliterate".to_string()],
    }];

    let err = handler(
        make_request(repository, Some(make_jwt(Some(resources)))),
        Arc::new(ResourceGrantsAuthorizer::new(
            "resources".into(),
            "resource_id".into(),
            None,
            "urc-{id}".into(),
            "urc-*".into(),
        )),
        immutable_store,
        mutable_store,
        notification,
        &hook_dispatcher,
        &Some(verifier).into(),
    )
    .await
    .unwrap_err();

    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn succeeds_for_authorized_request_with_existing_address() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, _) = test_store_create().await.unwrap();

    // Write a fragment so the obliterate has something to act on
    let context: Context = rand::random();
    let payload = Bytes::from_static(b"test payload");
    let hash = lore_storage::hash::hash_slice(&payload);
    let address = Address { hash, context };
    immutable_store
        .clone()
        .put(
            repository,
            address,
            Fragment {
                flags: 0,
                size_payload: payload.len() as u32,
                size_content: payload.len() as u64,
            },
            Some(payload),
            false,
        )
        .await
        .unwrap();

    // Confirm the fragment is readable before obliterating it
    immutable_store
        .clone()
        .get(repository, address)
        .await
        .and_then(lore_storage::StoreGetData::into_payload)
        .expect("address should be present before obliterate");

    let mut notification = MockNotificationSender::new();
    notification
        .expect_obliterate()
        .with(eq(repository), eq(address))
        .return_once(|_, _| Ok(()));
    let notification = Arc::new(notification);
    let hook_dispatcher = HookDispatcher::empty();
    let verifier = make_verifier(good_key_service());
    let resources = vec![ResourcePermission {
        resource_id: format!("urc-{repository}"),
        permission: vec!["read".to_string(), "obliterate".to_string()],
    }];

    let mut request = Request::new(ObliterateRequest {
        address: Some(address.into()),
    });
    request.metadata_mut().insert_bin(
        REPOSITORY_ID_KEY,
        tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
    );
    let value: MetadataValue<tonic::metadata::Ascii> =
        format!("Bearer {}", make_jwt(Some(resources)))
            .parse()
            .unwrap();
    request.metadata_mut().insert("authorization", value);

    handler(
        request,
        Arc::new(ResourceGrantsAuthorizer::new(
            "resources".into(),
            "resource_id".into(),
            None,
            "urc-{id}".into(),
            "urc-*".into(),
        )),
        immutable_store.clone(),
        mutable_store,
        notification,
        &hook_dispatcher,
        &Some(verifier).into(),
    )
    .await
    .expect("handler should succeed");

    // An obliterated address resolves to nothing rather than to a reference whose payload has
    // gone missing: the store refuses it on the tombstone, before it ever looks for bytes.
    let get_err = immutable_store.get(repository, address).await.unwrap_err();
    assert!(
        get_err.is_address_not_found(),
        "payload should be obliterated; got: {get_err:?}"
    );
}

#[tokio::test]
async fn obliterate_permission_matrix() {
    use lore_server::authnz::global_grants_authorizer::GlobalGrantsAuthorizer;
    use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
    use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
    use lore_server::authnz::repository_authorizer::VerifiedToken;
    use serde_json::json;

    struct Policy(RepositoryId);
    #[async_trait]
    impl RepositoryAuthorizer for Policy {
        async fn check_repository_access(
            &self,
            token: Option<&VerifiedToken<'_>>,
            id: RepositoryId,
            action: Option<&str>,
        ) -> Result<(), tonic::Status> {
            assert_eq!(id, self.0);
            let token = token.unwrap();
            let mut validation = jsonwebtoken::Validation::new(ALGORITHM);
            validation.set_audience(&[TEST_AUDIENCE]);
            let decoded = jsonwebtoken::decode::<AuthorizationToken>(
                token.raw,
                &DecodingKey::from_secret(SIGNING_SECRET.as_ref()),
                &validation,
            )
            .unwrap();
            assert_eq!(decoded.claims.user_id, token.claims.user_id);
            assert!(action.is_none() || action == Some("obliterate"));
            Ok(())
        }
    }

    for case in 0..8 {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, _) = test_store_create().await.unwrap();
        let (fragment, address, payload) = lore_revision::fragment::generate_random();
        immutable_store
            .clone()
            .put(repository, address, fragment, Some(payload), false)
            .await
            .unwrap();
        let allowed = matches!(case, 0 | 3 | 4 | 5 | 7);
        let mut notification = MockNotificationSender::new();
        notification
            .expect_obliterate()
            .times(usize::from(allowed))
            .with(eq(repository), eq(address))
            .returning(|_, _| Ok(()));
        let notification = Arc::new(notification);
        let mut claims = AuthorizationToken {
            issuer: "test-issuer".into(),
            user_id: "test-user".into(),
            issued_at: 1,
            audience: vec![TEST_AUDIENCE.into()],
            expires: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 60,
            ..Default::default()
        };
        let mut authorizer: Arc<dyn RepositoryAuthorizer> =
            Arc::new(GlobalGrantsAuthorizer::new(Some("roles".into())));
        match case {
            0 => authorizer = Arc::new(AllowAllRepositoryAuthorizer),
            2 => claims.extra = json!({"roles": ["admin"]}).as_object().unwrap().clone(),
            3 => {
                claims.extra = json!({"roles": ["read", "obliterate"]})
                    .as_object()
                    .unwrap()
                    .clone();
            }
            4..=6 => {
                let resource = if case == 5 {
                    "all".into()
                } else if case == 6 {
                    format!("repo-{}", random::<RepositoryId>())
                } else {
                    format!("repo-{repository}")
                };
                claims.extra = json!({"access": {"entries": [
                    {"id": resource, "actions": []}, {"id": resource, "actions": ["read", "obliterate"]}
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
            7 => authorizer = Arc::new(Policy(repository)),
            _ => {}
        }
        let mut request = make_request(
            repository,
            if case == 0 {
                None
            } else {
                Some(sign_claims(&claims))
            },
        );
        request.get_mut().address = Some(address.into());
        let verifier = if case == 0 {
            None
        } else {
            Some(make_verifier(good_key_service()))
        };
        let result = handler(
            request,
            authorizer,
            immutable_store.clone(),
            mutable_store,
            notification,
            &HookDispatcher::empty(),
            &Arc::new(verifier),
        )
        .await;
        assert_eq!(result.is_ok(), allowed, "case={case}: {result:?}");
        if allowed {
            assert!(
                immutable_store
                    .get(repository, address)
                    .await
                    .unwrap_err()
                    .is_address_not_found()
            );
        } else {
            assert_eq!(result.unwrap_err().code(), Code::PermissionDenied);
            assert!(immutable_store.get(repository, address).await.is_ok());
        }
    }
}

#[tokio::test]
async fn expired_token_cannot_obliterate() {
    use lore_server::authnz::global_grants_authorizer::GlobalGrantsAuthorizer;
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, _) = test_store_create().await.unwrap();
    let mut claims = AuthorizationToken {
        issuer: "test-issuer".into(),
        user_id: "test-user".into(),
        issued_at: 1,
        audience: vec![TEST_AUDIENCE.into()],
        expires: 1,
        ..Default::default()
    };
    claims.extra = serde_json::json!({"roles": ["read", "obliterate"]})
        .as_object()
        .unwrap()
        .clone();
    let result = handler(
        make_request(repository, Some(sign_claims(&claims))),
        Arc::new(GlobalGrantsAuthorizer::new(Some("roles".into()))),
        immutable_store,
        mutable_store,
        Arc::new(MockNotificationSender::new()),
        &HookDispatcher::empty(),
        &Arc::new(Some(make_verifier(good_key_service()))),
    )
    .await;
    assert_eq!(result.unwrap_err().code(), Code::Unauthenticated);
}
