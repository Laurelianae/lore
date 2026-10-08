// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::body::Body;
use axum::body::Bytes;
use axum::extract::Path;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_revision::immutable;
use lore_revision::repository::RepositoryContext;
use lore_storage::options::WriteOptions;
use lore_transport::grpc::CORRELATION_ID_HEADER;
use serde::Serialize;
use tracing::debug;
use tracing::info;

use crate::auth::jwt::AuthorizationToken;
use crate::authnz::repository_authorizer::PartitionGrants;
use crate::authnz::repository_authorizer::RawToken;
use crate::authnz::repository_authorizer::VerifiedToken;
use crate::http::server::ServerState;
use crate::util::get_user_id_from_token;
use crate::util::setup_execution;

#[derive(Serialize)]
struct ResponseData {
    address: String,
}

#[derive(Serialize)]
struct ResponseSuccess {
    data: ResponseData,
}

pub async fn handler(
    State(state): State<Arc<ServerState>>,
    Path(repository_id): Path<String>,
    Extension(user_info): Extension<Option<AuthorizationToken>>,
    raw_token: Option<Extension<RawToken>>,
    partition_grants: Option<Extension<PartitionGrants>>,
    headers: HeaderMap,
    data: Bytes,
) -> Response {
    info!("Put repository {} data {} bytes", repository_id, data.len());
    info!("User info: {:?}", user_info);

    let mut header_error = HeaderMap::new();
    header_error.insert("content-type", HeaderValue::from_str("text/plain").unwrap());

    let correlation_id = headers
        .get(CORRELATION_ID_HEADER)
        .and_then(|header_value| header_value.to_str().map(str::to_string).ok())
        .unwrap_or_default();

    let repository = match repository_id.parse::<lore_base::types::RepositoryId>() {
        Ok(repository) => repository,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid repository id").into_response(),
    };
    let token = raw_token
        .as_ref()
        .zip(user_info.as_ref())
        .map(|(Extension(raw), claims)| VerifiedToken {
            raw: &raw.0,
            claims,
        });
    if let Err(status) = state
        .repository_authorizer
        .require_write_with_grants(
            token.as_ref(),
            repository,
            partition_grants.as_ref().map(|Extension(grants)| grants),
        )
        .await
    {
        let code = if status.code() == tonic::Code::NotFound {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::FORBIDDEN
        };
        return (code, status.message().to_string()).into_response();
    }
    let user_id = get_user_id_from_token(user_info);
    let execution = setup_execution(module_path!(), correlation_id, user_id);
    LORE_CONTEXT
        .scope(execution, async move {
            let repository = match repository_id.parse::<Context>() {
                Ok(repository_id) => Arc::new(RepositoryContext::new_server_context(
                    state.immutable_store.clone(),
                    state.mutable_store.clone(),
                    repository_id.into(),
                )),
                Err(error) => {
                    debug!("Error parsing the repository ID {}", error);
                    return (
                        StatusCode::BAD_REQUEST,
                        header_error,
                        Body::from("Wrong repository"),
                    )
                        .into_response();
                }
            };

            let context = uuid::Uuid::now_v7().into();
            let address = match immutable::write(
                repository.clone(),
                context,
                data,
                WriteOptions::default().with_remote_write(),
            )
            .await
            {
                Ok(result) => result,
                Err(error) => {
                    debug!("Failed to write into immutable store. {}", error);
                    return (
                        StatusCode::BAD_REQUEST,
                        header_error,
                        Body::from("Malformed data"),
                    )
                        .into_response();
                }
            };

            (
                StatusCode::OK,
                Json(ResponseSuccess {
                    data: ResponseData {
                        address: format!("{address}"),
                    },
                }),
            )
                .into_response()
        })
        .await
}
