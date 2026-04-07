//! 多设备审计处理器（`/auth/sessions/*`）
//!
//! 提供用户对账号登录情况的全量审计能力，
//! 允许识别异常登录并执行远程强制退出。
//!
//! 所有接口均需要 `Authorization: Bearer <access_token>` 请求头。

use std::sync::Arc;

use axum::{
    extract::{Json, Path, Query, State},
    http::HeaderMap,
    response::Response,
};

use crate::{
    api::{self, ApiError, ApiResult},
    app::AppState,
    do_protocol::{
        BatchDeleteDeviceRequest, DeleteDeviceRequest, DeleteDeviceResponse, UpdateAliasRequest,
        UserSessionRequest, UserSessionResponse,
    },
    oidc_flow,
    types::{BatchDeleteQuery, BatchDeleteSessionsData, SessionDeleteScope, UpdateSessionRequest},
};

use super::support;

// ─── 设备列表 ────────────────────────────────────────────────────────────────

/// `GET /auth/sessions`
///
/// 返回当前账号下所有未过期且未被注销的活跃设备清单。
///
/// 流程：
/// 1. 验证 Access Token，获取 `user_id` 和 `current_session_id`
/// 2. 从 KV 按 `user_id` 前缀枚举所有活跃 Session 记录
/// 3. 将 `current_session_id` 对应的条目标记为 `SessionKind::Current`，其余为 `Remote`
/// 4. 从各 Session 记录中提取 CF 元数据，构造 `SessionGeoLocation`
/// 5. 返回 `Vec<SessionListItem>` 数组
pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let claims = support::bearer_claims(&state, &headers)?;
    let response = support::call_user_session(
        &state,
        &claims.sub,
        &UserSessionRequest::ListSessions(crate::do_protocol::AuthenticatedSessionRequest {
            session_id: claims.sid,
        }),
    )
    .await?;
    match response {
        UserSessionResponse::ListSessions(data) => Ok(api::json_ok(data, &state.trace_id)),
        _ => Err(ApiError::internal(
            "user session durable object returned an unexpected list_sessions response",
        )),
    }
}

// ─── 设备详情 ────────────────────────────────────────────────────────────────

/// `GET /auth/sessions/{session_id}`
///
/// 返回指定设备的完整审计信息与环境指纹。
///
/// 流程：
/// 1. 验证 Access Token，获取 `user_id`
/// 2. 从 KV 读取 `session_id` 对应的 Session 记录
/// 3. **鉴权**：确认该 Session 归属于当前用户（防止越权读取他人会话）
/// 4. 返回 `SessionDetailData`（含完整 CF 元数据快照，包括 TLS 指纹等）
pub async fn get_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> ApiResult<Response> {
    let claims = support::bearer_claims(&state, &headers)?;
    let response = support::call_user_session(
        &state,
        &claims.sub,
        &UserSessionRequest::GetSessionDetail(DeleteDeviceRequest {
            current_session_id: claims.sid,
            target_session_id: session_id,
        }),
    )
    .await?;
    match response {
        UserSessionResponse::GetSessionDetail(data) => Ok(api::json_ok(data, &state.trace_id)),
        _ => Err(ApiError::internal(
            "user session durable object returned an unexpected get_session_detail response",
        )),
    }
}

// ─── 修改设备属性 ────────────────────────────────────────────────────────────

/// `PATCH /auth/sessions/{session_id}`
///
/// 远程修改指定会话的元数据（当前仅支持 `alias` 字段）。
///
/// 流程：
/// 1. 验证 Access Token
/// 2. **鉴权**：确认 Session 归属于当前用户
/// 3. 按 `FieldUpdate` 语义更新 KV 中的 Session 别名字段
/// 4. 返回 `UpdateSessionData`
pub async fn update_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Json(body): Json<UpdateSessionRequest>,
) -> ApiResult<Response> {
    let claims = support::bearer_claims(&state, &headers)?;
    let response = support::call_user_session(
        &state,
        &claims.sub,
        &UserSessionRequest::UpdateSession(UpdateAliasRequest {
            current_session_id: claims.sid,
            target_session_id: session_id,
            alias: body.alias,
        }),
    )
    .await?;
    match response {
        UserSessionResponse::UpdateSession(data) => Ok(api::json_ok(data, &state.trace_id)),
        _ => Err(ApiError::internal(
            "user session durable object returned an unexpected update_session response",
        )),
    }
}

// ─── 强制注销指定设备 ────────────────────────────────────────────────────────

/// `DELETE /auth/sessions/{session_id}`
///
/// 远程强制注销指定设备（"踢出"功能）。
///
/// > **注意**：Access Token 为无状态 JWT，注销后剩余寿命内仍可访问业务接口。
///
/// 流程：
/// 1. 验证 Access Token，获取 `user_id` 和 `current_session_id`
/// 2. **鉴权**：确认目标 Session 归属于当前用户
/// 3. 从 KV 中删除目标 Session 的 Refresh Token 记录
/// 4. 若配置了 OIDC 同步登出，构造 `OidcLogoutAction`
/// 5. 返回 `DeleteSessionData`
pub async fn delete_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> ApiResult<Response> {
    let claims = support::bearer_claims(&state, &headers)?;
    let deleting_current = claims.sid == session_id;
    let response = support::call_user_session(
        &state,
        &claims.sub,
        &UserSessionRequest::DeleteSession(DeleteDeviceRequest {
            current_session_id: claims.sid,
            target_session_id: session_id,
        }),
    )
    .await?;
    match response {
        UserSessionResponse::DeleteSession(DeleteDeviceResponse::Ok {
            mut data,
            id_token_hint,
        }) => {
            if deleting_current {
                if let Ok(discovery) = oidc_flow::discover(&state.config.oidc).await {
                    data.logout = support::logout_action(&discovery, &state, id_token_hint);
                }
            }
            api::json_with_cookie(
                data,
                &state.trace_id,
                deleting_current.then(|| support::clear_refresh_cookie(&state)),
            )
        }
        UserSessionResponse::DeleteSession(DeleteDeviceResponse::NotFound) => Err(
            ApiError::not_found("SESSION_NOT_FOUND", "session not found"),
        ),
        _ => Err(ApiError::internal(
            "user session durable object returned an unexpected delete_session response",
        )),
    }
}

// ─── 批量注销会话 ────────────────────────────────────────────────────────────

/// `DELETE /auth/sessions`
///
/// 根据 `scope` 参数批量清理当前账号下的活跃会话。
///
/// | `scope`  | 效果                                        |
/// | -------- | ------------------------------------------- |
/// | `others` | 踢出除当前设备外的所有其他活跃设备          |
/// | `all`    | 注销该账号下全部活跃会话（含当前会话）      |
///
/// > **注意**：当 `scope=all` 时，客户端必须在收到响应后立即从内存中抹除 AT。
///
/// 流程：
/// 1. 验证 Access Token，获取 `user_id` 和 `current_session_id`
/// 2. 从 KV 按 `user_id` 前缀枚举所有活跃 Session：
///    - `others`：撤销所有 `session_id != current_session_id` 的记录
///    - `all`：撤销全部记录（含当前）
/// 3. 若 `scope=all` 且配置了 OIDC 同步登出，构造 `OidcLogoutAction`
/// 4. 若 `scope=all`，同时清除当前设备的 RT Cookie（`Max-Age=0`）
/// 5. 返回 `BatchDeleteSessionsData`（含 `count` 和 `scope`）
pub async fn batch_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<BatchDeleteQuery>,
) -> ApiResult<Response> {
    let claims = support::bearer_claims(&state, &headers)?;
    let response = support::call_user_session(
        &state,
        &claims.sub,
        &UserSessionRequest::BatchDelete(BatchDeleteDeviceRequest {
            current_session_id: claims.sid,
            scope: query.scope,
        }),
    )
    .await?;
    let batch = match response {
        UserSessionResponse::BatchDelete(data) => data,
        _ => {
            return Err(ApiError::internal(
                "user session durable object returned an unexpected batch_delete response",
            ));
        }
    };

    let logout = if matches!(query.scope, SessionDeleteScope::All) {
        match oidc_flow::discover(&state.config.oidc).await {
            Ok(discovery) => {
                support::logout_action(&discovery, &state, batch.current_id_token_hint.clone())
            }
            Err(_) => None,
        }
    } else {
        None
    };
    let data = BatchDeleteSessionsData {
        count: batch.count,
        scope: query.scope,
        logout,
    };
    let clear_cookie = matches!(query.scope, SessionDeleteScope::All)
        .then(|| support::clear_refresh_cookie(&state));
    api::json_with_cookie(data, &state.trace_id, clear_cookie)
}
