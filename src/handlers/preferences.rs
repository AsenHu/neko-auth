//! 账户安全偏好处理器（`/auth/preferences`）
//!
//! 定义账户全局的安全防御策略，影响所有关联设备的会话生存期与接入逻辑。
//! 所有接口均需要 `Authorization: Bearer <access_token>` 请求头。

use std::sync::Arc;

use axum::{
    extract::{Json, State},
    http::HeaderMap,
    response::Response,
};

use crate::{
    api::{self, ApiError, ApiResult},
    app::AppState,
    do_protocol::{
        AuthenticatedSessionRequest, UpdatePreferencesDoRequest, UserSessionRequest,
        UserSessionResponse,
    },
    types::UpdatePreferencesRequest,
};

use super::support;

// ─── 获取安全配置 ────────────────────────────────────────────────────────────

/// `GET /auth/preferences`
///
/// 返回当前账号生效的全局安全策略配置。
///
/// 流程：
/// 1. 从 `Authorization` 头验证 Access Token，获取 `user_id`
/// 2. 从 KV 读取该用户的 `UserPreferences` 记录
/// 3. 若记录不存在，返回系统预设的默认策略
///    （建议默认值：`idle_timeout=Permanent`、`tor_transition=Deny`）
/// 4. 返回 `UserPreferences`
pub async fn get_preferences(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let claims = support::bearer_claims(&state, &headers)?;
    let response = support::call_user_session(
        &state,
        &claims.sub,
        &UserSessionRequest::GetPreferences(AuthenticatedSessionRequest {
            session_id: claims.sid,
        }),
    )
    .await?;
    match response {
        UserSessionResponse::Preferences(data) => Ok(api::json_ok(data, &state.trace_id)),
        _ => Err(ApiError::internal(
            "user session durable object returned an unexpected preferences response",
        )),
    }
}

// ─── 修改安全配置 ────────────────────────────────────────────────────────────

/// `PATCH /auth/preferences`
///
/// 更新全局安全策略；变更立即对该账号所有关联设备的后续会话生效。
///
/// 请求体中只需提供**要修改的字段**，不提供的字段保持不变。
///
/// 流程：
/// 1. 从 `Authorization` 头验证 Access Token，获取 `user_id`
/// 2. 从 KV 读取当前 `UserPreferences`（或取默认值）
/// 3. 仅更新请求体中非 `None` 的字段：
///    - `idle_timeout`: 修改闲置超时策略
///    - `tor_transition`: 修改 Tor 切换策略
/// 4. 将更新后的配置写回 KV
/// 5. 返回完整的 `UserPreferences`（反映写入后的最终状态）
pub async fn update_preferences(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<UpdatePreferencesRequest>,
) -> ApiResult<Response> {
    let claims = support::bearer_claims(&state, &headers)?;
    let response = support::call_user_session(
        &state,
        &claims.sub,
        &UserSessionRequest::UpdatePreferences(UpdatePreferencesDoRequest {
            session_id: claims.sid,
            idle_timeout: body.idle_timeout,
            tor_transition: body.tor_transition,
        }),
    )
    .await?;
    match response {
        UserSessionResponse::Preferences(data) => Ok(api::json_ok(data, &state.trace_id)),
        _ => Err(ApiError::internal(
            "user session durable object returned an unexpected preferences response",
        )),
    }
}
