//! 当前会话管理处理器（`/auth/session`）
//!
//! 管理用户在当前活跃设备上的登录状态与令牌续期。
//! 除 `refresh` 外，所有接口均需要 `Authorization: Bearer <access_token>` 请求头。

use std::sync::Arc;

use axum::{
    extract::{Json, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};

use crate::{
    api::{self, ApiError, ApiResult},
    app::AppState,
    do_protocol::{
        DeleteDeviceRequest, RefreshDeviceRequest, RefreshDeviceResponse, SessionIdentityRequest,
        UpdateAliasRequest, UserSessionRequest, UserSessionResponse,
    },
    oidc_flow, security,
    types::{GetSessionQuery, UpdateSessionRequest},
};

use super::support;

// ─── 获取当前会话信息 ────────────────────────────────────────────────────────

/// `GET /auth/session`
///
/// 返回当前活跃会话的上下文信息，以及可选的完整身份快照。
///
/// 若客户端仅需校验 Token 有效性，建议保持 `identity=false`（默认），
/// 这可跳过服务端对身份快照的检索，显著提升响应速度。
///
/// 流程：
/// 1. 从 `Authorization` 头提取并验证 Access Token（JWT 签名与有效期）
/// 2. 从 Token Payload 中获取 `session_id`
/// 3. 从请求本身提取 `RequestContext`（客户端 IP 和 CF 元数据）
/// 4. 若 `identity=true`：
///    a. 从 KV 读取该 Session 的 OIDC Raw Claims（identity 快照）
///    b. 构建 `ProtectedJwsPayload`（sub、email、phone_number）并生成 JWS
/// 5. 返回 `GetSessionData`
pub async fn get_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<GetSessionQuery>,
) -> ApiResult<Response> {
    let claims = support::bearer_claims(&state, &headers)?;
    let response = support::call_user_session(
        &state,
        &claims.sub,
        &UserSessionRequest::GetSession(SessionIdentityRequest {
            session_id: claims.sid,
            include_identity: query.identity,
        }),
    )
    .await?;
    match response {
        UserSessionResponse::GetSession(mut data) => {
            data.context = state.context.clone();
            Ok(api::json_ok(data, &state.trace_id))
        }
        _ => Err(ApiError::internal(
            "user session durable object returned an unexpected get_session response",
        )),
    }
}

// ─── 令牌续期 ────────────────────────────────────────────────────────────────

/// `POST /auth/session/refresh`
///
/// Access Token 续期（Token Rotation）。
///
/// 消耗当前 Refresh Token Cookie，签发新的 AT + RT。
/// **不需要** `Authorization` 头；凭证通过 `__Http-refresh-token` Cookie 提供。
///
/// 流程（Account-Level Actor 模型）：
/// 1. 从 Cookie 中读取 `__Http-refresh-token`
/// 2. 验证 RT：存在性、序列号匹配（防重放攻击）、未被撤销
/// 3. 检查账户 `idle_timeout` 策略——距上次活跃超时则拒绝续期
/// 4. 检查 `tor_transition` 策略——与上次请求的 IP 性质对比
/// 5. 旋转 RT：
///    a. 旧 RT 立即失效（KV 中更新序列号或标记撤销）
///    b. 签发新 RT，更新 Session 记录中的 `last_active_at`
///    c. 写入 `Set-Cookie: __Http-refresh-token=<new_rt>` 响应头
///       （属性详见 README §2.3.2：HttpOnly、Secure、SameSite=Strict、
///        Path=/auth/session/refresh、无 Domain）
/// 6. 签发新 Access Token（JWT），返回 `SessionRefreshData`
pub async fn refresh(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let Some(refresh_token) =
        support::refresh_cookie_value(&headers, &state.config.cookie.refresh_token_name)
    else {
        return support::unauthorized_with_clear_cookie(
            &state,
            "MISSING_REFRESH_TOKEN",
            "missing refresh token cookie",
        );
    };
    let claims =
        match security::verify_refresh_token(&state.config.jwt, &state.host, &refresh_token) {
            Ok(claims) => claims,
            Err(error) => {
                return support::unauthorized_with_clear_cookie(
                    &state,
                    "INVALID_REFRESH_TOKEN",
                    error.to_string(),
                );
            }
        };
    let next_seq = claims.seq + 1;
    let (next_refresh_token, _refresh_expires_at) = security::issue_refresh_token(
        &state.config.jwt,
        &state.host,
        &claims.sub,
        &claims.sid,
        next_seq,
    )
    .map_err(|e| ApiError::internal(format!("failed to issue refresh token: {e}")))?;

    let request = RefreshDeviceRequest {
        session_id: claims.sid.clone(),
        refresh_token_hash: security::hash_refresh_token(&refresh_token),
        next_refresh_token_hash: security::hash_refresh_token(&next_refresh_token),
        next_refresh_token_seq: next_seq,
        context: state.context.clone(),
        user_agent: crate::request_context::user_agent(&headers),
        now: support::now_unix(),
    };
    let response =
        support::call_user_session(&state, &claims.sub, &UserSessionRequest::Refresh(request))
            .await?;
    let refresh_response = match response {
        UserSessionResponse::Refresh(response) => response,
        _ => {
            return Err(ApiError::internal(
                "user session durable object returned an unexpected refresh response",
            ));
        }
    };

    match refresh_response {
        RefreshDeviceResponse::Ok(data) if data.sub == claims.sub => {
            let (access_token, expires_at) = security::issue_access_token(
                &state.config.jwt,
                &state.host,
                &claims.sub,
                &data.session_id,
            )
            .map_err(|e| ApiError::internal(format!("failed to issue access token: {e}")))?;
            api::json_with_cookie(
                crate::types::SessionRefreshData {
                    access_token,
                    expires_at,
                },
                &state.trace_id,
                Some(support::set_refresh_cookie(&state, &next_refresh_token)),
            )
        }
        RefreshDeviceResponse::Ok(_) => support::unauthorized_with_clear_cookie(
            &state,
            "INVALID_REFRESH_TOKEN",
            "refresh token subject mismatch",
        ),
        RefreshDeviceResponse::Invalid => support::unauthorized_with_clear_cookie(
            &state,
            "INVALID_REFRESH_TOKEN",
            "refresh token is no longer valid",
        ),
        RefreshDeviceResponse::Reused => support::unauthorized_with_clear_cookie(
            &state,
            "REFRESH_TOKEN_REUSED",
            "refresh token reuse detected; the device session was revoked",
        ),
        RefreshDeviceResponse::IdleTimeout => Ok(api::error_with_cookie(
            StatusCode::UNAUTHORIZED,
            "AUTH_IDLE_TIMEOUT",
            "session idle timeout",
            &state.trace_id,
            Some(support::clear_refresh_cookie(&state)),
        )?),
        RefreshDeviceResponse::TorTransitionDenied => Ok(api::error_with_cookie(
            StatusCode::FORBIDDEN,
            "AUTH_TOR_TRANSITION_DENIED",
            "tor transition denied for this session",
            &state.trace_id,
            Some(support::clear_refresh_cookie(&state)),
        )?),
    }
}

// ─── 修改当前会话属性 ────────────────────────────────────────────────────────

/// `PATCH /auth/session`
///
/// 修改当前正在使用的设备/会话的元数据（当前仅支持 `alias` 字段）。
///
/// 流程：
/// 1. 从 `Authorization` 头验证 Access Token
/// 2. 从 Token 中提取 `session_id`
/// 3. 反序列化请求体为 `UpdateSessionRequest`
///    （序列化方案确定后，在此添加 `Json<UpdateSessionRequest>` 提取器）
/// 4. 按 `FieldUpdate` 语义更新 KV 中的 Session 记录：
///    - `Ignore`：跳过，不修改
///    - `Delete`：清空 `alias` 字段
///    - `Set(v)`：写入新的 `alias` 值
/// 5. 返回 `UpdateSessionData`
pub async fn update_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<UpdateSessionRequest>,
) -> ApiResult<Response> {
    let claims = support::bearer_claims(&state, &headers)?;
    let response = support::call_user_session(
        &state,
        &claims.sub,
        &UserSessionRequest::UpdateSession(UpdateAliasRequest {
            current_session_id: claims.sid.clone(),
            target_session_id: claims.sid,
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

// ─── 注销当前会话 ────────────────────────────────────────────────────────────

/// `DELETE /auth/session`
///
/// 用户主动注销当前设备的登录状态。
///
/// > **注意**：Access Token 为无状态 JWT，注销后在其剩余寿命内理论上仍可
/// > 访问业务接口。客户端必须在收到成功响应后立即从内存中抹除 AT。
///
/// 流程：
/// 1. 从 `Authorization` 头验证 Access Token
/// 2. 从 Token 中提取 `session_id`
/// 3. 从 KV 中删除该 Session 关联的 Refresh Token 记录
/// 4. 若服务端配置了 OIDC 同步登出，构造 `OidcLogoutAction`
///    （含 `id_token_hint`、`post_logout_redirect_uri` 等参数）
/// 5. 写入清除 Cookie 的响应头：`Max-Age=0`（属性详见 README §2.3.4）
/// 6. 返回 `DeleteSessionData`
pub async fn delete_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let claims = support::bearer_claims(&state, &headers)?;
    let response = support::call_user_session(
        &state,
        &claims.sub,
        &UserSessionRequest::DeleteSession(DeleteDeviceRequest {
            current_session_id: claims.sid.clone(),
            target_session_id: claims.sid,
        }),
    )
    .await?;
    match response {
        UserSessionResponse::DeleteSession(crate::do_protocol::DeleteDeviceResponse::Ok {
            mut data,
            id_token_hint,
        }) => {
            if let Ok(discovery) = oidc_flow::discover(&state.config.oidc).await {
                data.logout = support::logout_action(&discovery, &state, id_token_hint);
            }
            api::json_with_cookie(
                data,
                &state.trace_id,
                Some(support::clear_refresh_cookie(&state)),
            )
        }
        UserSessionResponse::DeleteSession(crate::do_protocol::DeleteDeviceResponse::NotFound) => {
            support::unauthorized_with_clear_cookie(
                &state,
                "SESSION_NOT_FOUND",
                "session was already logged out",
            )
        }
        _ => Err(ApiError::internal(
            "user session durable object returned an unexpected delete_session response",
        )),
    }
}
