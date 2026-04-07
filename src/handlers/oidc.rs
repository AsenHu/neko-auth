//! OIDC 认证流程处理器（`/auth/oidc/*`）
//!
//! 实现完整的 OpenID Connect Authorization Code Flow + PKCE，
//! 包括发起授权、接收回调和处理 Back-Channel 登出通知。
//!
//! 所有接口均不需要 `Authorization` 请求头。

use std::sync::Arc;

use axum::{
    extract::{Form, Query, State},
    http::HeaderMap,
    response::Response,
};

use crate::{
    api::{self, ApiError, ApiResult},
    app::AppState,
    do_protocol::{
        LoginDeviceRequest, OidcStateRecord, OidcStateRequest, UserSessionRequest,
        UserSessionResponse,
    },
    oidc_flow, security,
    types::{BackchannelLogoutForm, OidcCallbackParams},
};

use super::support;

// ─── 发起授权 ────────────────────────────────────────────────────────────────

/// `GET /auth/oidc/authorize`
///
/// 生成 CSRF 防护参数与 PKCE 挑战，构造 IdP 授权 URL，返回 302 重定向。
///
/// 不接受任何客户端参数，所有配置均从服务端预置的 IdP 配置文件中读取。
///
/// 流程（参见 OIDC Core §3.1.2.1）：
/// 1. 生成加密级随机 `state`（防 CSRF）
/// 2. 生成 PKCE `code_verifier`（43–128 字符随机字符串）
///    并计算 `code_challenge = BASE64URL(SHA-256(code_verifier))`
/// 3. 将 `state → code_verifier` 映射持久化到 KV（TTL ~10 分钟）
/// 4. 从 Env 读取 IdP 配置（`issuer`、`client_id`、`redirect_uri` 等）
/// 5. 拼接授权 URL，设置 `response_type=code`、`scope=openid email profile`、
///    `code_challenge_method=S256`，返回 `302 Found` 重定向
///
/// 参见：<https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest>
pub async fn authorize(State(state): State<Arc<AppState>>) -> ApiResult<Response> {
    let discovery = oidc_flow::discover(&state.config.oidc).await?;
    let state_value = security::random_token(32).map_err(ApiError::from)?;
    let nonce = security::random_token(32).map_err(ApiError::from)?;
    let code_verifier = security::random_token(64).map_err(ApiError::from)?;
    let now = support::now_unix();

    let record = OidcStateRecord {
        host: state.host.clone(),
        state: state_value.clone(),
        code_verifier: code_verifier.clone(),
        nonce: nonce.clone(),
        created_at: now,
        expires_at: now + state.config.oidc_state_ttl_seconds as i64,
    };
    let object_name = security::oidc_state_do_name(&state.host, &state_value);
    let _: bool =
        support::call_oidc_state(&state, &object_name, &OidcStateRequest::Store(record)).await?;

    let location = oidc_flow::build_authorization_url(
        &discovery,
        &state.config.oidc,
        &state_value,
        &nonce,
        &code_verifier,
    )?;
    api::redirect(&location, None)
}

// ─── 登录回调 ────────────────────────────────────────────────────────────────

/// `GET /auth/oidc/callback`
///
/// 处理 IdP 通过浏览器重定向带回的授权响应（Query String 模式）。
///
/// 参见 OIDC Core §3.1.2.5：
/// <https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse>
pub async fn callback_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<OidcCallbackParams>,
) -> ApiResult<Response> {
    process_callback(state, headers, params).await
}

/// `POST /auth/oidc/callback`
///
/// 处理 IdP 通过 Form Post 方式发起的授权回调（推荐模式）。
///
/// Form Post 模式可确保敏感的 `code` 仅在请求体中传输，
/// 不会出现在浏览器历史记录或服务器访问日志中。
///
/// 参见 OAuth 2.0 Form Post Response Mode：
/// <https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html>
pub async fn callback_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(params): Form<OidcCallbackParams>,
) -> ApiResult<Response> {
    process_callback(state, headers, params).await
}

/// 回调业务处理逻辑（GET/POST 共用）
///
/// 完整流程：
/// 1. 检查 `error` 字段——若 IdP 返回错误则直接拒绝并记录日志
/// 2. 从 KV 中取出 `state` 对应的 `code_verifier`，
///    无论认证是否成功，消费后立即删除（防止重放）
/// 3. 使用 `code + code_verifier` 向 IdP Token Endpoint 换取 Token
/// 4. 验证 ID Token（签名、`iss`、`aud`、`exp`、`nonce` 等）
/// 5. 提取并存储用户身份快照（`sub`、`email`、`phone_number` 等）
/// 6. 创建本地 Session 记录，关联设备指纹（IP、UA、CF 元数据）
/// 7. 签发 Refresh Token，通过 `__Http-refresh-token` Cookie 持久化设置
///    （Cookie 属性参见 README §2.3.2）
/// 8. 返回 `302 Found`，重定向至系统预设主页
async fn process_callback(
    state: Arc<AppState>,
    headers: HeaderMap,
    params: OidcCallbackParams,
) -> ApiResult<Response> {
    let object_name = security::oidc_state_do_name(&state.host, &params.state);

    if let Some(error) = params.error.as_deref() {
        let _ = support::call_oidc_state::<_, Option<OidcStateRecord>>(
            &state,
            &object_name,
            &OidcStateRequest::Consume {
                state: params.state.clone(),
                now: support::now_unix(),
            },
        )
        .await;
        return Err(ApiError::bad_request(
            "OIDC_AUTH_ERROR",
            params
                .error_description
                .unwrap_or_else(|| error.to_string()),
        ));
    }

    let record: OidcStateRecord = support::call_oidc_state::<_, Option<OidcStateRecord>>(
        &state,
        &object_name,
        &OidcStateRequest::Consume {
            state: params.state.clone(),
            now: support::now_unix(),
        },
    )
    .await?
    .ok_or_else(|| ApiError::unauthorized("INVALID_OIDC_STATE", "state is invalid or expired"))?;

    if record.host != state.host {
        return Err(ApiError::unauthorized(
            "INVALID_OIDC_STATE",
            "state belongs to a different host",
        ));
    }

    let code = params
        .code
        .ok_or_else(|| ApiError::bad_request("MISSING_AUTHORIZATION_CODE", "missing code"))?;
    let discovery = oidc_flow::discover(&state.config.oidc).await?;
    let tokens =
        oidc_flow::exchange_code(&discovery, &state.config.oidc, &code, &record.code_verifier)
            .await?;
    let verified = oidc_flow::verify_id_token(
        &discovery,
        &state.config.oidc,
        &tokens.id_token,
        &record.nonce,
    )
    .await?;
    let userinfo = oidc_flow::fetch_userinfo(&discovery, &tokens.access_token).await?;
    let userinfo_sub = userinfo
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ApiError::unauthorized("INVALID_USERINFO", "userinfo missing sub"))?;
    if userinfo_sub != verified.sub {
        return Err(ApiError::unauthorized(
            "INVALID_USERINFO",
            "userinfo sub mismatch",
        ));
    }

    let protected_jws =
        security::sign_protected(&state.config.jwt, &state.host, &verified.protected)
            .map_err(|e| ApiError::internal(format!("failed to sign protected identity: {e}")))?;
    let session_id = security::random_token(32).map_err(ApiError::from)?;
    let (refresh_token, _refresh_expires_at) = security::issue_refresh_token(
        &state.config.jwt,
        &state.host,
        &verified.sub,
        &session_id,
        1,
    )
    .map_err(|e| ApiError::internal(format!("failed to issue refresh token: {e}")))?;
    let identity = oidc_flow::merge_claims(verified.claims.clone(), userinfo);
    let login = LoginDeviceRequest {
        host: state.host.clone(),
        sub: verified.sub.clone(),
        identity,
        protected: verified.protected,
        protected_jws,
        id_token_hint: tokens.id_token,
        oidc_sid: verified.sid,
        default_preferences: state.config.default_preferences.clone(),
        session_id: session_id.clone(),
        refresh_token_hash: security::hash_refresh_token(&refresh_token),
        refresh_token_seq: 1,
        context: state.context.clone(),
        user_agent: crate::request_context::user_agent(&headers),
    };
    let sub = login.sub.clone();
    match support::call_user_session(&state, &sub, &UserSessionRequest::Login(login)).await? {
        UserSessionResponse::Login { session_id: stored } if stored == session_id => {}
        _ => {
            return Err(ApiError::internal(
                "user session durable object returned an unexpected login response",
            ));
        }
    }

    api::redirect(
        &state.config.post_login_redirect_uri,
        Some(support::set_refresh_cookie(&state, &refresh_token)),
    )
}

// ─── Back-Channel 登出 ───────────────────────────────────────────────────────

/// `POST /auth/oidc/backchannel_logout`
///
/// 接收 IdP 主动推送的后端登出通知，同步注销本地关联会话。
///
/// 本接口为**幂等操作**：若对应会话已被注销（例如用户手动退出），
/// 仍然返回 `200 OK`，以确保 IdP 侧同步状态的闭环。
///
/// 流程：
/// 1. 验证 `logout_token` JWT：
///    - 校验签名（使用 IdP JWKS）
///    - 校验 `iss`、`aud`、`iat`
///    - 确认 `events` claim 包含 `{"http://schemas.openid.net/event/backchannel-logout": {}}`
///    - 确认 **不包含** `nonce` claim（安全要求）
/// 2. 从 `sub` 或 `sid` claim 定位本地 Session 记录
/// 3. 批量撤销所有关联 Session 的 Refresh Token
/// 4. 无论是否找到 Session，均返回 `200 OK`
///
/// 参见 OpenID Connect Back-Channel Logout 1.0：
/// <https://openid.net/specs/openid-connect-backchannel-1_0.html>
pub async fn backchannel_logout(
    State(state): State<Arc<AppState>>,
    Form(body): Form<BackchannelLogoutForm>,
) -> ApiResult<Response> {
    let discovery = oidc_flow::discover(&state.config.oidc).await?;
    let (sub, sid) =
        oidc_flow::verify_logout_token(&discovery, &state.config.oidc, &body.logout_token).await?;

    if let Some(sub) = sub {
        let _ = support::call_user_session(
            &state,
            &sub,
            &UserSessionRequest::BackchannelLogout(crate::do_protocol::BackchannelLogoutRequest {
                sub: sub.clone(),
                sid,
            }),
        )
        .await?;
    }

    Ok(api::empty_ok(&state.trace_id))
}
