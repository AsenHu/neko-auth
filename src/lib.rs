//! neko-auth — Cloudflare Workers 上的 OIDC 身份认证服务
//!
//! 采用 **OIDC Authorization Code Flow + PKCE** 进行身份认证，
//! 通过**双 Token 旋转机制**（Access Token + Refresh Token）维护会话安全，
//! 并提供精细化的**多设备审计**与**全局安全策略**配置。
//!
//! # 路由结构
//!
//! ```text
//! /auth/oidc/authorize                GET
//! /auth/oidc/callback                 GET, POST
//! /auth/oidc/backchannel_logout       POST
//!
//! /auth/session/refresh               POST
//! /auth/session                       GET, PATCH, DELETE
//!
//! /auth/sessions                      GET, DELETE
//! /auth/sessions/{session_id}         GET, PATCH, DELETE
//!
//! /auth/preferences                   GET, PATCH
//! ```

use axum::{body, http, routing, Router};
use tower_service::Service;
use worker::*;

use handlers::{oidc, preferences, session, sessions};

mod handlers;
mod types;

/// 构建应用路由表
///
/// 路由按功能域分组，便于维护和权限管理。
/// 注意：`/auth/session/refresh` 必须在 `/auth/session` 之前注册，
/// 避免路由匹配歧义（Axum 按注册顺序进行最长前缀匹配）。
fn router() -> Router {
    Router::new()
        // ── OIDC 认证流程 ──────────────────────────────────────────────────
        // 发起授权：生成 state + PKCE challenge，302 重定向至 IdP
        .route("/auth/oidc/authorize", routing::get(oidc::authorize))
        // 登录回调：支持 GET（Query String 模式）和 POST（Form Post 模式）
        .route(
            "/auth/oidc/callback",
            routing::get(oidc::callback_get)
                .post(oidc::callback_post),
        )
        // Back-Channel 登出：接收 IdP 服务端推送的登出通知
        .route(
            "/auth/oidc/backchannel_logout",
            routing::post(oidc::backchannel_logout),
        )
        // ── 当前会话管理 ───────────────────────────────────────────────────
        // refresh 路径独立，使 Cookie 作用域（Path）精确限定在此接口
        .route("/auth/session/refresh", routing::post(session::refresh))
        .route(
            "/auth/session",
            routing::get(session::get_session)
                .patch(session::update_session)
                .delete(session::delete_session),
        )
        // ── 多设备审计 ─────────────────────────────────────────────────────
        // 集合路由：列表查询 & 批量注销
        .route(
            "/auth/sessions",
            routing::get(sessions::list_sessions)
                .delete(sessions::batch_delete),
        )
        // 单体路由：按 session_id 操作
        .route(
            "/auth/sessions/:session_id",
            routing::get(sessions::get_session)
                .patch(sessions::update_session)
                .delete(sessions::delete_session),
        )
        // ── 账户安全偏好 ───────────────────────────────────────────────────
        .route(
            "/auth/preferences",
            routing::get(preferences::get_preferences)
                .patch(preferences::update_preferences),
        )
}

/// Cloudflare Workers fetch 入口
///
/// 将所有入站 HTTP 请求转发至 Axum 路由器处理。
#[event(fetch)]
async fn fetch(
    req: HttpRequest,
    _env: Env,
    _ctx: Context,
) -> Result<http::Response<body::Body>> {
    Ok(router().call(req).await?)
}
