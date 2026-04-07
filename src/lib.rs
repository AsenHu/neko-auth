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

use std::sync::Arc;

use axum::{Router, body, http, routing};
use tower_service::Service;
use worker::*;

use handlers::{oidc, preferences, session, sessions};

mod api;
mod app;
mod config;
mod do_protocol;
mod durable_objects;
mod handlers;
mod oidc_flow;
mod request_context;
mod security;
mod storage;
mod types;

/// 构建应用路由表
///
/// 路由按功能域分组，便于维护和权限管理。
/// 注意：`/auth/session/refresh` 必须在 `/auth/session` 之前注册，
/// 避免路由匹配歧义（Axum 按注册顺序进行最长前缀匹配）。
///
/// 返回 `Router<Arc<AppState>>`，由调用方通过 `.with_state(state)`
/// 填入域名配置后即可对外提供服务。
fn router() -> Router<Arc<app::AppState>> {
    Router::new()
        // ── OIDC 认证流程 ──────────────────────────────────────────────────
        // 发起授权：生成 state + PKCE challenge，302 重定向至 IdP
        .route("/auth/oidc/authorize", routing::get(oidc::authorize))
        // 登录回调：支持 GET（Query String 模式）和 POST（Form Post 模式）
        .route(
            "/auth/oidc/callback",
            routing::get(oidc::callback_get).post(oidc::callback_post),
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
            routing::get(sessions::list_sessions).delete(sessions::batch_delete),
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
            routing::get(preferences::get_preferences).patch(preferences::update_preferences),
        )
}

/// Cloudflare Workers fetch 入口
///
/// 流程：
/// 1. 从 `Host` 头提取请求域名（去掉端口）
/// 2. 以域名为 key 从 Workers Secrets 中加载并解析 [`config::DomainConfig`]
/// 3. 将配置注入路由器的 State，然后处理请求
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<http::Response<body::Body>> {
    // 提取 Host 头，去掉可能附带的端口号（如 "example.com:443" → "example.com"）
    let host = req
        .headers()
        .get("Host")?
        .and_then(|h| h.split(':').next().map(str::to_string))
        .unwrap_or_default();

    let request_context = request_context::from_worker_request(&req);
    let trace_id = request_context::trace_id(req.headers());

    // 以域名为 key 从 Workers Secrets 加载 JSON 配置并解析
    let config = match config::load(&host, &env) {
        Ok(c) => c,
        Err(_) => return Ok(domain_error_response(&host)),
    };

    let req: HttpRequest = req.try_into()?;
    let state = Arc::new(app::AppState {
        host,
        config,
        env,
        context: request_context,
        trace_id,
    });

    // 将域名配置与 Workers Env 注入 State，供各 handler 提取
    Ok(router().with_state(state).call(req).await?)
}

/// 域名配置加载失败时返回的标准错误响应
///
/// 可能原因：域名对应的 Secret 不存在，或 JSON 格式损坏。
fn domain_error_response(host: &str) -> http::Response<body::Body> {
    let body = serde_json::json!({
        "code": "DOMAIN_NOT_CONFIGURED",
        "message": format!("no valid configuration found for domain '{host}'"),
    })
    .to_string();

    http::Response::builder()
        .status(http::StatusCode::SERVICE_UNAVAILABLE)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(body::Body::from(body))
        .expect("error response is always valid")
}
