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

use axum::{body, http};
use worker;

mod logic;

#[worker::event(fetch)]
async fn fetch(
    _req: worker::Request,
    _env: worker::Env,
    _ctx: worker::Context,
) -> worker::Result<http::Response<body::Body>> {
    todo!()
}
