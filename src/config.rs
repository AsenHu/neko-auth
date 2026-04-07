//! 域名级别的配置定义与加载逻辑
//!
//! 每个接入域名在 Cloudflare Workers 中对应一个同名 Secret，
//! 值为 JSON 格式的 [`DomainConfig`]。
//!
//! # 配置格式示例
//!
//! Secret 的 key 为去掉端口的请求域名（如 `app.example.com`），value 为：
//!
//! ```json
//! {
//!   "oidc": {
//!     "issuer": "https://accounts.google.com",
//!     "client_id": "…",
//!     "client_secret": "…",
//!     "redirect_uri": "https://app.example.com/auth/oidc/callback",
//!     "scopes": ["openid", "email", "profile"]
//!   },
//!   "post_login_redirect_uri": "https://app.example.com/",
//!   "default_preferences": {
//!     "idle_timeout": { "type": "permanent" },
//!     "tor_transition": "deny"
//!   },
//!   "jwt": {
//!     "at_secret_seed": "…",
//!     "rt_secret_seed": "…",
//!     "at_ttl_seconds": 900,
//!     "rt_ttl_seconds": 2592000
//!   }
//! }
//! ```

use serde::Deserialize;
use worker::Env;

use crate::types::{IdleTimeout, TorTransition, UserPreferences};

const DEV_HOST: &str = "neko-auth-dev.g61.workers.dev";

/// 从 Workers Secrets 中加载指定域名的配置并解析
///
/// 以 `host`（去掉端口）为 key 读取对应的 Secret，
/// 将其反序列化为 [`DomainConfig`]。
///
/// # 错误
///
/// - Secret 不存在（域名未配置）：返回 `worker::Error`
/// - JSON 格式非法（配置损坏）：返回 `worker::Error`，消息中包含具体原因
pub fn load(host: &str, env: &Env) -> worker::Result<DomainConfig> {
    if host == DEV_HOST {
        return Ok(hardcoded_dev_config());
    }

    let raw = env.secret(host)?.to_string();
    serde_json::from_str(&raw)
        .map_err(|e| worker::Error::RustError(format!("invalid config for '{host}': {e}")))
}

fn hardcoded_dev_config() -> DomainConfig {
    DomainConfig {
        oidc: OidcProviderConfig {
            issuer: "https://account.lolinya.net".to_string(),
            client_id: "nya_pYvrP44jkKLRuUrtv0YQI".to_string(),
            client_secret: "chino_FhQsNVmg_8fXDrZo1LTT8DaLWIr0ydTN".to_string(),
            redirect_uri: "https://neko-auth-dev.g61.workers.dev/auth/oidc/callback".to_string(),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
        },
        post_login_redirect_uri: "https://neko-auth-dev.g61.workers.dev/".to_string(),
        post_logout_redirect_uri: Some("https://neko-auth-dev.g61.workers.dev/".to_string()),
        default_preferences: UserPreferences {
            idle_timeout: IdleTimeout::Permanent,
            tor_transition: TorTransition::Deny,
        },
        jwt: JwtConfig {
            at_secret_seed: "dev-only-at-seed-neko-auth-2026-04-08-change-after-smoke-test"
                .to_string(),
            rt_secret_seed: "dev-only-rt-seed-neko-auth-2026-04-08-change-after-smoke-test"
                .to_string(),
            at_ttl_seconds: 900,
            rt_ttl_seconds: 2_592_000,
        },
        cookie: CookieConfig::default(),
        oidc_state_ttl_seconds: default_oidc_state_ttl_seconds(),
    }
}

/// 单个域名的完整运行配置
#[derive(Debug, Clone, Deserialize)]
pub struct DomainConfig {
    /// OIDC 提供商连接参数
    pub oidc: OidcProviderConfig,

    /// 登录成功后浏览器跳回的固定地址，不接受外部参数覆盖
    pub post_login_redirect_uri: String,

    /// RP-Initiated Logout 完成后的可选跳转地址
    pub post_logout_redirect_uri: Option<String>,

    /// 新用户首次登录时使用的默认安全偏好
    pub default_preferences: UserPreferences,

    /// AT / RT 的 JWT 签名与有效期配置
    pub jwt: JwtConfig,

    /// Refresh Token Cookie 策略
    #[serde(default)]
    pub cookie: CookieConfig,

    /// OIDC state 的短期存活时间（秒）
    #[serde(default = "default_oidc_state_ttl_seconds")]
    pub oidc_state_ttl_seconds: u64,
}

/// OIDC 提供商连接参数
#[derive(Debug, Clone, Deserialize)]
pub struct OidcProviderConfig {
    /// IdP 的 Issuer URL，用于 OIDC Discovery（`/.well-known/openid-configuration`）
    pub issuer: String,

    /// 在 IdP 注册的 Client ID
    pub client_id: String,

    /// 在 IdP 注册的 Client Secret（用于 Token Endpoint 鉴权）
    pub client_secret: String,

    /// 授权成功后的回调 URI（须与 IdP 侧注册完全一致）
    pub redirect_uri: String,

    /// 请求的 OIDC scope 列表（至少包含 `"openid"`）
    pub scopes: Vec<String>,
}

/// JWT 签名与有效期配置
#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    /// Access Token 签名密钥的随机种子
    ///
    /// 实际密钥由此种子派生，种子本身不直接参与签名运算。
    pub at_secret_seed: String,

    /// Refresh Token 签名密钥的随机种子
    pub rt_secret_seed: String,

    /// Access Token 的有效时长（秒）
    pub at_ttl_seconds: u64,

    /// Refresh Token 的有效时长（秒）
    pub rt_ttl_seconds: u64,
}

/// Refresh Token Cookie 配置
#[derive(Debug, Clone, Deserialize)]
pub struct CookieConfig {
    /// Cookie 名称，默认使用 `__Http-` 前缀以禁止 Domain 属性
    #[serde(default = "default_refresh_cookie_name")]
    pub refresh_token_name: String,

    /// Cookie Path，默认仅暴露给续期接口
    #[serde(default = "default_refresh_cookie_path")]
    pub refresh_token_path: String,

    /// SameSite 策略，首版固定按字符串写入响应头
    #[serde(default = "default_same_site")]
    pub same_site: String,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            refresh_token_name: default_refresh_cookie_name(),
            refresh_token_path: default_refresh_cookie_path(),
            same_site: default_same_site(),
        }
    }
}

fn default_refresh_cookie_name() -> String {
    "__Http-refresh-token".to_string()
}

fn default_refresh_cookie_path() -> String {
    "/auth/session/refresh".to_string()
}

fn default_same_site() -> String {
    "Strict".to_string()
}

fn default_oidc_state_ttl_seconds() -> u64 {
    600
}
