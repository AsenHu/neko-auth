//! 公共数据类型定义
//!
//! 本模块定义所有 API 层的请求/响应数据结构，
//! 严格对应 README 中的接口规范（§2.1 ~ §2.5）。

use std::{collections::HashMap, net::IpAddr};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

// ─── 统一响应封装 ────────────────────────────────────────────────────────────

/// 业务成功时的统一响应外层封装
///
/// 所有接口在处理成功后均使用此结构包裹业务数据，参见 README §2.1.2。
#[derive(Debug, Serialize)]
pub struct SuccessResponse<T: Serialize> {
    /// 固定为 `"SUCCESS"`
    pub code: &'static str,

    /// 业务数据载荷；无数据时该字段在 JSON 中缺失
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,

    /// 服务端处理时的精确 UTC 时间戳（纳秒级 ISO 8601 / RFC 3339）
    #[serde(with = "time::serde::rfc3339")]
    pub server_time: OffsetDateTime,

    /// 全链路追踪 ID，对应 Cloudflare Ray ID，用于问题排查
    pub trace_id: String,
}

impl<T: Serialize> SuccessResponse<T> {
    pub fn new(data: Option<T>, server_time: OffsetDateTime, trace_id: impl Into<String>) -> Self {
        Self { code: "SUCCESS", data, server_time, trace_id: trace_id.into() }
    }
}

/// 业务失败时的统一响应外层封装
///
/// 所有接口在处理失败、权限不足或发生异常时使用此结构，参见 README §2.1.3。
#[derive(Debug, Serialize)]
pub struct FailureResponse<E: Serialize> {
    /// 语义化错误码，例如 `"INVALID_TOKEN"`、`"AUTH_IDLE_TIMEOUT"`
    pub code: String,

    /// 人类可读的错误描述，包含动态上下文信息，可直接用于调试
    pub message: String,

    /// 结构化错误详情；仅当该错误码有关联上下文参数时存在
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<E>,

    /// 服务端处理时的精确 UTC 时间戳
    #[serde(with = "time::serde::rfc3339")]
    pub server_time: OffsetDateTime,

    /// 全链路追踪 ID
    pub trace_id: String,
}

impl FailureResponse<()> {
    /// 构造一个不带 `details` 的简单错误响应
    pub fn simple(
        code: impl Into<String>,
        message: impl Into<String>,
        server_time: OffsetDateTime,
        trace_id: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: None,
            server_time,
            trace_id: trace_id.into(),
        }
    }
}

// ─── 共享业务模型 ─────────────────────────────────────────────────────────────

/// Cloudflare 注入的地理与网络元数据
///
/// 使用 `serde_json::Value` 保留原始结构，以兼容未来 CF 侧字段变更。
///
/// 字段定义参见：
/// <https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties>
pub type Cf = Value;

/// 当前请求的物理接入环境（实时状态）
#[derive(Debug, Serialize, Deserialize)]
pub struct RequestContext {
    /// 客户端 IP 地址（IPv4 或 IPv6）
    pub ip: IpAddr,

    /// Cloudflare 注入的地理与网络元数据
    pub cf: Cf,
}

/// 可选字段更新语义
///
/// 用于 PATCH 接口的请求体，明确区分三种更新意图：
/// - 字段缺失（`Ignore`）：不修改
/// - 字段为 `null`（`Delete`）：清空
/// - 字段有具体值（`Set(T)`）：写入
///
/// > **注意**：具体的 JSON 序列化方案尚未确定（参见 README §2.3.3），
/// > 目前暂不提供 `Serialize`/`Deserialize` 实现。
#[derive(Debug, Default)]
pub enum FieldUpdate<T> {
    /// 不修改该字段（JSON 中字段缺失）
    #[default]
    Ignore,

    /// 清空该字段（JSON 中字段值为 `null`）
    Delete,

    /// 将字段设置为指定值
    Set(T),
}

/// 修改会话属性的请求体
///
/// 供 `PATCH /auth/session` 和 `PATCH /auth/sessions/{session_id}` 使用。
#[derive(Debug)]
pub struct UpdateSessionRequest {
    /// 设备的自定义别名（如 `"我的办公 MacBook"`）
    ///
    /// 序列化方案待定，参见 README §2.3.3
    pub alias: FieldUpdate<String>,
}

/// 修改会话属性成功后的响应载荷
///
/// 供 `PATCH /auth/session` 和 `PATCH /auth/sessions/{session_id}` 使用。
#[derive(Debug, Serialize)]
pub struct UpdateSessionData {
    /// 被修改的会话全局唯一标识（256-bit Global ID）
    pub session_id: String,

    /// 更新后的设备别名；若已清空则该字段在 JSON 中缺失
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

/// OIDC RP-Initiated Logout 引导指令
///
/// 当会话被注销且服务端配置了 OIDC 同步登出时返回。
/// 客户端应按照 `method` 向 `target` 发起请求以完成 IdP 侧的全局登出。
///
/// 参见：<https://openid.net/specs/openid-connect-rpinitiated-1_0.html>
#[derive(Debug, Serialize, Deserialize)]
pub struct OidcLogoutAction {
    /// 浏览器发起登出请求所使用的 HTTP 方法
    pub method: LogoutMethod,

    /// IdP 的登出端点 URL
    pub target: String,

    /// 随请求携带的参数（如 `id_token_hint`、`post_logout_redirect_uri`）
    ///
    /// - `GET`：拼接为 Query String
    /// - `POST`：编码为 `application/x-www-form-urlencoded` 请求体
    pub fields: HashMap<String, String>,
}

/// OIDC 登出请求的 HTTP 方法
#[derive(Debug, Serialize, Deserialize)]
pub enum LogoutMethod {
    #[serde(rename = "GET")]
    Get,

    #[serde(rename = "POST")]
    Post,
}

/// 会话分类标记
///
/// 用于在多设备列表中区分当前正在使用的设备与其他远程设备。
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionKind {
    /// 当前正在发出本次请求的设备
    Current,

    /// 其他远程设备
    Remote,
}

// ─── OIDC 认证流程请求类型 ───────────────────────────────────────────────────

/// OIDC 授权回调的通用参数（GET Query 和 POST Form 共用）
///
/// 参见 OIDC Core §3.1.2.5：
/// <https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse>
#[derive(Debug, Deserialize)]
pub struct OidcCallbackParams {
    /// IdP 返回的授权码（认证成功时存在）
    pub code: Option<String>,

    /// 服务端在发起授权时生成的 CSRF 防护随机值（始终存在）
    pub state: String,

    /// OIDC 错误码（认证失败时存在，如 `"access_denied"`）
    pub error: Option<String>,

    /// 错误的人类可读描述（认证失败时可选存在）
    pub error_description: Option<String>,
}

/// `POST /auth/oidc/backchannel_logout` 的 Form 请求体
///
/// 参见 OpenID Connect Back-Channel Logout 1.0 §2.5：
/// <https://openid.net/specs/openid-connect-backchannel-1_0.html>
#[derive(Debug, Deserialize)]
pub struct BackchannelLogoutForm {
    /// 由 IdP 签发的登出令牌（JWT）
    pub logout_token: String,
}

// ─── 会话管理（/auth/session）────────────────────────────────────────────────

/// `GET /auth/session` 的查询参数
#[derive(Debug, Deserialize)]
pub struct GetSessionQuery {
    /// 是否同时返回重量级身份数据（`identity` 和 `protected` 字段）
    ///
    /// 默认为 `false`；设为 `true` 时会额外从存储中检索身份快照，响应略慢。
    #[serde(default)]
    pub identity: bool,
}

/// `GET /auth/session` 的成功响应载荷
#[derive(Debug, Serialize)]
pub struct GetSessionData {
    /// 当前会话/设备的全局唯一标识（256-bit Global ID）
    pub session_id: String,

    /// 当前物理连接的实时接入环境
    pub context: RequestContext,

    /// OIDC 提供商返回的原始非敏感用户声明（Raw Claims）
    ///
    /// 数据结构取决于 IdP 实现，可用于展示头像、昵称等基础信息。
    /// 仅在请求参数 `identity=true` 时存在。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Value>,

    /// 服务端签名的受保护身份凭据（JWS Compact Serialization）
    ///
    /// 客户端应将其视为不透明字符串传输，解码后的载荷结构参见 [`ProtectedJwsPayload`]。
    /// 仅在请求参数 `identity=true` 时存在。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected: Option<String>,
}

/// `GET /auth/session` 中 `protected` 字段解码后的 JWS 载荷
///
/// 代表已通过 OIDC 强验证的身份属性，由服务端签名背书，不可篡改。
#[derive(Debug, Serialize, Deserialize)]
pub struct ProtectedJwsPayload {
    /// 用户的唯一标识（Subject），用于关联业务账户
    pub sub: String,

    /// 已验证的电子邮件地址
    ///
    /// 仅当 OIDC 侧 `email_verified` 为 `true` 时存在。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// 已验证的电话号码
    ///
    /// 仅当 OIDC 侧 `phone_number_verified` 为 `true` 时存在。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    // 其他标准 JWT 字段（exp、iss、aud 等）由签名逻辑自动处理，此处不列出。
}

/// `POST /auth/session/refresh` 的成功响应载荷
#[derive(Debug, Serialize)]
pub struct SessionRefreshData {
    /// 新签发的 Access Token（JWT）
    ///
    /// 客户端应存储于内存中，用于后续接口的 `Authorization: Bearer <token>` 头。
    pub access_token: String,

    /// 当前 Access Token 的精确到期时间（UTC）
    ///
    /// 前端可据此预判续期时机，处理连续滚动逻辑。
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// `DELETE /auth/session` 的成功响应载荷
#[derive(Debug, Serialize)]
pub struct DeleteSessionData {
    /// 被注销的会话/设备 ID（256-bit Global ID）
    pub session_id: String,

    /// OIDC RP-Initiated Logout 引导指令
    ///
    /// 仅在服务端配置了 OIDC 同步登出且该 Session 依然有效时返回。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logout: Option<OidcLogoutAction>,
}

// ─── 多设备审计（/auth/sessions）────────────────────────────────────────────

/// `GET /auth/sessions` 响应中的单个设备条目
#[derive(Debug, Serialize)]
pub struct SessionListItem {
    /// 设备的全局唯一标识（256-bit Global ID）
    pub session_id: String,

    /// 会话分类（当前设备或远程设备）
    pub kind: SessionKind,

    /// 用户设置的设备别名
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,

    /// 最后一次活跃的精确 UTC 时间
    #[serde(with = "time::serde::rfc3339")]
    pub last_active_at: OffsetDateTime,

    /// 最近活跃时的客户端 IP 地址
    pub ip: IpAddr,

    /// 浏览器/客户端原始 User-Agent 指纹
    pub ua: String,

    /// 详细地理位置信息（由 Cloudflare 提供）
    pub location: SessionGeoLocation,
}

/// 设备的地理位置信息
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionGeoLocation {
    /// Cloudflare 数据中心三字代码（如 `"HKG"`、`"SJC"`）
    pub colo: String,

    /// 国家/地区代码（ISO 3166-1 alpha-2，如 `"CN"`）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,

    /// 城市名称（如 `"Hangzhou"`）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,

    /// 大洲代码（如 `"AS"`、`"NA"`）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continent: Option<String>,

    /// 经纬度坐标，格式为 `(latitude, longitude)`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coordinates: Option<(f32, f32)>,

    /// 邮政编码（如 `"310000"`、`"78701"`）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,

    /// 都会区代码（DMA，如 `"635"`）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metro_code: Option<String>,

    /// 第一级行政区划名称（如 `"Zhejiang"`、`"Texas"`）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// 第一级行政区划代码（ISO 3166-2，如 `"ZJ"`、`"TX"`）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region_code: Option<String>,
}

/// `GET /auth/sessions/{session_id}` 的成功响应载荷
#[derive(Debug, Serialize)]
pub struct SessionDetailData {
    /// 设备的全局唯一标识（256-bit Global ID）
    pub session_id: String,

    /// 会话分类
    pub kind: SessionKind,

    /// 用户自定义别名
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,

    /// 该设备首次在本系统注册的精确 UTC 时间
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,

    /// 最后一次活跃的精确 UTC 时间
    #[serde(with = "time::serde::rfc3339")]
    pub last_active_at: OffsetDateTime,

    /// 该设备最后一次活跃时的物理接入环境快照
    pub context: SessionContext,
}

/// 设备活跃时的接入环境快照
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionContext {
    /// 最近活跃时的客户端 IP 地址
    pub ip: IpAddr,

    /// 浏览器/客户端原始 User-Agent 指纹
    pub ua: String,

    /// 完整的 Cloudflare 地理与网络元数据快照
    ///
    /// 包含 TLS 指纹（`tlsClientHelloEcho`）、ISP 名称（`asOrganization`）等详细信息。
    /// 字段定义参见：
    /// <https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties>
    pub cf: Cf,
}

/// `DELETE /auth/sessions` 的查询参数
#[derive(Debug, Deserialize)]
pub struct BatchDeleteQuery {
    /// 注销范围
    pub scope: SessionDeleteScope,
}

/// `DELETE /auth/sessions` 的成功响应载荷
#[derive(Debug, Serialize)]
pub struct BatchDeleteSessionsData {
    /// 成功注销的会话总数
    pub count: u32,

    /// 执行的注销范围
    pub scope: SessionDeleteScope,

    /// OIDC RP-Initiated Logout 引导指令
    ///
    /// 仅在 `scope` 为 `all` 且当前会话被包含在注销范围内时返回。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logout: Option<OidcLogoutAction>,
}

/// 批量注销会话的范围
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionDeleteScope {
    /// 注销除当前会话外的所有其他活跃会话
    Others,

    /// 注销该账号下全部活跃会话（含当前会话）
    All,
}

// ─── 账户安全偏好（/auth/preferences）──────────────────────────────────────

/// 用户的全局账户安全配置
///
/// 供 `GET /auth/preferences` 响应和 `PATCH /auth/preferences` 响应使用。
#[derive(Debug, Serialize, Deserialize)]
pub struct UserPreferences {
    /// 闲置自动登出时限
    pub idle_timeout: IdleTimeout,

    /// Tor 网络接入切换策略
    pub tor_transition: TorTransition,
}

/// 闲置超时配置
///
/// 控制会话在无活动状态下的最大存活时长。
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum IdleTimeout {
    /// 设置具体的闲置时限（以秒为单位存储与传输）
    Duration {
        #[serde(with = "duration_seconds")]
        value: Duration,
    },

    /// 永不因闲置而登出
    Permanent,
}

/// Tor 网络接入切换策略
///
/// 控制同一会话是否允许在 Tor 与非 Tor 网络之间切换。
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TorTransition {
    /// 允许在普通网络与 Tor 之间切换
    Allow,

    /// 禁止切换，一旦检测到变化立即注销该会话
    Deny,
}

/// `PATCH /auth/preferences` 的请求体
#[derive(Debug, Deserialize)]
pub struct UpdatePreferencesRequest {
    /// 修改闲置自动登出时限；不提供则不修改
    pub idle_timeout: Option<IdleTimeout>,

    /// 修改 Tor 切换策略；不提供则不修改
    pub tor_transition: Option<TorTransition>,
}

// ─── 辅助模块 ────────────────────────────────────────────────────────────────

/// `time::Duration` 的秒数序列化辅助模块
///
/// 将 `Duration` 序列化为整数秒，反序列化时从整数秒还原。
mod duration_seconds {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        d.whole_seconds().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = i64::deserialize(d)?;
        Ok(Duration::seconds(secs))
    }
}
