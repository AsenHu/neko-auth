# neko-auth

该模块采用 **OIDC (OpenID Connect)** 标准处理身份认证，结合**双 Token 旋转机制**确保会话安全，并提供精细化的**多设备审计与全局安全策略**配置。

## 1 接口概览

### 1.1 OIDC 认证流程 `/auth/oidc`

负责处理与第三方身份提供商（IdP）的交互，管理从登录发起到远程登出的完整生命周期。

| 方法 | 路径 | 说明 | 备注 |
| :--- | :--- | :--- | :--- |
| `GET` | `/auth/oidc/authorize` | 发起 OIDC 授权请求 | **302 重定向**至提供商登录页，支持 `state` 校验。 |
| `GET/POST` | `/auth/oidc/callback` | 登录授权回调 | 接收 `code` 并换取 Token，建立本地会话与设备关联。 |
| `POST` | `/auth/oidc/backchannel_logout` | 远程撤销回调 | 接收提供商的 **Back-channel Logout** 通知，同步注销本地会话。 |

### 1.2 会话管理 `/auth/session`

管理用户在当前活跃设备上的实时登录状态与令牌续期。

| 方法 | 路径 | 说明 | 备注 |
| :--- | :--- | :--- | :--- |
| `GET` | `/auth/session` | 获取当前用户信息 | 返回用户资料、权限清单及**当前设备 ID**。 |
| `POST` | `/auth/session/refresh` | 令牌续期 | 采用 **Token Rotation**，旧 Token 立即作废并触发 `idle_timeout` 检查。 |
| `PATCH` | `/auth/session` | 修改当前设备属性 | 例如修改设备别名 |
| `DELETE` | `/auth/session` | 主动登出当前设备 | 立即注销当前设备的 Access/Refresh Token。 |

### 1.3 设备管理器 `/auth/sessions`

提供用户对账号登录情况的审计能力，允许识别异常登录并执行远程强制退出。

| 方法 | 路径 | 说明 | 备注 |
| :--- | :--- | :--- | :--- |
| `GET` | `/auth/sessions` | 获取活跃设备列表 | 列表包含 IP、地理位置、UA 及最后活动时间。 |
| `GET` | `/auth/sessions/{session_id}` | 获取特定设备详情 | 返回该设备的详细指纹信息（如浏览器版本、TLS 属性等）。 |
| `PATCH` | `/auth/sessions/{session_id}` | 修改设备属性 | 目前支持修改设备别名（`alias`），提升审计识别度。 |
| `DELETE` | `/auth/sessions/{session_id}` | 强制注销指定设备 | 远程撤销该设备关联的所有令牌，实现“踢出”功能。 |
| `DELETE` | `/auth/sessions` | 批量注销设备 | 通过 `scope` 参数指定：`others`（踢出其他）或 `all`（全量退出）。 |

### 1.4 账户偏好设置 `/auth/preferences`

定义账户全局的安全防御策略，影响所有关联设备的会话生存期与接入逻辑。

| 方法 | 路径 | 说明 | 备注 |
| :--- | :--- | :--- | :--- |
| `GET` | `/auth/preferences` | 获取全局安全配置 | 返回当前账号生效的 `idle_timeout` 与 `tor_transition` 策略。 |
| `PATCH` | `/auth/preferences` | 修改账户安全配置 | 允许更新安全策略，采用语义化字符串进行配置。 |

## 2 接口定义

### 2.1 统一规范

#### 2.1.1 请求头

| Header | 格式 | 说明 |
| :--- | :--- | :--- |
| `Authorization` | `Bearer <access_token>` | 身份凭证 |
| `Content-Type` | `application/json` | 想写就写吧 |

Access Token 从 `POST /auth/session/refresh` 接口获取。

大多数接口都需要 `Authorization` 请求头，具体见接口详情。

`Content-Type` 建议写一下，不过不写通常也不会失败。

#### 2.1.2 成功响应模型

当业务处理成功时返回

```rust
pub struct SuccessResponse<T> {
    /// 语义化的成功标识符。固定为 "SUCCESS"
    pub code: String,

    /// 业务数据载荷
    pub data: Option<T>,

    /// 服务端当前的精确处理时间 (UTC)
    /// 类型: time::OffsetDateTime (纳秒级 ISO 8601 字符串)
    pub server_time: OffsetDateTime,

    /// 全链路追踪 ID，对应 Cloudflare Ray ID，用于问题排查
    pub trace_id: String,
}
```

#### 2.1.3 错误响应模型

当业务处理失败、权限不足或发生异常时返回。

```rust
pub struct FailureResponse<E> {
    /// 语义化的错误代码。例如 "AUTH_IDLE_TIMEOUT"、"INVALID_TOKEN"。
    pub code: String,

    /// 人类友好的错误描述。包含动态生成的上下文信息，可直接用于调试。
    pub message: String,

    /// 结构化的错误详情（可选）。
    /// [逻辑]：仅当该错误码有关联的上下文参数时存在，否则该字段在 JSON 中缺失。
    pub details: Option<E>,

    /// 服务端当前的精确处理时间 (UTC)
    /// 类型: time::OffsetDateTime (纳秒级 ISO 8601 字符串)
    pub server_time: OffsetDateTime,

    /// 全链路追踪 ID。
    pub trace_id: String,
}
```

### 2.2 OIDC 认证流程 `/auth/oidc`

OIDC 认证流程接口严格遵守 OIDC 规范，因此对于规范中已有的行为引用规范链接。

所有的 OIDC 接口都不需要 `Authorization` 请求头。

#### 2.2.1 发起授权 `GET /auth/oidc/authorize`

该接口不需要身份验证，也没有传入的参数。

1. 遵循 **[OpenID Connect Core 1.0 - Section 3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)**，完全基于服务端预置的身份提供商（IdP）配置文件构造认证重定向 URL。
2. 服务端强制采用 **[Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)**（授权码模式），通过设置 `response_type=code` 确保所有令牌换取过程均在受控的 Back-channel 环境下完成。
3. 服务端自动生成并持久化加密级随机 **`state`** 以防御 CSRF 攻击，并强制执行 **[RFC 7636 (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)** 规范，生成 `code_challenge` 并本地安全持有 `code_verifier`。
4. 接口不接受任何形式的外部 `redirect_uri` 或目标跳转参数，登录成功后的重定向目标由服务端逻辑强制锁定，以杜绝重定向攻击或非预期的 API 自动执行。

#### 2.2.2 登录回调 `GET/POST /auth/oidc/callback`

1. 遵循 **[OpenID Connect Core 1.0 - Section 3.1.2.5](https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse)** 处理认证响应。
2. 建议身份提供商（IdP）采用 **[OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)** 方式发起回调，以确保敏感的 `code` 仅在请求体中传输，避免出现在浏览器历史记录或服务器访问日志中。
3. 服务端对 **`state`** 挑战值执行严格校验。该值必须由 `GET /auth/oidc/authorize` 生成，并且只能使用一次，无论认证是否成功。
4. 认证成功后，服务端签发 **Refresh Token** 并通过 Cookie 进行持久化设置。

Cookie 格式参见 `POST /auth/session/refresh`

服务端在完成 Cookie 设置后，将向浏览器返回 302 Found 响应，将其引导至系统预设的默认主页，前端主页加载后，需要静默调用一次 `POST /auth/session/refresh`（此时浏览器会自动带上刚才设置的 RT Cookie），从而获取到首个 Access Token 和用户信息。

#### 2.2.3 远程撤销回调 `POST /auth/oidc/backchannel_logout` (可选)

1. 本接口属于 **[OpenID Connect Back-channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)** 扩展规范的实现。
2. 若系统中未找到对应的会话（可能已由用户手动退出），服务端依然返回 200 OK，以确保 IdP 端的同步状态幂等且流程闭环。

### 2.3 会话管理 `/auth/session`

管理用户在当前活跃设备上的实时登录状态与令牌续期。

#### 2.3.1 获取当前用户信息 `GET /auth/session`

本接口返回当前活跃会话的完整上下文、身份快照及由服务端签名背书的受保护凭据。支持通过查询参数按需获取重量级身份数据。

需要 `Authorization` 请求头。

Query 参数

| 参数 | 类型 | 必选 | 说明 |
| :--- | :--- | :--- | :--- |
| `identity` | `bool` | 否 | 默认为 `false`。仅当设为 `true` 时，响应中才会包含 `identity` 和 `protected` 字段。 |

若客户端仅需校验 Token 有效性或获取当前物理接入环境（RequestContext），建议保持 `identity=false`。这可以跳过服务端对身份快照的检索，显著提升响应速度。

```rust
pub struct GetSessionData {
    /// 当前会话/设备的全局唯一标识 (256-bit Global ID)
    pub session_id: String,

    /// 运行上下文：反映当前物理连接的实时状态
    pub context: RequestContext,

    /// 身份快照：OIDC 提供商返回的全部原始非敏感声明 (Raw Claims)
    /// 数据结构取决于 IdP 的具体实现，前端可用于展示头像、昵称等基础信息
    /// 是一个 JSON
    /// 仅在请求参数 `identity=true` 时存在
    pub identity: Option<Value>,

    /// 受保护的身份凭据 (JWS 紧凑序列化字符串)
    /// 该字段为不可篡改的服务端签名，客户端应将其视为不透明 String 传输
    /// 解析后的载荷结构参考下文：ProtectedJwsPayload
    /// 仅在请求参数 `identity=true` 时存在
    pub protected: Option<String>,
}

pub struct RequestContext {
    /// 客户端物理 IP 地址 (IPv4 或 IPv6)
    pub ip: IpAddr,

    /// Cloudflare 提供的地理与网络元数据
    /// 字段定义参考: https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties
    pub cf: Cf, 
}

/// 解码后的受保护 JWS 载荷 (Protected JwsPayload)
/// 代表在 OIDC 端已经过强验证（Verified）的身份属性
pub struct ProtectedJwsPayload {
    /// 用户的唯一标识 (Subject)，用于关联业务账户
    pub sub: String,

    /// 经验证的电子邮件地址
    /// [逻辑]：仅在 OIDC 侧 email_verified 为 true 时存在
    pub email: Option<String>,

    /// 经验证的电话号码
    /// [逻辑]：仅在 OIDC 侧 phone_number_verified 为 true 时存在
    pub phone_number: Option<String>,

    /*
        其他标准 JWT 字段（如 exp, iss, aud 等）由签名逻辑自动处理
        此处仅列出业务相关的受保护字段
    */
}
```

暂时还不知道失败时会产生什么错误

#### 2.3.2 令牌续期 `POST /auth/session/refresh`

本接口负责 Access Token (AT) 的滚动更新及 Refresh Token (RT) 的安全旋转。接口设计基于 **Account-Level Actor 模型**，在保证极速响应的同时，通过严苛的令牌序列校验与多维度环境监控实现工业级的防御强度。

由于 Cookie 的发送只能指定到路径，因此使用 `POST /auth/session/refresh` 而不是 `POST /auth/session`

不需要 `Authorization` 请求头，需要的参数由服务端通过 Cookie 管理。

请求需要的 Cookie 如下。

| 键 | 值 | 说明 |
| :--- | :--- | :--- |
| `__Http-refresh-token` | `<Refresh Token>` | 颁发的 Refresh Token |

成功时会设置一个 Cookie 到浏览器，格式如下。

| 属性 | 值 | 说明 |
| :--- | :--- | :--- |
| `__Http-refresh-token` | `<Refresh Token>` | 颁发的 Refresh Token |
| `Domain` | 无 | 禁止子域名访问 |
| `Expires` | `<date>` | 过期时间 |
| `HttpOnly` | 有 | 禁止任何 JavaScript 脚本访问 |
| `Path` | `/auth/session/refresh` | 确保凭证仅在续期接口暴露 |
| `SameSite` | `Strict` | 禁止在任何第三方发起的请求中携带此 Cookie |
| `Secure` | 有 | 强制仅在加密的 HTTPS 连接中传输 |

`__Http-` 是一个新前缀，不是我写错了，[参见](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#cookie_prefixes)

此外，还会返回 Access Token 以供请求其他接口，格式如下。

```rust
pub struct SessionRefreshData {
    /// 新签发的 Access Token (JWT)
    /// 客户端应将其存储于内存中，用于业务接口鉴权
    pub access_token: String,
    
    /// 当前 Access Token 的精确到期时间戳 (UTC)
    /// 类型参考: Rust `time::OffsetDateTime` (纳秒精度 ISO 8601 字符串)
    /// 用于前端预判自动续期时机及处理连续滚动逻辑
    pub expires_at: OffsetDateTime,
}
```

暂时还不知道失败时会产生什么错误

#### 2.3.3 修改当前会话属性 `PATCH /auth/session`

本接口允许用户修改当前正在使用的设备/会话的元数据（如别名），无需通过设备 ID 即可快捷操作。

需要 `Authorization` 请求头。

请求体如下

```rust
pub struct UpdateSessionRequest {
    /// 设备的自定义别名 (如 "我的办公 MacBook")
    /// [逻辑]：若为 null 则保持不变，若为空字符串则清空别名
    pub alias: FieldUpdate<String>,
}

pub enum FieldUpdate<T> {
    /// 不修改：JSON 中缺失该键
    Ignore,
    /// 删除/重置：JSON 中该键的值为 null
    Delete,
    /// 设置/更新：JSON 中该键为具体类型的值
    Set(T),
}
```

成功时返回

```rust
pub struct UpdateSessionData {
    /// 当前会话/设备的全局唯一标识 (256-bit Global ID)
    pub session_id: String,

    /// 更新后的设备别名
    pub alias: Option<String>,
}
```

暂时还不知道失败时会产生什么错误

#### 2.3.4 销毁当前会话 `DELETE /auth/session`

用户主动注销当前设备的登录状态。

- 由于 Access Token 为无状态 JWT，在服务端注销会话后，该 Token 在其剩余寿命内理论上仍可访问业务接口。
- 调用本接口成功后，客户端必须立即从内存中抹除 Access Token。

需要 `Authorization` 请求头，无请求参数。

成功时返回

```rust
pub struct DeleteSessionData {
    /// 被注销的会话/设备 ID (256-bit Global ID)
    pub session_id: String,

    /// [可选] 引导全局登出的指令
    /// https://openid.net/specs/openid-connect-rpinitiated-1_0.html
    /// 仅在服务端配置了 OIDC 同步登出且该 Session 依然有效时返回
    pub logout: Option<OidcLogoutAction>,
}

pub struct OidcLogoutAction {
    /// 浏览器发起登出的 HTTP 方法
    /// 取值范围: "GET" 或 "POST"
    pub method: LogoutMethod,

    /// 目标 URL：身份提供商 (IdP) 的登出端点
    pub target: String,

    /// 携带参数：
    /// [逻辑]：
    /// - 若为 GET：作为 Query Params 拼接到 URL 后
    /// - 若为 POST：作为 application/x-www-form-urlencoded 放入请求体
    /// 通常包含 id_token_hint, post_logout_redirect_uri 等
    pub fields: HashMap<String, String>,
}

pub enum LogoutMethod {
    Get,  // 对应字符串 "GET"
    Post, // 对应字符串 "POST"
}
```

会清理 Cookie，具体格式如下。

| 属性 | 值 | 说明 |
| :--- | :--- | :--- |
| `__Http-refresh-token` | 空 | 清除 Token 内容 |
| `Domain` | 无 | 禁止子域名访问 |
| `HttpOnly` | 有 | 禁止任何 JavaScript 脚本访问 |
| `Max-Age` | `0` | 告知浏览器立即删除该 Cookie |
| `Path` | `/auth/session/refresh` | 确保凭证仅在续期接口暴露 |
| `SameSite` | `Strict` | 禁止在任何第三方发起的请求中携带此 Cookie |
| `Secure` | 有 | 强制仅在加密的 HTTPS 连接中传输 |

暂时还不知道失败时会产生什么错误

### 2.4 设备管理器 `/auth/sessions`

提供用户对账号登录情况的审计能力，允许识别异常登录并执行远程强制退出。

#### 2.4.1 获取活跃设备列表 `GET /auth/sessions`

返回当前账号下所有未过期且未被注销的设备清单。

需要 `Authorization` 请求头。

成功时返回

```rust
/// 响应根对象为设备模型数组
pub type SessionListResponse = Vec<SessionListItem>;

pub struct SessionListItem {
    /// 设备的全局唯一标识 (256-bit Global ID)
    pub session_id: String,

    /// 会话分类
    /// 取值: "current" (当前设备), "remote" (远程/其他设备)
    pub kind: SessionKind,

    /// 用户设置的设备别名
    pub alias: Option<String>,

    /// 最后一次活跃的精确时间 (UTC)
    /// 类型: time::OffsetDateTime (具有纳秒级精度)
    pub last_active_at: OffsetDateTime,

    /// 最近一次活跃时的客户端 IP 地址
    pub ip: IpAddr,

    /// 浏览器/客户端原始指纹 (User-Agent)
    pub ua: String,

    /// 详细地理位置信息
    pub location: SessionGeoLocation,
}

pub enum SessionKind {
    Current,
    Remote,
}

pub struct SessionGeoLocation {
    /// Cloudflare 数据中心三字代码 (如 "HKG", "SJC")
    pub colo: String,

    /// 国家/地区代码 (ISO 3166-1 alpha-2, 如 "CN")
    pub country: Option<String>,

    /// 城市名称 (如 "Hangzhou")
    pub city: Option<String>,

    /// 大洲代码 (如 "AS", "NA")
    pub continent: Option<String>,

    /// Latitude and longitude of the incoming request, e.g. (30.27130, -97.74260)
    pub coordinates: Option<(f32, f32)>

    /// 邮政编码 (如 "310000", "78701")
    pub postal_code: Option<String>,
    
    /// 都会区代码 (DMA, 如 "635")
    pub metro_code: Option<String>,

    /// 第一级行政区划名称 (如 "Zhejiang", "Texas")
    pub region: Option<String>,

    /// 第一级行政区划代码 (ISO 3166-2, 如 "ZJ", "TX")
    pub region_code: Option<String>,
}
```

暂时还不知道失败时会产生什么错误

#### 2.4.2 获取特定设备详情 `GET /auth/sessions/{session_id}`

本接口返回指定设备的完整审计信息，展示服务端记录的所有环境指纹。

路径中 `id` 为设备的全局唯一标识 (256-bit Global ID)

需要 `Authorization` 请求头。

成功时返回

```rust
pub struct SessionDetailData {
    /// 设备的全局唯一标识 (256-bit Global ID)
    pub session_id: String,

    /// 会话分类
    /// 取值: "current" (当前设备), "remote" (远程/其他设备)
    pub kind: SessionKind,

    /// 用户自定义别名
    pub alias: Option<String>,

    /// 该设备首次在本系统注册的精确时间 (UTC)
    /// 类型: time::OffsetDateTime
    pub created_at: OffsetDateTime,

    /// 最后一次活跃的精确时间 (UTC)
    pub last_active_at: OffsetDateTime,

    /// 运行上下文：反映该设备最后一次活跃时的物理接入环境
    pub context: SessionContext,
}

pub enum SessionKind {
    Current,
    Remote,
}

pub struct SessionContext {
    /// 最近一次活跃时的客户端 IP 地址 (IpAddr)
    pub ip: IpAddr,

    /// 浏览器/客户端原始指纹 (User-Agent)
    pub ua: String,

    /// 完整的 Cloudflare 地理与网络元数据
    /// 包含 User-Agent (userAgent), TLS 指纹 (tlsClientHelloEcho), 
    /// ISP 名称 (asOrganization) 等。
    /// 字段定义参照: https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties
    pub cf: Cf,
}
```

暂时还不知道失败时会产生什么错误

#### 2.4.3 修改特定会话属性 `PATCH /auth/sessions/{session_id}`

本接口允许用户通过会话 ID 远程修改指定会话的元数据（如别名）。

需要 `Authorization` 请求头。

请求体如下

使用与 `PATCH /auth/session` 相同的结构

```rust
pub struct UpdateSessionRequest {
    /// 设备的自定义别名 (如 "我的办公 MacBook")
    /// [逻辑]：
    /// - 忽略该字段：保持原别名不变
    /// - 传字符串内容：更新别名为该值
    /// - 传 null：删除别名（重置为未命名状态）
    pub alias: FieldUpdate<String>,
}

pub enum FieldUpdate<T> {
    /// 不修改：JSON 中缺失该键
    Ignore,
    /// 删除/重置：JSON 中该键的值为 null
    Delete,
    /// 设置/更新：JSON 中该键为具体类型的值
    Set(T),
}
```

成功时返回

```rust
pub struct UpdateSessionData {
    /// 被修改会话的全局唯一标识 (256-bit Global ID)
    pub session_id: String,

    /// 更新后的会话别名
    pub alias: Option<String>,
}
```

#### 2.4.4 强制注销指定会话 `DELETE /auth/sessions/{session_id}`

远程注销指定的会话（即“踢出”特定设备）。由于 Access Token 为无状态 JWT，在服务端注销会话后，该 Token 在其剩余寿命内理论上仍可访问业务接口。

需要 `Authorization` 请求头。

成功时返回

```rust
pub struct DeleteSessionData {
    /// 被注销的会话 ID
    pub session_id: String,

    /// [可选] 引导全局登出的指令
    /// https://openid.net/specs/openid-connect-rpinitiated-1_0.html
    /// 仅在服务端配置了 OIDC 同步登出且该 Session 依然有效时返回
    pub logout: Option<OidcLogoutAction>,
}

pub struct OidcLogoutAction {
    /// 浏览器发起登出的 HTTP 方法
    /// 取值范围: "GET" 或 "POST"
    pub method: LogoutMethod,

    /// 目标 URL：身份提供商 (IdP) 的登出端点
    pub target: String,

    /// 携带参数：
    /// [逻辑]：
    /// - 若为 GET：作为 Query Params 拼接到 URL 后
    /// - 若为 POST：作为 application/x-www-form-urlencoded 放入请求体
    /// 通常包含 id_token_hint, post_logout_redirect_uri 等
    pub fields: HashMap<String, String>,
}

pub enum LogoutMethod {
    Get,  // 对应字符串 "GET"
    Post, // 对应字符串 "POST"
}
```

#### 2.4.5 批量注销会话 `DELETE /auth/sessions`

根据指定的范围批量清理当前账号下的活跃会话。由于 Access Token 为无状态 JWT，剩下的不想说了。

当响应的 `scope` 为 `all` 时，客户端必须立即从内存中抹除 Access Token。

需要 `Authorization` 请求头。

该接口必须携带查询参数，具体如下

| 参数 | 类型 | 说明 |
| :--- | :--- | :--- |
| `scope` | `string` | 取值范围：`others`（注销除当前会话外的所有会话）, `all`（注销该账号下全部活跃会话） |

成功时返回

```rust
pub struct BatchDeleteSessionsData {
    /// 成功注销的会话总数
    pub count: u32,

    /// 执行的操作范围
    pub scope: SessionDeleteScope,

    /// [可选] 引导全局登出的指令
    /// https://openid.net/specs/openid-connect-rpinitiated-1_0.html
    /// 仅在 scope 为 "all" 且当前会话被注销时返回
    pub logout: Option<OidcLogoutAction>,
}

pub enum SessionDeleteScope {
    /// 注销除当前会话外的所有其他活跃会话
    Others,
    /// 注销该账号下全部活跃会话（包含当前发起请求的会话）
    All,
}

pub struct OidcLogoutAction {
    /// 浏览器发起登出的 HTTP 方法
    /// 取值范围: "GET" 或 "POST"
    pub method: LogoutMethod,

    /// 目标 URL：身份提供商 (IdP) 的登出端点
    pub target: String,

    /// 携带参数：
    /// [逻辑]：
    /// - 若为 GET：作为 Query Params 拼接到 URL 后
    /// - 若为 POST：作为 application/x-www-form-urlencoded 放入请求体
    /// 通常包含 id_token_hint, post_logout_redirect_uri 等
    pub fields: HashMap<String, String>,
}

pub enum LogoutMethod {
    Get,  // 对应字符串 "GET"
    Post, // 对应字符串 "POST"
}
```

### 2.5 账户偏好设置 `/auth/preferences`

定义账户全局的安全防御策略，影响所有关联设备的会话生存期与网络接入逻辑。

#### 2.5.1 获取账户安全配置 `GET /auth/preferences`

返回当前账号生效的安全策略。

需要 `Authorization` 请求头。

成功时返回

```rust
pub struct UserPreferences {
    /// 闲置自动登出时限
    pub idle_timeout: IdleTimeout,

    /// 是否允许非 Tor 与 Tor 网络间的会话切换
    pub tor_transition: TorTransition,
}

/// 闲置超时配置
pub enum IdleTimeout {
    /// 设置具体的时间跨度 (精度取决于实现，通常建议为秒)
    /// 类型参考: Rust `time::Duration`
    Duration(Duration),

    /// 永不超时
    Permanent,
}

/// Tor 切换策略
pub enum TorTransition {
    /// 允许在普通网络与 Tor 之间切换
    Allow,
    /// 禁止切换。一旦检测到变化，立即注销会话
    Deny,
}
```

#### 2.5.2 修改账户安全配置 `PATCH /auth/preferences`

更新全局安全策略。

需要 `Authorization` 请求头。

请求体

```rust
pub struct UpdatePreferencesRequest {
    /// 修改闲置自动登出时限 (可选)
    pub idle_timeout: Option<IdleTimeout>,

    /// 修改 Tor 切换策略 (可选)
    pub tor_transition: Option<TorTransition>,
}
```

成功时返回

```rust
pub struct UserPreferences {
    /// 闲置自动登出时限
    pub idle_timeout: IdleTimeout,

    /// 是否允许非 Tor 与 Tor 网络间的会话切换
    pub tor_transition: TorTransition,
}

/// 闲置超时配置
pub enum IdleTimeout {
    /// 设置具体的时间跨度 (精度取决于实现，通常建议为秒)
    /// 类型参考: Rust `time::Duration`
    Duration(Duration),

    /// 永不超时
    Permanent,
}

/// Tor 切换策略
pub enum TorTransition {
    /// 允许在普通网络与 Tor 之间切换
    Allow,
    /// 禁止切换。一旦检测到变化，立即注销会话
    Deny,
}
```
