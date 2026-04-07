//! 账户安全偏好处理器（`/auth/preferences`）
//!
//! 定义账户全局的安全防御策略，影响所有关联设备的会话生存期与接入逻辑。
//! 所有接口均需要 `Authorization: Bearer <access_token>` 请求头。

use axum::{
    extract::Json,
    http::StatusCode,
    response::IntoResponse,
};

use crate::types::UpdatePreferencesRequest;

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
pub async fn get_preferences() -> impl IntoResponse {
    // TODO: 实现上述业务逻辑
    StatusCode::NOT_IMPLEMENTED
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
    Json(body): Json<UpdatePreferencesRequest>,
) -> impl IntoResponse {
    // TODO: 实现上述业务逻辑
    let _ = body;
    StatusCode::NOT_IMPLEMENTED
}
