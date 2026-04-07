//! HTTP 请求处理器
//!
//! 按接口路径前缀分模块组织：
//!
//! | 模块            | 路由前缀              | 说明                         |
//! | --------------- | --------------------- | ---------------------------- |
//! | [`oidc`]        | `/auth/oidc/*`        | OIDC 认证流程（授权/回调/登出）|
//! | [`session`]     | `/auth/session`       | 当前设备的会话管理            |
//! | [`sessions`]    | `/auth/sessions/*`    | 多设备审计与强制退出          |
//! | [`preferences`] | `/auth/preferences`   | 账户全局安全偏好配置          |

pub mod oidc;
pub mod preferences;
pub mod session;
pub mod sessions;
mod support;
