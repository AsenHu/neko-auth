use crate::{config::DomainConfig, types::RequestContext};
use worker::Env;

/// 每个入站请求独立注入的运行状态。
#[derive(Debug, Clone)]
pub struct AppState {
    pub host: String,
    pub config: DomainConfig,
    pub env: Env,
    pub context: RequestContext,
    pub trace_id: String,
}
