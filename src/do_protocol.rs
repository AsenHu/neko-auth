use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::types::{
    DeleteSessionData, FieldUpdate, GetSessionData, ProtectedJwsPayload, RequestContext,
    SessionDeleteScope, SessionDetailData, SessionListItem, UpdateSessionData, UserPreferences,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcStateRecord {
    pub host: String,
    pub state: String,
    pub code_verifier: String,
    pub nonce: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum OidcStateRequest {
    Store(OidcStateRecord),
    Consume { state: String, now: i64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginDeviceRequest {
    pub host: String,
    pub sub: String,
    pub identity: Value,
    pub protected: ProtectedJwsPayload,
    pub protected_jws: String,
    pub id_token_hint: String,
    pub oidc_sid: Option<String>,
    pub default_preferences: UserPreferences,
    pub session_id: String,
    pub refresh_token_hash: String,
    pub refresh_token_seq: i64,
    pub context: RequestContext,
    pub user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshDeviceRequest {
    pub session_id: String,
    pub refresh_token_hash: String,
    pub next_refresh_token_hash: String,
    pub next_refresh_token_seq: i64,
    pub context: RequestContext,
    pub user_agent: String,
    pub now: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedSessionRequest {
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionIdentityRequest {
    pub session_id: String,
    pub include_identity: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAliasRequest {
    pub current_session_id: String,
    pub target_session_id: String,
    pub alias: FieldUpdate<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteDeviceRequest {
    pub current_session_id: String,
    pub target_session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchDeleteDeviceRequest {
    pub current_session_id: String,
    pub scope: SessionDeleteScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePreferencesDoRequest {
    pub session_id: String,
    pub idle_timeout: Option<crate::types::IdleTimeout>,
    pub tor_transition: Option<crate::types::TorTransition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackchannelLogoutRequest {
    pub sub: String,
    pub sid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum UserSessionRequest {
    Login(LoginDeviceRequest),
    Refresh(RefreshDeviceRequest),
    GetSession(SessionIdentityRequest),
    ListSessions(AuthenticatedSessionRequest),
    GetSessionDetail(DeleteDeviceRequest),
    UpdateSession(UpdateAliasRequest),
    DeleteSession(DeleteDeviceRequest),
    BatchDelete(BatchDeleteDeviceRequest),
    GetPreferences(AuthenticatedSessionRequest),
    UpdatePreferences(UpdatePreferencesDoRequest),
    BackchannelLogout(BackchannelLogoutRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshDeviceData {
    pub session_id: String,
    pub sub: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case")]
pub enum RefreshDeviceResponse {
    Ok(RefreshDeviceData),
    Invalid,
    Reused,
    IdleTimeout,
    TorTransitionDenied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchDeleteDeviceData {
    pub count: u32,
    pub current_id_token_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case")]
pub enum DeleteDeviceResponse {
    Ok {
        data: DeleteSessionData,
        id_token_hint: Option<String>,
    },
    NotFound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case")]
pub enum UserSessionResponse {
    Login { session_id: String },
    Refresh(RefreshDeviceResponse),
    GetSession(GetSessionData),
    ListSessions(Vec<SessionListItem>),
    GetSessionDetail(SessionDetailData),
    UpdateSession(UpdateSessionData),
    DeleteSession(DeleteDeviceResponse),
    BatchDelete(BatchDeleteDeviceData),
    Preferences(UserPreferences),
    BackchannelLogout { count: u32 },
}
