use std::{collections::HashMap, sync::Arc};

use axum::http::{HeaderMap, StatusCode, header};
use serde::{Serialize, de::DeserializeOwned};
use time::OffsetDateTime;
use worker::{Headers, Method, Request, RequestInit, send::IntoSendFuture};

use crate::{
    api::{self, ApiError, ApiResult},
    app::AppState,
    do_protocol::UserSessionRequest,
    oidc_flow::DiscoveryDocument,
    security::{self, LocalAccessClaims},
    types::{LogoutMethod, OidcLogoutAction},
};

const OIDC_STATE_BINDING: &str = "OIDC_STATE_OBJECT";
const USER_SESSION_BINDING: &str = "USER_SESSION_OBJECT";

pub fn bearer_claims(state: &AppState, headers: &HeaderMap) -> ApiResult<LocalAccessClaims> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| raw.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("MISSING_ACCESS_TOKEN", "missing bearer token"))?;

    security::verify_access_token(&state.config.jwt, &state.host, token)
        .map_err(|e| ApiError::unauthorized("INVALID_ACCESS_TOKEN", e.to_string()))
}

pub fn refresh_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| {
            raw.split(';').find_map(|part| {
                let (key, value) = part.trim().split_once('=')?;
                (key == name).then(|| value.to_string())
            })
        })
}

pub fn set_refresh_cookie(state: &AppState, token: &str) -> String {
    format!(
        "{}={}; Max-Age={}; Path={}; HttpOnly; Secure; SameSite={}",
        state.config.cookie.refresh_token_name,
        token,
        state.config.jwt.rt_ttl_seconds,
        state.config.cookie.refresh_token_path,
        state.config.cookie.same_site
    )
}

pub fn clear_refresh_cookie(state: &AppState) -> String {
    format!(
        "{}=; Max-Age=0; Path={}; HttpOnly; Secure; SameSite={}",
        state.config.cookie.refresh_token_name,
        state.config.cookie.refresh_token_path,
        state.config.cookie.same_site
    )
}

pub async fn call_oidc_state<T, R>(state: &AppState, object_name: &str, body: &T) -> ApiResult<R>
where
    T: Serialize,
    R: DeserializeOwned,
{
    call_do(&state.env, OIDC_STATE_BINDING, object_name, body).await
}

pub async fn call_user_session(
    state: &AppState,
    sub: &str,
    body: &UserSessionRequest,
) -> ApiResult<crate::do_protocol::UserSessionResponse> {
    let object_name = security::user_do_name(&state.host, sub);
    call_do(&state.env, USER_SESSION_BINDING, &object_name, body).await
}

async fn call_do<T, R>(
    env: &worker::Env,
    binding: &str,
    object_name: &str,
    body: &T,
) -> ApiResult<R>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let namespace = env.durable_object(binding).map_err(ApiError::from)?;
    let stub = namespace.get_by_name(object_name).map_err(ApiError::from)?;
    let request = json_request("https://durable-object.internal/rpc", body)?;
    let mut response = stub
        .fetch_with_request(request)
        .into_send()
        .await
        .map_err(ApiError::from)?;
    if !(200..=299).contains(&response.status_code()) {
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "DURABLE_OBJECT_ERROR",
            format!(
                "durable object {binding}/{object_name} returned HTTP {}",
                response.status_code()
            ),
        ));
    }
    response.json().into_send().await.map_err(ApiError::from)
}

pub fn json_request<T: Serialize>(url: &str, body: &T) -> ApiResult<Request> {
    let body = serde_json::to_string(body).map_err(|e| {
        ApiError::internal(format!("failed to serialize durable object request: {e}"))
    })?;
    let headers = Headers::new();
    headers
        .set("content-type", "application/json")
        .map_err(ApiError::from)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body)));
    Request::new_with_init(url, &init).map_err(ApiError::from)
}

pub fn logout_action(
    discovery: &DiscoveryDocument,
    state: &AppState,
    id_token_hint: Option<String>,
) -> Option<OidcLogoutAction> {
    let target = discovery.end_session_endpoint.clone()?;
    let mut fields = HashMap::new();
    if let Some(id_token_hint) = id_token_hint {
        fields.insert("id_token_hint".to_string(), id_token_hint);
    }
    if let Some(uri) = state.config.post_logout_redirect_uri.clone() {
        fields.insert("post_logout_redirect_uri".to_string(), uri);
    }
    Some(OidcLogoutAction {
        method: LogoutMethod::Get,
        target,
        fields,
    })
}

pub fn unauthorized_with_clear_cookie(
    state: &Arc<AppState>,
    code: &'static str,
    message: impl Into<String>,
) -> ApiResult<axum::response::Response> {
    Ok(api::error_with_cookie(
        StatusCode::UNAUTHORIZED,
        code,
        message,
        &state.trace_id,
        Some(clear_refresh_cookie(state)),
    )?)
}

pub fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}
