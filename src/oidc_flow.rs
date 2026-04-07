use jsonwebtoken::{DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use openidconnect::{PkceCodeChallenge, PkceCodeVerifier};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use worker::{Headers, Method, Request, RequestInit, send::IntoSendFuture};

use crate::{
    api::{ApiError, ApiResult},
    config::OidcProviderConfig,
    types::ProtectedJwsPayload,
};

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryDocument {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
    pub end_session_endpoint: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenEndpointResponse {
    pub access_token: String,
    pub id_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OidcJwtClaims {
    iss: String,
    sub: String,
    exp: i64,
    iat: Option<i64>,
    nonce: Option<String>,
    sid: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    phone_number: Option<String>,
    phone_number_verified: Option<bool>,
    events: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct VerifiedIdToken {
    pub sub: String,
    pub sid: Option<String>,
    pub protected: ProtectedJwsPayload,
    pub claims: Value,
}

pub async fn discover(config: &OidcProviderConfig) -> ApiResult<DiscoveryDocument> {
    let issuer = config.issuer.trim_end_matches('/');
    fetch_json(&format!("{issuer}/.well-known/openid-configuration"), None).await
}

pub fn build_authorization_url(
    discovery: &DiscoveryDocument,
    config: &OidcProviderConfig,
    state: &str,
    nonce: &str,
    code_verifier: &str,
) -> ApiResult<String> {
    let verifier = PkceCodeVerifier::new(code_verifier.to_string());
    let challenge = PkceCodeChallenge::from_code_verifier_sha256(&verifier);
    let mut url = url::Url::parse(&discovery.authorization_endpoint)
        .map_err(|e| ApiError::internal(format!("invalid authorization endpoint: {e}")))?;
    {
        let mut params = url.query_pairs_mut();
        params
            .append_pair("response_type", "code")
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", &config.redirect_uri)
            .append_pair("scope", &config.scopes.join(" "))
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", challenge.as_str())
            .append_pair("code_challenge_method", "S256");
    }
    Ok(url.to_string())
}

pub async fn exchange_code(
    discovery: &DiscoveryDocument,
    config: &OidcProviderConfig,
    code: &str,
    code_verifier: &str,
) -> ApiResult<TokenEndpointResponse> {
    let body = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", config.redirect_uri.as_str()),
        ("client_id", config.client_id.as_str()),
        ("client_secret", config.client_secret.as_str()),
        ("code_verifier", code_verifier),
    ])
    .map_err(|e| ApiError::internal(format!("failed to encode token request: {e}")))?;

    let headers = Headers::new();
    headers
        .set("content-type", "application/x-www-form-urlencoded")
        .map_err(ApiError::from)?;
    fetch_json(
        &discovery.token_endpoint,
        Some((Method::Post, headers, body)),
    )
    .await
}

pub async fn verify_id_token(
    discovery: &DiscoveryDocument,
    config: &OidcProviderConfig,
    id_token: &str,
    nonce: &str,
) -> ApiResult<VerifiedIdToken> {
    let jwks: JwkSet = fetch_json(&discovery.jwks_uri, None).await?;
    let header = decode_header(id_token)
        .map_err(|e| ApiError::unauthorized("INVALID_ID_TOKEN", e.to_string()))?;
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| ApiError::unauthorized("INVALID_ID_TOKEN", "id_token missing kid"))?;
    let jwk = jwks
        .find(kid)
        .ok_or_else(|| ApiError::unauthorized("INVALID_ID_TOKEN", "id_token kid not in JWKS"))?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[config.issuer.as_str()]);
    validation.set_audience(&[config.client_id.as_str()]);
    let data = decode::<OidcJwtClaims>(
        id_token,
        &DecodingKey::from_jwk(jwk)
            .map_err(|e| ApiError::unauthorized("INVALID_ID_TOKEN", e.to_string()))?,
        &validation,
    )
    .map_err(|e| ApiError::unauthorized("INVALID_ID_TOKEN", e.to_string()))?;
    if data.claims.nonce.as_deref() != Some(nonce) {
        return Err(ApiError::unauthorized("INVALID_ID_TOKEN", "nonce mismatch"));
    }

    let claims_value = serde_json::to_value(&data.claims)
        .map_err(|e| ApiError::internal(format!("failed to normalize id token claims: {e}")))?;
    let protected = ProtectedJwsPayload {
        sub: data.claims.sub.clone(),
        email: data
            .claims
            .email_verified
            .unwrap_or(false)
            .then_some(data.claims.email)
            .flatten(),
        phone_number: data
            .claims
            .phone_number_verified
            .unwrap_or(false)
            .then_some(data.claims.phone_number)
            .flatten(),
    };

    Ok(VerifiedIdToken {
        sub: data.claims.sub,
        sid: data.claims.sid,
        protected,
        claims: claims_value,
    })
}

pub async fn fetch_userinfo(discovery: &DiscoveryDocument, access_token: &str) -> ApiResult<Value> {
    let endpoint = discovery
        .userinfo_endpoint
        .as_ref()
        .ok_or_else(|| ApiError::internal("OIDC provider has no userinfo_endpoint"))?;
    let headers = Headers::new();
    headers
        .set("authorization", &format!("Bearer {access_token}"))
        .map_err(ApiError::from)?;
    fetch_json(endpoint, Some((Method::Get, headers, String::new()))).await
}

pub fn merge_claims(mut id_claims: Value, userinfo: Value) -> Value {
    if let (Some(id_obj), Some(userinfo_obj)) = (id_claims.as_object_mut(), userinfo.as_object()) {
        for (key, value) in userinfo_obj {
            id_obj.insert(key.clone(), value.clone());
        }
        id_claims
    } else {
        userinfo
    }
}

pub async fn verify_logout_token(
    discovery: &DiscoveryDocument,
    config: &OidcProviderConfig,
    logout_token: &str,
) -> ApiResult<(Option<String>, Option<String>)> {
    let jwks: JwkSet = fetch_json(&discovery.jwks_uri, None).await?;
    let header = decode_header(logout_token)
        .map_err(|e| ApiError::unauthorized("INVALID_LOGOUT_TOKEN", e.to_string()))?;
    let kid = header.kid.as_deref().ok_or_else(|| {
        ApiError::unauthorized("INVALID_LOGOUT_TOKEN", "logout_token missing kid")
    })?;
    let jwk = jwks.find(kid).ok_or_else(|| {
        ApiError::unauthorized("INVALID_LOGOUT_TOKEN", "logout_token kid not in JWKS")
    })?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[config.issuer.as_str()]);
    validation.set_audience(&[config.client_id.as_str()]);
    validation.validate_exp = false;
    let data = decode::<Value>(
        logout_token,
        &DecodingKey::from_jwk(jwk)
            .map_err(|e| ApiError::unauthorized("INVALID_LOGOUT_TOKEN", e.to_string()))?,
        &validation,
    )
    .map_err(|e| ApiError::unauthorized("INVALID_LOGOUT_TOKEN", e.to_string()))?;

    if data.claims.get("nonce").is_some() {
        return Err(ApiError::unauthorized(
            "INVALID_LOGOUT_TOKEN",
            "logout_token must not contain nonce",
        ));
    }
    let has_event = data
        .claims
        .get("events")
        .and_then(Value::as_object)
        .map(|events| events.contains_key("http://schemas.openid.net/event/backchannel-logout"))
        .unwrap_or(false);
    if !has_event {
        return Err(ApiError::unauthorized(
            "INVALID_LOGOUT_TOKEN",
            "logout_token missing backchannel logout event",
        ));
    }
    let iat = data
        .claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| {
            ApiError::unauthorized("INVALID_LOGOUT_TOKEN", "logout_token missing iat")
        })?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if iat > now + 60 || now - iat > 300 {
        return Err(ApiError::unauthorized(
            "INVALID_LOGOUT_TOKEN",
            "logout_token iat is outside the accepted clock skew",
        ));
    }
    let sub = data
        .claims
        .get("sub")
        .and_then(Value::as_str)
        .map(str::to_string);
    let sid = data
        .claims
        .get("sid")
        .and_then(Value::as_str)
        .map(str::to_string);
    if sub.is_none() && sid.is_none() {
        return Err(ApiError::unauthorized(
            "INVALID_LOGOUT_TOKEN",
            "logout_token must contain sub or sid",
        ));
    }
    Ok((sub, sid))
}

async fn fetch_json<T: for<'de> Deserialize<'de>>(
    url: &str,
    request: Option<(Method, Headers, String)>,
) -> ApiResult<T> {
    let mut response = if let Some((method, headers, body)) = request {
        let mut init = RequestInit::new();
        init.with_method(method).with_headers(headers);
        if !body.is_empty() {
            init.with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body)));
        }
        let req = Request::new_with_init(url, &init).map_err(ApiError::from)?;
        worker::Fetch::Request(req)
            .send()
            .into_send()
            .await
            .map_err(ApiError::from)?
    } else {
        let url = url::Url::parse(url)
            .map_err(|e| ApiError::internal(format!("invalid fetch url: {e}")))?;
        worker::Fetch::Url(url)
            .send()
            .into_send()
            .await
            .map_err(ApiError::from)?
    };
    if !(200..=299).contains(&response.status_code()) {
        return Err(ApiError::new(
            axum::http::StatusCode::BAD_GATEWAY,
            "OIDC_HTTP_ERROR",
            format!("OIDC endpoint returned HTTP {}", response.status_code()),
        ));
    }
    response.json().into_send().await.map_err(ApiError::from)
}
