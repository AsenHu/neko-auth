use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use worker::{Error, Result, wasm_bindgen::JsCast};

use crate::config::JwtConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAccessClaims {
    pub typ: String,
    pub host: String,
    pub sub: String,
    pub sid: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalRefreshClaims {
    pub typ: String,
    pub host: String,
    pub sub: String,
    pub sid: String,
    pub seq: i64,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
}

pub fn random_token(num_bytes: usize) -> Result<String> {
    let mut bytes = vec![0u8; num_bytes];
    let scope: worker::web_sys::WorkerGlobalScope = worker::js_sys::global().unchecked_into();
    scope
        .crypto()
        .map_err(Error::from)?
        .get_random_values_with_u8_array(&mut bytes)
        .map_err(Error::from)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub fn sha256_hex(input: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(input.as_ref());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub fn user_do_name(host: &str, sub: &str) -> String {
    sha256_hex(format!("{host}\0{sub}"))
}

pub fn oidc_state_do_name(host: &str, state: &str) -> String {
    sha256_hex(format!("{host}\0{state}"))
}

pub fn hash_refresh_token(token: &str) -> String {
    sha256_hex(token)
}

pub fn issue_access_token(
    jwt: &JwtConfig,
    host: &str,
    sub: &str,
    session_id: &str,
) -> jsonwebtoken::errors::Result<(String, OffsetDateTime)> {
    let now = OffsetDateTime::now_utc();
    let exp = now + time::Duration::seconds(jwt.at_ttl_seconds as i64);
    let claims = LocalAccessClaims {
        typ: "at".to_string(),
        host: host.to_string(),
        sub: sub.to_string(),
        sid: session_id.to_string(),
        iat: now.unix_timestamp(),
        exp: exp.unix_timestamp(),
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(derived_key(&jwt.at_secret_seed, host, "at").as_bytes()),
    )?;
    Ok((token, exp))
}

pub fn issue_refresh_token(
    jwt: &JwtConfig,
    host: &str,
    sub: &str,
    session_id: &str,
    seq: i64,
) -> jsonwebtoken::errors::Result<(String, OffsetDateTime)> {
    let now = OffsetDateTime::now_utc();
    let exp = now + time::Duration::seconds(jwt.rt_ttl_seconds as i64);
    let claims = LocalRefreshClaims {
        typ: "rt".to_string(),
        host: host.to_string(),
        sub: sub.to_string(),
        sid: session_id.to_string(),
        seq,
        jti: random_token(32).map_err(|_e| {
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken)
        })?,
        iat: now.unix_timestamp(),
        exp: exp.unix_timestamp(),
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(derived_key(&jwt.rt_secret_seed, host, "rt").as_bytes()),
    )?;
    Ok((token, exp))
}

pub fn verify_access_token(
    jwt: &JwtConfig,
    host: &str,
    token: &str,
) -> jsonwebtoken::errors::Result<LocalAccessClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_aud = false;
    let data = decode::<LocalAccessClaims>(
        token,
        &DecodingKey::from_secret(derived_key(&jwt.at_secret_seed, host, "at").as_bytes()),
        &validation,
    )?;
    if data.claims.typ != "at" || data.claims.host != host {
        return Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        ));
    }
    Ok(data.claims)
}

pub fn verify_refresh_token(
    jwt: &JwtConfig,
    host: &str,
    token: &str,
) -> jsonwebtoken::errors::Result<LocalRefreshClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_aud = false;
    let data = decode::<LocalRefreshClaims>(
        token,
        &DecodingKey::from_secret(derived_key(&jwt.rt_secret_seed, host, "rt").as_bytes()),
        &validation,
    )?;
    if data.claims.typ != "rt" || data.claims.host != host {
        return Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        ));
    }
    Ok(data.claims)
}

pub fn sign_protected<T: Serialize>(
    jwt: &JwtConfig,
    host: &str,
    claims: &T,
) -> jsonwebtoken::errors::Result<String> {
    encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(derived_key(&jwt.at_secret_seed, host, "protected").as_bytes()),
    )
}

fn derived_key(seed: &str, host: &str, purpose: &str) -> String {
    sha256_hex(format!("{purpose}\0{host}\0{seed}"))
}
