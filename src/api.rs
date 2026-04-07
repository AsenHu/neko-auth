use axum::{
    Json,
    body::Body,
    http::{HeaderValue, Response, StatusCode, header},
    response::IntoResponse,
};
use serde::Serialize;
use time::OffsetDateTime;

use crate::types::{FailureResponse, SuccessResponse};

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    pub fn unauthorized(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, code, message)
    }

    pub fn not_found(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, code, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let body = FailureResponse::simple(
            self.code,
            self.message,
            OffsetDateTime::now_utc(),
            String::new(),
        );
        (self.status, Json(body)).into_response()
    }
}

pub fn json_ok<T: Serialize>(data: T, trace_id: &str) -> axum::response::Response {
    Json(SuccessResponse::new(
        Some(data),
        OffsetDateTime::now_utc(),
        trace_id.to_string(),
    ))
    .into_response()
}

pub fn empty_ok(trace_id: &str) -> axum::response::Response {
    Json(SuccessResponse::<()>::new(
        None,
        OffsetDateTime::now_utc(),
        trace_id.to_string(),
    ))
    .into_response()
}

pub fn redirect(location: &str, set_cookie: Option<String>) -> ApiResult<Response<Body>> {
    let mut builder = Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location);
    if let Some(cookie) = set_cookie {
        builder = builder.header(header::SET_COOKIE, cookie);
    }
    builder
        .body(Body::empty())
        .map_err(|e| ApiError::internal(format!("failed to build redirect response: {e}")))
}

pub fn json_with_cookie<T: Serialize>(
    data: T,
    trace_id: &str,
    set_cookie: Option<String>,
) -> ApiResult<Response<Body>> {
    let body = serde_json::to_string(&SuccessResponse::new(
        Some(data),
        OffsetDateTime::now_utc(),
        trace_id.to_string(),
    ))
    .map_err(|e| ApiError::internal(format!("failed to serialize response: {e}")))?;

    let mut builder = Response::builder().status(StatusCode::OK).header(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Some(cookie) = set_cookie {
        builder = builder.header(header::SET_COOKIE, cookie);
    }
    builder
        .body(Body::from(body))
        .map_err(|e| ApiError::internal(format!("failed to build response: {e}")))
}

pub fn error_with_cookie(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
    trace_id: &str,
    set_cookie: Option<String>,
) -> ApiResult<Response<Body>> {
    let body = serde_json::to_string(&FailureResponse::simple(
        code,
        message,
        OffsetDateTime::now_utc(),
        trace_id.to_string(),
    ))
    .map_err(|e| ApiError::internal(format!("failed to serialize response: {e}")))?;

    let mut builder = Response::builder().status(status).header(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Some(cookie) = set_cookie {
        builder = builder.header(header::SET_COOKIE, cookie);
    }
    builder
        .body(Body::from(body))
        .map_err(|e| ApiError::internal(format!("failed to build response: {e}")))
}

impl From<worker::Error> for ApiError {
    fn from(error: worker::Error) -> Self {
        ApiError::internal(error.to_string())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(error: serde_json::Error) -> Self {
        ApiError::internal(error.to_string())
    }
}
