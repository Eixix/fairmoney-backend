use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
}

impl AppError {
    pub fn unauthorized(message: String) -> Self {
        Self::Unauthorized(message)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Unauthorized(msg) => {
                (StatusCode::UNAUTHORIZED, msg).into_response()
            }
            AppError::JwtError(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}