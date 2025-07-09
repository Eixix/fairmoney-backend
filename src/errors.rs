use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error(transparent)]
    JwtError(#[from] jsonwebtoken::errors::Error),

    #[error(transparent)]
    SqlxError(#[from] sqlx::Error),

    #[error("Password hashing error")]
    ArgonError(String),
}

impl AppError {
    pub fn unauthorized(message: String) -> Self {
        Self::Unauthorized(message)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match self {
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, self.to_string()).into_response()
    }
}
