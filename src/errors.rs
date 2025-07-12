use actix_web::{HttpResponse, ResponseError};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not Found: {0}")]
    NotFound(String),

    #[error("Bad Request: {0}")]
    BadRequest(String),

    #[error("JWT Error: {0}")]
    JwtError(String),

    #[error("SQL Error: {0}")]
    SqlxError(#[from] sqlx::Error),

    #[error("Password hashing error: {0}")]
    ArgonError(String),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::Unauthorized(_) => HttpResponse::Unauthorized().json(json!({
                "error": "Unauthorized",
                "message": self.to_string()
            })),
            AppError::Forbidden(_) => HttpResponse::Forbidden().json(json!({
                "error": "Forbidden",
                "message": self.to_string()
            })),
            AppError::NotFound(_) => HttpResponse::NotFound().json(json!({
                "error": "Not Found",
                "message": self.to_string()
            })),
            AppError::BadRequest(_) => HttpResponse::BadRequest().json(json!({
                "error": "Bad Request",
                "message": self.to_string()
            })),
            _ => HttpResponse::InternalServerError().json(json!({
                "error": "Internal Server Error",
                "message": self.to_string()
            })),
        }
    }
}


