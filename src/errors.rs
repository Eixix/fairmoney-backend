use actix_web::{error::ResponseError, HttpResponse};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Database error")]
    DbError(#[from] diesel::result::Error),

    #[error("Password verification failed")]
    PasswordVerifyError(#[from] argon2::password_hash::Error),

    #[error("User not found")]
    UserNotFound,

    #[error("Wrong password")]
    WrongPassword,

    #[error("Internal error")]
    InternalError,

    #[error("No authentication token")]
    NoAuthToken,

    #[error("Unauthorized")]
    Unauthorized,
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::UserNotFound => HttpResponse::BadRequest().body("User not found"),
            AppError::PasswordVerifyError(_) => {
                HttpResponse::BadRequest().body("Password verification failed")
            }
            AppError::NoAuthToken => HttpResponse::BadRequest().body("No authentication token"),
            AppError::Unauthorized => HttpResponse::Unauthorized().body("Unauthorized"),
            AppError::WrongPassword => HttpResponse::BadRequest().body("Password is wrong"),
            _ => HttpResponse::InternalServerError().finish(),
        }
    }
}
