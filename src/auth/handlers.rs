use crate::auth::jwt::create_jwt;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use crate::errors::AppError;

#[derive(Deserialize)]
pub struct AuthPayload {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    token: String,
}

pub fn auth_routes() -> Router {
    Router::new().route("/login", post(login_handler))
}

async fn login_handler(Json(payload): Json<AuthPayload>) -> Result<Json<TokenResponse>, AppError> {
    if payload.username == "admin" && payload.password == "password" {
        let token = create_jwt(payload.username)?;
        Ok(Json(TokenResponse { token }))
    } else {
        Err(AppError::unauthorized(
            "Invalid username or password".to_string(),
        ))
    }
}
