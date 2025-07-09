use crate::auth::jwt::create_jwt;
use crate::db::models::User;
use crate::errors::AppError;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use axum::routing::post;
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

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
    Router::new()
        .route("/login", post(login_handler))
        .route("/register", post(register_handler))
}

async fn login_handler(
    Extension(pool): Extension<SqlitePool>,
    Json(payload): Json<AuthPayload>,
) -> Result<Json<TokenResponse>, AppError> {
    let record = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
        .bind(&payload.username)
        .fetch_optional(&pool)
        .await?;

    if let Some(user) = record {
        if verify_password(&payload.password, &user.password_hash)? {
            let token = create_jwt(user.id)?;
            Ok(Json(TokenResponse { token }))
        } else {
            Err(AppError::Unauthorized(
                "Invalid username or password".to_string(),
            ))
        }
    } else {
        Err(AppError::Unauthorized("User not found".to_string()))
    }
}

async fn register_handler(
    Extension(pool): Extension<SqlitePool>,
    Json(payload): Json<AuthPayload>,
) -> Result<Json<TokenResponse>, AppError> {
    let hash = hash_password(&payload.password)?;
    let user = User::new(&payload.username, &hash);

    sqlx::query(
        "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
    )
        .bind(&user.id)
        .bind(&payload.username)
        .bind(&user.password_hash)
    .execute(&pool)
    .await?;

    let token = create_jwt(user.id)?;
    Ok(Json(TokenResponse { token }))
}

fn hash_password(password: &str) -> Result<String, AppError> {
    let mut salt =SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::ArgonError(e.to_string()))?;
    Ok(password_hash.to_string())
}

fn verify_password(password: &str, hash: &str) -> Result<bool, AppError> {
    let parsed_hash = PasswordHash::new(&hash).map_err(|e| AppError::ArgonError(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}
